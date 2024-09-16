#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <netinet/in.h>
#include <string>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#include <boost/program_options.hpp>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/MacAddress.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/PcapLiveDevice.h>
#include <pcapplusplus/RawPacket.h>
#include <pcapplusplus/SystemUtils.h>

#include "inotify-cpp/Event.h"
#include "inotify-cpp/Notification.h"
#include "inotify-cpp/NotifierBuilder.h"
#include "lib/logger.hpp"
#include "lib/net.hpp"

using namespace std;
namespace fs = std::filesystem;
namespace po = boost::program_options;

struct DemoHeader {
    uint8_t port; // egress port
    uint8_t type; // packet type. 0: init, 1: follow-up
};

// Variables for synchronization between threads.
class SyncVars {
public:
    string dst_if_name;     // the interface to which packets are sent
    bool first_time = true; // whether this is the first packet ever sent
    mutex mtx;              // lock for dst_if_name
    condition_variable cv;  // for reading dst_if_name
} vars;

// Create a demo packet.
pcpp::Packet create_demo_packet(pcpp::PcapLiveDevice *egress_intf,
                                const std::string &protocol) {
    pcpp::Packet packet;

    // Add L2 header.
    uint16_t ethertype = 0;
    if (protocol == "ip") {
        ethertype = 0x0800;
    } else if (protocol == "demo") {
        ethertype = 0xdead;
    }
    pcpp::EthLayer *eth_layer = new pcpp::EthLayer(
        /*sourceMac=*/egress_intf->getMacAddress(),
        /*destMac=*/pcpp::MacAddress("aa:bb:cc:dd:ee:ff"), ethertype);
    if (!packet.addLayer(eth_layer, /*ownInPacket=*/true)) {
        error("Failed to add the Ethernet layer");
    }

    // Add L3 header.
    if (protocol == "ethernet") {
        // Do nothing.
    } else if (protocol == "ip") {
        pcpp::IPv4Layer *ipv4_layer = new pcpp::IPv4Layer(
            /*srcIP=*/pcpp::IPv4Address(),
            /*dstIP=*/pcpp::IPv4Address());
        if (!packet.addLayer(ipv4_layer, /*ownInPacket=*/true)) {
            error("Failed to add the IPv4 layer");
        }
    } else if (protocol == "demo") {
        DemoHeader demo = {.port = 0, .type = 0};
        packet.getRawPacket()->reallocateData(
            packet.getRawPacket()->getRawDataLen() + sizeof(demo));
        packet.getRawPacket()->appendData((const unsigned char *)&demo,
                                          sizeof(demo));
    } else {
        error("Invalid protocol: '" + protocol + "'");
    }

    packet.computeCalculateFields();
    return packet;
}

// Packet sender.
void packet_sender(const chrono::milliseconds period,
                   const std::string &protocol) {
    unique_lock<mutex> lck(vars.mtx);

    // Open interfaces.
    auto intfs = open_interfaces_as_map(/*tap_only=*/true);
    if (intfs.empty()) {
        error("No interfaces available");
    }
    info("Found " + to_string(intfs.size()) + " interfaces");

    // Create pcap file for recording packets.
    pcpp::PcapFileWriterDevice pcap("sender.pcap");
    if (!pcap.open()) {
        error("Failed to open " + pcap.getFileName());
    }

    // There was a race condition causing the sender to send two packets
    // consecutively without delay in the beginning. The following cv.wait seems
    // to resolve the issue.
    // vars.cv.wait(lck);

    while (1) {
        vars.cv.wait_for(lck, period);
        if (vars.dst_if_name.empty()) {
            continue;
        }

        // Find the interface.
        auto dev_it = intfs.find(vars.dst_if_name);
        if (dev_it == intfs.end()) {
            warn("Interface not found: " + vars.dst_if_name);
            continue;
        }
        auto dev = dev_it->second;

        // Craft the packet to send.
        auto packet = create_demo_packet(dev, protocol);

        if (vars.first_time) {
            // Wait after the program is loaded (when the Mimesis plugin
            // notifying the sender through the shared file), and before
            // actually sending the first packet, for the target program to have
            // enough time to be ready to "boot up" and to be in the right state
            // for processing packets.
            info("Wait for 5 seconds before the first send");
            this_thread::sleep_for(chrono::seconds(5));
            vars.first_time = false;
        }

        // Log the packet.
        pcap.writePacket(*packet.getRawPacketReadOnly());
        pcap.flush();

        // Send the packet to the specified interface.
        info("Sending a packet to " + dev->getName());
        if (!dev->sendPacket(*packet.getRawPacketReadOnly(),
                             /*checkMtu=*/false)) {
            error("Failed to send packet");
        }
    }
}

// File notification handler.
void notification_handler(inotify::Notification notification) {
    lock_guard<mutex> lck(vars.mtx);
    string if_name;
    ifstream send_packet_file(notification.path);
    send_packet_file >> if_name;
    send_packet_file.close();
    info("Notification handler read '" + if_name + "' interface name");
    vars.dst_if_name = if_name;

    static chrono::time_point<chrono::high_resolution_clock> last_update;
    constexpr chrono::milliseconds delay(500);
    auto now = chrono::high_resolution_clock::now();
    if (last_update.time_since_epoch().count() == 0 ||
        now - last_update > delay) {
        // First trigger or time has elapesd more than 500 ms.
        last_update = now;
        vars.cv.notify_all();
    } else {
        info("Sending packets too quickly. Ignoring this one.");
    }
};

void parse_args(int argc, char **argv, std::string &protocol) {
    po::options_description desc("Packet sender options");
    desc.add_options()("help,h", "Show help message");
    desc.add_options()("protocol,p", po::value<string>()->default_value("ip"),
                       "Packet protocol: ['ethernet', 'ip', 'demo']");
    po::variables_map vm;

    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
    } catch (const exception &e) {
        error(e.what());
    }

    if (vm.count("help")) {
        cout << desc << endl;
        exit(0);
    }

    protocol = vm.at("protocol").as<string>();
}

int main(int argc, char **argv) {
    // Parse arguments.
    std::string protocol;
    parse_args(argc, argv, protocol);

    thread sending_thread(packet_sender, chrono::milliseconds(1000), protocol);

    // Create the send_packet file.
    const fs::path send_packet_fn("/dev/shm/send_packet");
    ofstream send_packet(send_packet_fn);
    if (!send_packet) {
        error("Failed to open " + send_packet_fn.string());
    }
    send_packet.close();

    // Monitor the send_packet file on modification.
    auto events = {
        inotify::Event::modify, // File was modified.
    };
    auto notifier = inotify::BuildNotifier()
                        .watchFile(send_packet_fn)
                        .onEvents(events, notification_handler);
    info("Monitoring " + send_packet_fn.string());
    thread monitor_thread([&notifier]() { notifier.run(); });

    // Join all threads.
    if (sending_thread.joinable()) {
        sending_thread.join();
    }
    if (monitor_thread.joinable()) {
        monitor_thread.join();
    }

    info("Exiting");
    return 0;
}
