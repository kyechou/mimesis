#include "sender.hpp"

#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <netinet/in.h>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#include <EthLayer.h>
#include <MacAddress.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <PcapLiveDevice.h>
#include <RawPacket.h>

#include "inotify-cpp/Event.h"
#include "inotify-cpp/Notification.h"
#include "inotify-cpp/NotifierBuilder.h"
#include "lib/logger.hpp"
#include "lib/net.hpp"

using namespace std;
namespace fs = std::filesystem;

// Variables for synchronization between threads.
class SyncVars {
public:
    string dst_if_name;    // the interface to which packets are sent
    mutex mtx;             // lock for dst_if_name
    condition_variable cv; // for reading dst_if_name
} vars;

// Create a demo packet.
pcpp::Packet create_demo_packet(pcpp::PcapLiveDevice *egress_intf) {
    auto eth_layer = new pcpp::EthLayer(
        /*sourceMac=*/egress_intf->getMacAddress(),
        /*destMac=*/pcpp::MacAddress("aa:bb:cc:dd:ee:ff"),
        /*etherType=*/0xdead);
    pcpp::Packet packet;
    if (!packet.addLayer(eth_layer, /*ownInPacket=*/true)) {
        error("Failed to add the Ethernet layer");
    }
    packet.computeCalculateFields();
    DemoHeader demo = {.seed = htons(1), .len = htons(42)};
    packet.getRawPacket()->reallocateData(
        packet.getRawPacket()->getRawDataLen() + sizeof(demo));
    packet.getRawPacket()->appendData((const unsigned char *)&demo,
                                      sizeof(demo));
    return packet;
}

// Packet sender.
void packet_sender(const chrono::milliseconds period) {
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
        auto packet = create_demo_packet(dev);

        // Log the packet.
        pcap.writePacket(*packet.getRawPacketReadOnly());
        pcap.flush();

        // Send the packet to the specified interface.
        info("Sending a packet to " + dev->getName() + "\n" +
             packet.toString());
        if (!dev->sendPacket(*packet.getRawPacketReadOnly(),
                             /*checkMtu=*/false)) {
            error("Failed to send packet");
        }
    }
}

// File notification handler.
void notification_handler(inotify::Notification notification) {
    string if_name;
    ifstream send_packet_file(notification.path);
    send_packet_file >> if_name;
    send_packet_file.close();
    info("Notification handler read '" + if_name + "' interface name");

    lock_guard<mutex> lck(vars.mtx);
    vars.dst_if_name = if_name;
    vars.cv.notify_all();
};

int main() {
    thread sending_thread(packet_sender, chrono::milliseconds(1000));

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
