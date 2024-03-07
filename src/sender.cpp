#include "sender.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <unistd.h>
#include <vector>

#include "inotify-cpp/Event.h"
#include "inotify-cpp/Notification.h"
#include "inotify-cpp/NotifierBuilder.h"
#include "lib/logger.hpp"
#include "lib/net.hpp"

using namespace std;
namespace fs = std::filesystem;

int main() {
    // Variables for synchronization between threads.
    string dst_if_name;    // the interface to which packets are sent
    mutex mtx;             // lock for dst_if_name
    condition_variable cv; // for reading dst_if_name

    // Packet sender.
    auto packet_sender = [&dst_if_name, &mtx,
                          &cv](chrono::milliseconds period) {
        unique_lock<mutex> lck(mtx);
        Packet packet;
        memset(&packet, 0, sizeof(packet));
        vector<Interface> interfaces =
            open_existing_interfaces(/*tap_only=*/true);

        if (interfaces.empty()) {
            error("No interfaces available");
        }

        info("Found " + to_string(interfaces.size()) + " interfaces");

        while (1) {
            cv.wait_for(lck, period);
            if (dst_if_name.empty()) {
                continue;
            }

            // Find the interface file descriptor.
            auto if_it = find_if(interfaces.begin(), interfaces.end(),
                                 [&dst_if_name](const Interface &i) {
                                     return i.if_name == dst_if_name;
                                 });
            if (if_it == interfaces.end()) {
                warn("Interface not found: " + dst_if_name);
                continue;
            }

            info("Sending a packet to " + dst_if_name);
            ssize_t nwrite = write(if_it->fd, &packet, sizeof(packet));
            if (nwrite < 0) {
                error("Failed to send packet", errno);
            }
        }
    };
    std::thread sending_thread(packet_sender, chrono::milliseconds(1000));

    // Create the send_packet file.
    const fs::path send_packet_fn("/dev/shm/send_packet");
    ofstream send_packet(send_packet_fn);
    if (!send_packet) {
        error("Failed to open " + send_packet_fn.string());
    }
    send_packet.close();

    // File notification handler.
    auto notification_handler = [&dst_if_name, &mtx,
                                 &cv](inotify::Notification notification) {
        string if_name;
        ifstream send_packet_file(notification.path);
        send_packet_file >> if_name;
        send_packet_file.close();
        info("Notification handler read '" + if_name + "' interface name");

        lock_guard<mutex> lck(mtx);
        dst_if_name = if_name;
        cv.notify_all();
    };

    // Monitor the send_packet file on modification.
    auto events = {
        inotify::Event::modify, // File was modified.
    };
    auto notifier = inotify::BuildNotifier()
                        .watchFile(send_packet_fn)
                        .onEvents(events, notification_handler);
    info("Monitoring " + send_packet_fn.string());
    std::thread monitor_thread([&notifier]() { notifier.run(); });

    if (sending_thread.joinable()) {
        sending_thread.join();
    }
    if (monitor_thread.joinable()) {
        monitor_thread.join();
    }

    info("Exiting");
    return 0;
}
