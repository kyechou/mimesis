#include "sender.hpp"

#include <cerrno>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
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
    Packet packet;
    memset(&packet, 0, sizeof(packet));
    vector<Interface> interfaces = open_existing_interfaces();

    if (interfaces.empty()) {
        error("No interfaces available");
    }

    auto notification_handler = [&](inotify::Notification notification) {
        auto ts = chrono::duration_cast<chrono::microseconds>(
                      notification.time.time_since_epoch())
                      .count();
        const auto &intf = interfaces.at(0);
        stringstream ss;
        ss << "[" << ts << "] Sending a packet to " << intf.if_name;
        info(ss.str());

        ssize_t nwrite = write(intf.fd, &packet, sizeof(packet));
        if (nwrite < 0) {
            error("Failed to send packet", errno);
        }
    };

    // Create the send_packet file at the shared folder.
    fs::path shared_dir("/dev/shm/mimesis");
    fs::path send_packet_file(shared_dir / "send_packet");
    fs::create_directory(shared_dir);
    ofstream send_packet(send_packet_file);
    send_packet.close();

    // Monitor the send_packet file on modification.
    auto events = {
        inotify::Event::modify, // File was modified.
    };
    auto notifier = inotify::BuildNotifier()
                        .watchFile(send_packet_file)
                        .onEvents(events, notification_handler);
    std::thread event_loop_thread([&notifier]() { notifier.run(); });

    if (event_loop_thread.joinable()) {
        event_loop_thread.join();
    }

    return 0;
}
