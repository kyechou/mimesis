#include <bpf/libbpf.h>
#include <bpf/libbpf_common.h>
#include <bpf/libbpf_legacy.h>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <linux/bpf.h>
#include <net/if.h>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>
#include <xdp/libxdp.h>

#include "demo-stateless.skel.h"
#include "lib/logger.hpp"

using namespace std;

class XDPLoader {
private:
    struct demo_stateless_bpf *_bpf = nullptr;
    struct xdp_program *_xdp = nullptr;
    struct bpf_map *if_params = nullptr;
    struct bpf_map *debug_map = nullptr;

    XDPLoader();
    static int libbpf_print_fn(enum libbpf_print_level level,
                               const char *format,
                               va_list args);
    static int libxdp_print_fn(enum libxdp_print_level level,
                               const char *format,
                               va_list args);

public:
    // Disable the copy/move constructors and the assignment operators.
    XDPLoader(const XDPLoader &) = delete;
    XDPLoader(XDPLoader &&) = delete;
    XDPLoader &operator=(const XDPLoader &) = delete;
    XDPLoader &operator=(XDPLoader &&) = delete;
    ~XDPLoader() { stop(); }

    static XDPLoader &get();

    // Open, load, and verify the BPF program.
    void start();
    // Unload and destroy the BPF program.
    void stop();
    // Attach the XDP program to the specified interfaces.
    void attach(const vector<pair<unsigned int, string>> &interfaces);
    // Detach the XDP program from the interfaces.
    void detach(vector<pair<unsigned int, string>> interfaces = {});
    // Detach any attached XDP programs from the interfaces.
    void detach_all_prog(vector<pair<unsigned int, string>> interfaces = {});
    // Map I/O
    void read_if_params(uint32_t &num_intfs, uint32_t &ifindex_offset);
    void write_if_params(const uint32_t num_intfs,
                         const uint32_t ifindex_offset);
    void read_debug_map(uint64_t &data,
                        uint64_t &data_end,
                        uint64_t &ingress_ifindex);
    // Error handling helper.
    static string xdp_errmsg(int err);
    // Get the mapping between <interface ID -> (ifindex, ifname)>.
    static vector<pair<unsigned int, string>> get_interfaces();
};

int main() {
    XDPLoader &loader = XDPLoader::get();
    auto interfaces = loader.get_interfaces();
    if (interfaces.empty()) {
        error("No interfaces available");
    }

    loader.start();
    loader.attach(interfaces);
    // loader.write_if_params(interfaces.size(), interfaces[0].first);

    char buffer[1024] = {0};
    uint64_t data, data_end, iifidx;

    while (1) {
        sleep(1);

        loader.read_debug_map(data, data_end, iifidx);
        snprintf(buffer, sizeof(buffer),
                 "data=%016lx data_end=%016lx iifidx=%lu", data, data_end,
                 iifidx);
        info(buffer);
    }

    loader.stop();
    return 0;
}

XDPLoader::XDPLoader() {
    libbpf_set_print(libbpf_print_fn);
    libxdp_set_print(libxdp_print_fn);
}

XDPLoader &XDPLoader::get() {
    static XDPLoader instance;
    return instance;
}

void XDPLoader::start() {
    if (_bpf) {
        error("BPF program is already opened");
    }
    if (_xdp) {
        error("XDP program is already created");
    }

    detach_all_prog();

    if (!(_bpf = demo_stateless_bpf__open())) {
        error("Failed to open the BPF program", errno);
    }
    info("Opened the BPF program");

    DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, .obj = _bpf->obj);
    _xdp = xdp_program__create(&xdp_opts);
    int err = libxdp_get_error(_xdp);
    if (err) {
        error("Failed to create XDP program: " + xdp_errmsg(err));
    }
    info("Created the XDP program");
}

void XDPLoader::stop() {
    detach();
    if (_xdp) {
        xdp_program__close(_xdp);
        _xdp = nullptr;
        info("Closed the XDP program");
    }
    if (_bpf) {
        _bpf->destroy(_bpf);
        _bpf = nullptr;
        info("Destroyed the BPF program");
    }
}

void XDPLoader::attach(const vector<pair<unsigned int, string>> &interfaces) {
    if (!_xdp) {
        return;
    }
    for (const auto &[ifindex, ifname] : interfaces) {
        int err = xdp_program__attach(_xdp, ifindex, XDP_MODE_SKB, /*flags=*/0);
        if (err) {
            error("Failed to attach XDP program to iface " + ifname + " (" +
                  to_string(ifindex) + "): " + xdp_errmsg(err));
        }
        string prog_name = xdp_program__name(_xdp);
        unsigned int id = xdp_program__id(_xdp);
        info("Attached XDP program " + prog_name + " (" + to_string(id) +
             ") to iface " + ifname + " (" + to_string(ifindex) + ")");
    }

    // Find and save maps
    if_params =
        bpf_object__find_map_by_name(xdp_program__bpf_obj(_xdp), "if_params");
    if (!if_params) {
        error("Failed to find map 'if_params'");
    }
    debug_map =
        bpf_object__find_map_by_name(xdp_program__bpf_obj(_xdp), "debug_map");
    if (!debug_map) {
        error("Failed to find map 'debug_map'");
    }
}

void XDPLoader::detach(vector<pair<unsigned int, string>> interfaces) {
    if (!_xdp) {
        return;
    }
    if (interfaces.empty()) {
        interfaces = get_interfaces();
    }
    for (const auto &[ifindex, ifname] : interfaces) {
        enum xdp_attach_mode mode = xdp_program__is_attached(_xdp, ifindex);
        if (mode) {
            int err = xdp_program__detach(_xdp, ifindex, mode, /*flags=*/0);
            if (err) {
                error("Failed to detach XDP program from iface " + ifname +
                          " (" + to_string(ifindex) + ")",
                      -err);
            }
            info("Detached XDP program from iface " + ifname + " (" +
                 to_string(ifindex) + ")");
        }
    }
}

void XDPLoader::detach_all_prog(vector<pair<unsigned int, string>> interfaces) {
    if (interfaces.empty()) {
        interfaces = get_interfaces();
    }
    for (const auto &[ifindex, ifname] : interfaces) {
        struct xdp_multiprog *mp = xdp_multiprog__get_from_ifindex(ifindex);
        if (libxdp_get_error(mp)) {
            if (errno == ENOENT) {
                // No XDP program is attached to the interface. Move on to the
                // next.
                xdp_multiprog__close(mp);
                continue;
            }
            error("Unable to get xdg_dispatcher program", errno);
        }
        if (!mp) {
            // No XDP program is attached to the interface. Move on to the next.
            xdp_multiprog__close(mp);
            continue;
        }

        int err = xdp_multiprog__detach(mp);
        if (err) {
            xdp_multiprog__close(mp);
            error("Failed to detach XDP programs from iface " + ifname + " (" +
                      to_string(ifindex) + ")",
                  -err);
        }
        xdp_multiprog__close(mp);
    }
}

void XDPLoader::read_if_params(uint32_t &num_intfs, uint32_t &ifindex_offset) {
    if (!if_params) {
        error("Map 'if_params' is not saved yet.");
    }

    static const uint32_t num_intfs_key = 0;
    static const uint32_t ifindex_offset_key = 1;
    if (bpf_map__lookup_elem(if_params, &num_intfs_key, sizeof(num_intfs_key),
                             &num_intfs, sizeof(num_intfs), /*flags=*/0) < 0) {
        error("Failed to lookup if_params map for num_intfs", errno);
    }
    if (bpf_map__lookup_elem(if_params, &ifindex_offset_key,
                             sizeof(ifindex_offset_key), &ifindex_offset,
                             sizeof(ifindex_offset), /*flags=*/0) < 0) {
        error("Failed to lookup if_params map for ifindex_offset", errno);
    }
}

void XDPLoader::write_if_params(const uint32_t num_intfs,
                                const uint32_t ifindex_offset) {
    if (!if_params) {
        error("Map 'if_params' is not saved yet.");
    }

    static const uint32_t num_intfs_key = 0;
    static const uint32_t ifindex_offset_key = 1;
    if (bpf_map__update_elem(if_params, &num_intfs_key, sizeof(num_intfs_key),
                             &num_intfs, sizeof(num_intfs), BPF_ANY) < 0) {
        error("Failed to update if_params map for num_intfs", errno);
    }
    if (bpf_map__update_elem(if_params, &ifindex_offset_key,
                             sizeof(ifindex_offset_key), &ifindex_offset,
                             sizeof(ifindex_offset), BPF_ANY) < 0) {
        error("Failed to update if_params map for ifindex_offset", errno);
    }
    info("Updated if_params map");
}

void XDPLoader::read_debug_map(uint64_t &data,
                               uint64_t &data_end,
                               uint64_t &ingress_ifindex) {
    if (!debug_map) {
        error("Map 'debug_map' is not saved yet.");
    }

    static const uint32_t data_key = 0;
    static const uint32_t data_end_key = 1;
    static const uint32_t iifidx_key = 2;
    if (bpf_map__lookup_elem(debug_map, &data_key, sizeof(data_key), &data,
                             sizeof(data), /*flags=*/0) < 0) {
        error("Failed to lookup debug_map for data", errno);
    }
    if (bpf_map__lookup_elem(debug_map, &data_end_key, sizeof(data_end_key),
                             &data_end, sizeof(data_end), /*flags=*/0) < 0) {
        error("Failed to lookup debug_map for data_end", errno);
    }
    if (bpf_map__lookup_elem(debug_map, &iifidx_key, sizeof(iifidx_key),
                             &ingress_ifindex, sizeof(ingress_ifindex),
                             /*flags=*/0) < 0) {
        error("Failed to lookup debug_map for ingress_ifindex", errno);
    }
}

string XDPLoader::xdp_errmsg(int err) {
    if (!err) {
        return "";
    }
    char errmsg[1024];
    libxdp_strerror(err, errmsg, sizeof(errmsg));
    return errmsg;
}

vector<pair<unsigned int, string>> XDPLoader::get_interfaces() {
    vector<pair<unsigned int, string>> res;
    struct if_nameindex *intfs = if_nameindex();
    if (!intfs) {
        error("if_nameindex()", errno);
    }

    for (auto intf = intfs; intf->if_index != 0 || intf->if_name != nullptr;
         ++intf) {
        string if_name{intf->if_name};
        if (if_name.starts_with("lo") || if_name.starts_with("sit")) {
            continue;
        }
        res.push_back({intf->if_index, intf->if_name});
    }

    if_freenameindex(intfs);
    return res;
}

int XDPLoader::libbpf_print_fn(enum libbpf_print_level level,
                               const char *format,
                               va_list args) {
    // Silence the verbose debug messages.
    if (level >= LIBBPF_DEBUG) {
        return 0;
    }

    constexpr int buffer_sz = 2048;
    static char buffer[buffer_sz];
    int res = vsnprintf(buffer, buffer_sz, format, args);

    if (res < 0) {
        error("vsnprintf() failed: " + to_string(res));
    } else if (static_cast<unsigned int>(res) >= buffer_sz) {
        // output was truncated
        res = buffer_sz - 1;
    }

    for (int i = res - 1; i >= 0 && isspace(buffer[i]); --i) {
        buffer[i] = '\0';
    }

    if (level == LIBBPF_WARN) {
        warn(buffer);
    } else if (level == LIBBPF_INFO) {
        info(buffer);
    } else if (level == LIBBPF_DEBUG) {
        debug(buffer);
    }

    return res;
}

int XDPLoader::libxdp_print_fn(enum libxdp_print_level level,
                               const char *format,
                               va_list args) {
    return libbpf_print_fn((enum libbpf_print_level)level, format, args);
}
