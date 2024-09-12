#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} intf_count SEC(".maps");

struct DemoHeader {
    uint8_t port; // egress port
};

struct Headers {
    struct ethhdr eth;
    struct DemoHeader demo;
};

static inline u16 ntohs(const u16 net) {
    u8 data[2] = {};
    __builtin_memcpy(data, &net, sizeof(data));
    return ((u16)data[1] << 0) | ((u16)data[0] << 8);
}

SEC("xdp")
int xdp_redirect(struct xdp_md *ctx) {
    void *data = NULL, *data_end = NULL;
    BPF_CORE_READ_INTO(&data, ctx, data);
    BPF_CORE_READ_INTO(&data_end, ctx, data_end);

    // The received packet frame is too short.
    if (data + sizeof(struct Headers) > data_end) {
        return XDP_DROP;
    }

    struct Headers *hdrs = data;
    struct ethhdr eth;
    struct DemoHeader demo;
    BPF_CORE_READ_INTO(&eth, hdrs, eth);
    BPF_CORE_READ_INTO(&demo, hdrs, demo);

    // Unexpected ethertype
    uint16_t ethertype = ntohs(eth.h_proto);
    if (ethertype != 0xdead) {
        return XDP_DROP;
    }

    // Get the number of interfaces
    u32 key = 0;
    u32 *num_intfs = (u32 *)bpf_map_lookup_elem(&intf_count, &key);
    if (!num_intfs) {
        return XDP_DROP;
    }

    // Destination port out of range
    if (demo.port >= *num_intfs) {
        return XDP_DROP;
    }

    return bpf_redirect(demo.port, 0);
}
