#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/**
 * 0: num_intfs
 * 1: ifindex_offset
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, u32);
    __type(value, u32);
} if_params SEC(".maps");

/**
 * 0: data
 * 1: data_end
 * 2: ingress_ifindex
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, u32);
    __type(value, u64);
} debug_map SEC(".maps");

struct DemoHeader {
    uint8_t port; // egress port
    uint8_t type; // packet type. 0: init, 1: follow-up
};

struct Headers {
    struct ethhdr eth;
    struct DemoHeader demo;
};

SEC("xdp")
int demo_stateless(struct xdp_md *ctx) {
    char *data = (char *)(long)ctx->data;
    char *data_end = (char *)(long)ctx->data_end;

    // Debug
    u64 data_loc = (u64)data;
    u64 data_end_loc = (u64)data_end;
    u64 iifidx = (u64)ctx->ingress_ifindex;
    const u32 data_key = 0, data_end_key = 1, iifidx_key = 2;
    bpf_map_update_elem(&debug_map, &data_key, &data_loc, BPF_ANY);
    bpf_map_update_elem(&debug_map, &data_end_key, &data_end_loc, BPF_ANY);
    bpf_map_update_elem(&debug_map, &iifidx_key, &iifidx, BPF_ANY);

    // // The received packet frame is too short.
    // if (data + sizeof(struct Headers) > data_end) {
    //     return XDP_DROP;
    // }

    // Unexpected ethertype
    // struct Headers *hdrs = (struct Headers *)data;
    // uint16_t ethertype = bpf_ntohs(hdrs->eth.h_proto);
    // bpf_printk("data: %lx, data_end: %lx, ethertype: %x", data, data_end,
    //            ethertype);
    // if (ethertype != 0xdead) {
    //     bpf_printk("drop");
    //     return XDP_DROP;
    // }

    // // Get the number of interfaces
    // u32 *num_intfs = (u32 *)bpf_map_lookup_elem(&if_params, &key);
    // if (!num_intfs) {
    //     return XDP_DROP;
    // }
    //
    // // Destination port out of range
    // if (hdrs->demo.port >= *num_intfs) {
    //     return XDP_DROP;
    // }

    return bpf_redirect(ctx->ingress_ifindex, 0);
    // return bpf_redirect(hdrs->demo.port + 2, 0);
}
