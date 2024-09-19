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
    struct iphdr ip;
};

int dst_ip_matching(uint32_t dst_addr) {
    // TODO: Do we need a htonl conversion for the IP address?

    // 10.1.2.0/24 -> intf 0
    uint32_t lb = (10ul << 24) + (1ul << 16) + (2ul << 8);
    uint32_t mask = 24;
    if (dst_addr >= lb && dst_addr < lb + (1ul << (32 - mask))) {
        return 0;
    }

    // 10.1.0.0/16 -> intf 1
    lb = (10ul << 24) + (1ul << 16);
    mask = 16;
    if (dst_addr >= lb && dst_addr < lb + (1ul << (32 - mask))) {
        return 1;
    }

    // 10.2.0.0/16 -> intf 2
    lb = (10ul << 24) + (2ul << 16);
    mask = 16;
    if (dst_addr >= lb && dst_addr < lb + (1ul << (32 - mask))) {
        return 2;
    }

    // 10.0.0.0/8  -> intf 3
    lb = (10ul << 24);
    mask = 8;
    if (dst_addr >= lb && dst_addr < lb + (1ul << (32 - mask))) {
        return 3;
    }

    return -1;
}

SEC("xdp")
int demo_stateless(struct xdp_md *ctx) {
    char *data = (char *)(long)ctx->data;
    char *data_end = (char *)(long)ctx->data_end;
    const int ETH_ALEN = 6;

    // // Debug
    // u64 data_loc = (u64)data;
    // u64 data_end_loc = (u64)data_end;
    // u64 iifidx = (u64)ctx->ingress_ifindex;
    // const u32 data_key = 0, data_end_key = 1, iifidx_key = 2;
    // bpf_map_update_elem(&debug_map, &data_key, &data_loc, BPF_ANY);
    // bpf_map_update_elem(&debug_map, &data_end_key, &data_end_loc, BPF_ANY);
    // bpf_map_update_elem(&debug_map, &iifidx_key, &iifidx, BPF_ANY);

    // The received packet frame is too short.
    if (data + sizeof(struct Headers) > data_end) {
        return XDP_DROP;
    }

    // Unexpected ethertype
    struct Headers *hdrs = (struct Headers *)data;
    uint16_t ethertype = bpf_ntohs(hdrs->eth.h_proto);
    if (ethertype != 0xdead) {
        return XDP_DROP;
    }

    // Interface parameters
    const u32 num_intfs_key = 0, idx_offset_key = 1;
    u32 *num_intfs = (u32 *)bpf_map_lookup_elem(&if_params, &num_intfs_key);
    u32 *idx_offset = (u32 *)bpf_map_lookup_elem(&if_params, &idx_offset_key);
    if (!num_intfs || !idx_offset) {
        return XDP_DROP;
    }
    
    int eg_intf = dst_ip_matching(hdrs->ip.daddr);
    if (eg_intf == -1)
    	return XDP_DROP;

    // Destination port out of range
    if (eg_intf >= (int)*num_intfs) {
        return XDP_DROP;
    }
    
    for(int i=0; i<ETH_ALEN ; i++) {
    	hdrs->eth.h_source[i]=0;
    }
    hdrs->eth.h_source[ETH_ALEN -1] = eg_intf;

    return bpf_redirect(eg_intf + *idx_offset, 0);
}