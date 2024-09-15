#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} intf_count SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} debug_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} data_map SEC(".maps");

struct DemoHeader {
    uint8_t port; // egress port
};

struct Headers {
    struct ethhdr eth;
    struct DemoHeader demo;
};
/*
static inline u16 ntohs(const u16 net) {
    u8 data[2] = {};
    __builtin_memcpy(data, &net, sizeof(data));
    return ((u16)data[1] << 0) | ((u16)data[0] << 8);
}
*/
SEC("xdp")
int xdp_redirect(struct xdp_md *ctx) {
	__u32 key = 0;
	__u32 debug_val=0;
	
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 data_raw = (__u64)data;
	
	

    // The received packet frame is too short.
    if (data + sizeof(struct Headers) > data_end) {
    	debug_val=1;
   		bpf_map_update_elem(&debug_map, &key, &debug_val, 0);
        return XDP_DROP;
    }

    struct Headers *hdrs = data;
    struct ethhdr *eth = &hdrs->eth;
	struct DemoHeader *demo = &hdrs->demo;
	bpf_map_update_elem(&debug_map, &key, &debug_val, 0);
	bpf_map_update_elem(&data_map, &key, &data_raw, 0);

    // Unexpected ethertype
    uint16_t ethertype = bpf_ntohs(eth->h_proto);
    if (ethertype != 0xdead) {
    	debug_val=2;
   		bpf_map_update_elem(&debug_map, &key, &debug_val, 0);
        return XDP_DROP;
    }

    // Get the number of interfaces
    u32 *num_intfs = bpf_map_lookup_elem(&intf_count, &key);
    if (!num_intfs) {
    	debug_val=3;
    	bpf_map_update_elem(&debug_map, &key, &debug_val, 0);
        return XDP_DROP;
    }

    // Destination port out of range
    if (demo->port >= *num_intfs) {
    	debug_val=4;
    	bpf_map_update_elem(&debug_map, &key, &debug_val, 0);
        return XDP_DROP;
    }
    
    debug_val=5;
    bpf_map_update_elem(&debug_map, &key, &debug_val, 0);
    return bpf_redirect(hdrs->demo.port, 0);
}
