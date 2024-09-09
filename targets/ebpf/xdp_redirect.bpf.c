#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <string.h>
#include <net/if.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} intf_count SEC(".maps");

struct DemoHeader {
    uint8_t port; // egress port
};

struct Headers {
    struct ethhdr eth;
    struct DemoHeader demo;
};

SEC("xdp")
int xdp_redirect(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    ssize_t len = data_end - data;
    struct Headers* hdrs;
    
    // Data too short
    if (data + sizeof(*hdrs) > data_end)
    	return XDP_DROP;
    
    hdrs=(struct Headers*)data;
    uint16_t ethertype = ntohs(hdrs->eth.h_proto);
    
    // Unexpected ethernet protocol
    if (ethertype != 0xdead)
        return XDP_DROP;
        
    // Count the number of interfaces
    
    __u32 key = 0;
    __u32* value = bpf_map_lookup_elem(&intf_count, &key);
    if (!value)
        return XDP_DROP;
    
    // NULL-check the number of interfaces
   	
    __u32 intf_num = *value;

    // Destination port out of range
    if (hdrs->demo.port >= intf_num)
    	return XDP_DROP;
    
    return bpf_redirect(hdrs->demo.port, 0);
}
