#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <string.h>
#include <net/if.h>

struct DemoHeader {
    uint8_t port; // egress port
};

struct Headers {
    struct ethhdr eth;
    struct DemoHeader demo;
};

SEC("xdp_redirect")
int xdp_redirect_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    ssize_t len = data_end - data;
    struct Headers hdrs;
    
    // Data too short
    if (len < sizeof(hdrs))
    	return XDP_DROP;
    memcpy(&hdrs, data, len);
    uint16_t ethertype = ntohs(hdrs.eth.h_proto);
    
    // Unexpected ethernet protocol
    if (ethertype != 0xdead)
        return XDP_DROP;
        
    // Count the number of interfaces
    struct if_nameindex *intfs = if_nameindex();
    int intf_count=0;
    for (struct if_nameindex * intf = intfs; intf->if_index != 0 || intf->if_name != NULL; ++intf)
    	intf_count++;
    if_freenameindex(intfs);
    
    // Destination port out of range
    if (hdrs.demo.port >= intf_count)
    	return XDP_DROP;
    
    return bpf_redirect(hdrs.demo.port, 0);
}
