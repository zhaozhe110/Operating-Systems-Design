#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "bpf/bpf_helpers.h"

struct port_rule {
  __u8 udp_action;
  __u8 tcp_action;
};

struct bpf_map_def SEC("maps") port_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct port_rule),
    .max_entries = 65536,
};

SEC("xdp_port_blocker")
int xdp_filter_by_port(struct xdp_md *ctx) {
  // convert the packet to a series of netowkr headers
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Check for Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // Check for IP header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    // Filter based on protocol
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)(tcp + 1) > data_end) {
            return XDP_PASS;
        }

        u32 port = ntohs(tcp->dest);
        struct port_rule *rule = bpf_map_lookup_elem(&port_map, &port);
        if (rule && rule->tcp_action == XDP_DROP) {
            return XDP_DROP;
        }

    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)(udp + 1) > data_end) {
            return XDP_PASS;
        }

        u32 port = ntohs(udp->dest);
        struct port_rule *rule = bpf_map_lookup_elem(&port_map, &port);
        if (rule && rule->udp_action == XDP_DROP) {
            return XDP_DROP;
        }
    }


  // Add more rules here...

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
