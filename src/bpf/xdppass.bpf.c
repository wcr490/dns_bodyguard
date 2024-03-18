#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	int pkt_sz = data_end - data;
	struct ethhdr *eth;
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
		return XDP_PASS;
	}
	struct iphdr *ip = data + sizeof(struct ethhdr);
	if (ip->protocol != 17) {
		return XDP_PASS;
	}
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) >
	    data_end) {
		return XDP_PASS;
	}
	struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + 12 > data_end) {
		return XDP_PASS;
	}
	if (ip->id == 0) {
		return XDP_DROP;
	}

	__be16 *flags = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + 10;
	if (bpf_htons(*flags) == 0x8580) {
		return XDP_DROP;
	}
	if (ip->frag_off != 0) {
		return XDP_DROP;
	}
	if (bpf_htons(udp->source) == 53) {
		bpf_printk("%d %d", bpf_htons(ip->id), bpf_htons(ip->frag_off));
		bpf_printk("port: %d : %d\n", bpf_htons(udp->source), bpf_htons(udp->dest));
		bpf_printk("0x%x\n", bpf_htons(*flags));
		bpf_printk("drop packet size: %d\n", pkt_sz);
	}
	return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
