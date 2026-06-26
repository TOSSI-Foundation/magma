/*
 * gtp_mark.c - TC ingress handler attached to gtp_veth0.
 *
 * When gtp_decap.c redirects the decapsulated inner packet to gtp_veth0 via
 * bpf_redirect(), the kernel clears skb->mark. This handler re-derives the UE
 * from the inner source IP, looks up the session, and restores the QoS mark so
 * OVS (on gtp_br0) sees the correct per-UE classification.
 *
 * NOTE: maps/structs are declared inline here to stay byte-identical with
 * gtp_decap.c / gtp_encap.c. All three will switch to the shared "gtp_maps.h"
 * during the libbpf compile bring-up (then maps gain LIBBPF_PIN_BY_NAME).
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_HLEN
#define ETH_HLEN 14
#endif
#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

/* UE session structures (must match gtp_decap.c / gtp_encap.c). */
struct ue_session_key {
    __be32 ue_ip;           /* keyed with a HOST-order value (see Finding 6 fix) */
};

struct ue_session_info {
    __be32 enb_ip;
    __u32 teid_ul_in;
    __u32 teid_ul_out;
    __u32 teid_dl_in;
    __u32 teid_dl_out;
    __u32 s1u_ifindex;
    __u32 sgi_ifindex;
    __u32 ovs_ifindex;
    __u8 ul_mac_src[6];
    __u8 ul_mac_dst[6];
    __u32 qos_mark;
    __u32 bearer_id;
    __u64 ul_bytes;
    __u64 dl_bytes;
    __u64 ul_packets;
    __u64 dl_packets;
    __u64 last_seen;
    __u32 session_flags;
    __u8 imsi[16];
    __u32 imsi_len;
    __u64 encoded_imsi;
    __u8 qfi;
    __u32 tunnel_id;
    __be32 tun_ipv4_dst;
    __u8 tun_flags;
    __u8 direction;
    __u32 original_port;
    __u8 reserved[3];
    __u32 metadata_mark;    /* mark stashed by gtp_decap.c, restored here */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct ue_session_key);
    __type(value, struct ue_session_info);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ue_session_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} stats_map SEC(".maps");

/* Statistics counters (gtp_veth0 mark handler range). */
#define STATS_VETH0_PACKETS_PROCESSED 50
#define STATS_VETH0_MARK_RESTORED 51
#define STATS_VETH0_MARK_FALLBACK 52
#define STATS_VETH0_SESSION_MISS 53

static __always_inline void update_stats(__u32 counter_id, __u64 value) {
    __u64 *count = bpf_map_lookup_elem(&stats_map, &counter_id);
    if (count)
        *count += value;
}

SEC("tc")
int gtp_veth0_mark_handler(struct __sk_buff *skb) {
    update_stats(STATS_VETH0_PACKETS_PROCESSED, 1);

    __u8 pkt_data[40];
    if (bpf_skb_load_bytes(skb, 0, pkt_data, sizeof(pkt_data)) < 0)
        return TC_ACT_OK;  /* pass through on short read */

    __u16 eth_type = (__u16)pkt_data[12] << 8 | (__u16)pkt_data[13];
    if (eth_type != ETH_P_IP)
        return TC_ACT_OK;  /* pass through non-IPv4 */

    __u8 ip_version = (pkt_data[ETH_HLEN] >> 4) & 0xF;
    if (ip_version != 4)
        return TC_ACT_OK;

    /*
     * Phase-1 Fix (Finding 6): key the session map in HOST byte order. The wire
     * address is big-endian; gtp_decap.c calls bpf_ntohl() before lookup and the
     * userspace populator packs host order, so this handler must match.
     */
    __be32 src_ip_be = *((__be32 *)&pkt_data[ETH_HLEN + 12]);
    __u32 src_ip = bpf_ntohl(src_ip_be);

    bpf_printk("[VETH0] pkt from UE IP host=0x%x net=0x%x", src_ip, src_ip_be);

    struct ue_session_key session_key = {.ue_ip = src_ip};
    struct ue_session_info *session_info =
        bpf_map_lookup_elem(&ue_session_map, &session_key);

    if (session_info == NULL) {
        update_stats(STATS_VETH0_SESSION_MISS, 1);
        return TC_ACT_OK;  /* pass through if no session */
    }

    if (!(session_info->session_flags & 1))
        return TC_ACT_OK;  /* pass through inactive sessions */

    __u32 restored_mark = bpf_ntohl(session_info->metadata_mark);
    skb->mark = restored_mark;
    update_stats(STATS_VETH0_MARK_RESTORED, 1);

    bpf_printk("[VETH0] restored mark 0x%x for UE 0x%x", restored_mark, src_ip);
    return TC_ACT_OK;  /* continue to OVS with mark set */
}

char _license[] SEC("license") = "GPL";
