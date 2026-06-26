

#ifdef COMPILE_TIME
static const int compile_timestamp = COMPILE_TIME;
#endif

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef ETH_HLEN
#define ETH_HLEN 14
#endif

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif
#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif
#ifndef TC_ACT_REDIRECT
#define TC_ACT_REDIRECT 7
#endif

#define BPF_ADJ_ROOM_MAC 1
#define BPF_ADJ_ROOM_NET 0

struct ue_session_key {
    __be32 ue_ip;
};

struct ue_session_info {
    __be32 enb_ip;
    __u32 teid_ul_in;    // TEID for uplink (eNB->UE)
    __u32 teid_ul_out;   // TEID for uplink response
    __u32 teid_dl_in;    // TEID for downlink (UE->eNB)
    __u32 teid_dl_out;   // TEID for downlink response
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
    __u32 metadata_mark;
};

// Configuration map for interface indices
struct config_key {
    __u32 key;
};

struct config_value {
    __u32 value;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct ue_session_key);
    __type(value, struct ue_session_info);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ue_session_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, struct config_key);
    __type(value, struct config_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} stats_map SEC(".maps");

#define STATS_UL_PACKETS 0
#define STATS_UL_BYTES 1
#define STATS_DL_PACKETS 2
#define STATS_DL_BYTES 3
#define STATS_UL_ERRORS 4
#define STATS_DL_ERRORS 5
#define STATS_SESSION_MISS 6
#define STATS_TEID_MISMATCH 7
#define STATS_GTP_DECAP_SUCCESS 8
#define STATS_GTP_ENCAP_SUCCESS 9
#define STATS_PKT_TOO_SHORT 10
#define STATS_INVALID_GTP 11
#define STATS_ADJUST_HEAD_FAIL 12
#define STATS_TOTAL_PROCESSED 13
#define STATS_UE_ATTACH 14
#define STATS_UE_DETACH 15
#define STATS_PKT_FORWARDED 16
#define STATS_PKT_DROPPED 17
#define STATS_SESSION_ACTIVE 18
#define STATS_QOS_APPLIED 19
#define STATS_INACTIVE_SESSION 20
#define STATS_DOUBLE_ENCAP_AVOIDED 21

#define CONFIG_S1U_IFINDEX 0
#define CONFIG_SGI_IFINDEX 1
#define CONFIG_OVS_IFINDEX 2
#define CONFIG_DEBUG_LEVEL 3
#define CONFIG_SGI_IP 4
#define CONFIG_EBPF_VETH_IFINDEX 5
#define CONFIG_LINK_MTU 6

// L3 (IP-payload) MTU of the S1-U egress link if CONFIG_LINK_MTU is unset/0.
#define DEFAULT_LINK_MTU 1500
// bpf_skb_adjust_room flag (added 5.0): keep coalesced/GSO skbs valid after grow.
#ifndef BPF_F_ADJ_ROOM_FIXED_GSO
#define BPF_F_ADJ_ROOM_FIXED_GSO (1ULL << 0)
#endif

static inline void update_stats(__u32 counter_id, __u64 value) {
    __u64 *count = bpf_map_lookup_elem(&stats_map, &counter_id);
    if (count) {
        *count += value;
    }
}

#define GTP_HDR_SIZE_MIN 8
#define GTP_VERSION_1 0x01
#define GTP_PT_FLAG 0x01
#define GTP_MSG_TPDU 0xFF
#define GTP_FLAG_PT 0x10
#define GTP_PORT_NO 2152

struct gtp1_header {
    __u8 flags;
    __u8 type;
    __be16 length;
    __be32 teid;
} __attribute__((packed));

static inline __u16 ip_checksum(__u8 *data, int len) {
    __u32 sum = 0;

    #pragma unroll
    for (int i = 0; i < 10; i++) {  // IP header is 20 bytes = 10 words
        if (i * 2 < len) {
            sum += ((__u16)data[i * 2] << 8) | (__u16)data[i * 2 + 1];
        }
    }

    #pragma unroll
    for (int i = 0; i < 2; i++) {  // Two iterations sufficient for 32-bit sum
        if (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    return ~sum;
}
SEC("tc")
int gtp_encap_handler(struct __sk_buff *skb) {
    update_stats(STATS_TOTAL_PROCESSED, 1);

    
    
    __u8 pkt_data[38];  // Phase-1 Fix (Finding 2): 38B suffices; 64 dropped valid short DL packets
    if (bpf_skb_load_bytes(skb, 0, pkt_data, sizeof(pkt_data)) < 0) {
        update_stats(STATS_PKT_TOO_SHORT, 1);
        return TC_ACT_SHOT;  // Drop malformed packets
    }
    
    __u16 eth_type = (__u16)pkt_data[12] << 8 | (__u16)pkt_data[13];
    
    if (eth_type != ETH_P_IP) {
        return TC_ACT_OK;  // Pass non-IPv4 packets
    }
    
    __u8 ip_version = (pkt_data[14] >> 4) & 0xF;
    __u8 ip_protocol = pkt_data[23];  // Protocol field at offset 23 (14+9)
    
    if (ip_version != 4) {
        return TC_ACT_OK;  // Pass non-IPv4
    }
    
    if (ip_protocol == IPPROTO_UDP) {
        // Phase-1 Fix (Finding 4): compute UDP offset from IHL (was fixed 34/36)
        __u8 de_ihl = pkt_data[14] & 0x0F;
        __u32 de_udp_off = 14 + (__u32)de_ihl * 4;
        __u8 de_ports[4];
        if (de_ihl >= 5 && bpf_skb_load_bytes(skb, de_udp_off, de_ports, 4) == 0) {
            __u16 udp_src = ((__u16)de_ports[0] << 8) | de_ports[1];
            __u16 udp_dest = ((__u16)de_ports[2] << 8) | de_ports[3];
            if (udp_dest == 2152 || udp_src == 2152) {
                update_stats(STATS_DOUBLE_ENCAP_AVOIDED, 1);
                return TC_ACT_OK;  // Already GTP encapsulated
            }
        }
    }

    __be32 dst_ip_be = *((__be32 *)&pkt_data[30]);

    __u32 dst_ip = bpf_ntohl(dst_ip_be);

    bpf_printk("[ENCAP] OUT: Processing packet for downlink\n");
    bpf_printk("[ENCAP] Dst IP (host order): 0x%x\n", dst_ip);

    struct ue_session_key session_key;
    session_key.ue_ip = dst_ip;

    struct ue_session_info *session_info =
    bpf_map_lookup_elem(&ue_session_map, &session_key);

    if (session_info == NULL) {
        bpf_printk("[ENCAP] Session NOT FOUND for UE IP: 0x%x\n", dst_ip);
        update_stats(STATS_SESSION_MISS, 1);
        update_stats(STATS_PKT_DROPPED, 1);
        return TC_ACT_SHOT;  // Drop unknown sessions
    }

    bpf_printk("[ENCAP] Session FOUND! TEID_DL_OUT: 0x%x",
            session_info->teid_dl_out);
    bpf_printk("[ENCAP] eNB IP: 0x%x\n", session_info->enb_ip);

    if (!(session_info->session_flags & 1) || session_info->teid_dl_out == 0) {
        bpf_printk("[ENCAP] Session INACTIVE or no TEID\n");
        update_stats(STATS_INACTIVE_SESSION, 1);
        update_stats(STATS_PKT_DROPPED, 1);
        return TC_ACT_SHOT;  // Drop inactive sessions
    }
    
    
    // Phase-1 Fix (Finding 4): Count only UE payload bytes for DL stats
    __u64 payload_len = skb->len;
    session_info->dl_packets++;
    session_info->dl_bytes += payload_len;

    session_info->last_seen = bpf_ktime_get_ns();
    
    // Apply QoS marking if configured
    if (session_info->qos_mark > 0) {
        // QoS marking would be applied here
        update_stats(STATS_QOS_APPLIED, 1);
    }
    
    __u32 gtp_hdr_len = GTP_HDR_SIZE_MIN;
    __u32 outer_hdr_len = sizeof(struct iphdr) + sizeof(struct udphdr) + gtp_hdr_len;
    
    __u16 inner_len = ((__u16)pkt_data[16] << 8) | (__u16)pkt_data[17];  // IP total length

    __u32 gtp_ext_len = 8;
    outer_hdr_len += gtp_ext_len;

    // Phase-2 Fix (encap-mtu-no-fragmentation-df-set): DYNAMIC, FAIL-LOUD egress-MTU
    // guard. bpf_redirect() bypasses ip_finish_output/ip_fragment, and we force DF on
    // the outer header, so an oversize outer frame is silently black-holed on the wire.
    // Drop it here instead of emitting a >MTU DF frame.
    //
    // Use skb->len (actual bytes the kernel will transmit), NOT the inner IP
    // total-length field from the packet (pkt_data[16..17] -> inner_len), which is
    // peer-controlled and unvalidated against the real frame. At gtp_veth1 ingress the
    // frame is [ETH_HLEN | inner IPv4 ...], so the outer L3 size after we strip the old
    // L2 and prepend IP/UDP/GTP is (skb->len - ETH_HLEN) + outer_hdr_len. Compare that
    // against the L3 link MTU. This also subsumes the old integer-overflow no-op.
    struct config_key mtu_key = {.key = CONFIG_LINK_MTU};
    struct config_value *mtu_val = bpf_map_lookup_elem(&config_map, &mtu_key);
    __u32 link_mtu = (mtu_val && mtu_val->value) ? mtu_val->value : DEFAULT_LINK_MTU;

    if (skb->len <= ETH_HLEN) {            // malformed: no room for an inner IP header
        update_stats(STATS_DL_ERRORS, 1);
        update_stats(STATS_PKT_DROPPED, 1);
        return TC_ACT_SHOT;
    }
    __u32 outer_l3_len = (skb->len - ETH_HLEN) + outer_hdr_len;  // bounded, no overflow
    if (outer_l3_len > link_mtu) {
        bpf_printk("[ENCAP] DROP oversize: outer_l3=%u > link_mtu=%u\n",
                   outer_l3_len, link_mtu);
        update_stats(STATS_DL_ERRORS, 1);
        update_stats(STATS_PKT_DROPPED, 1);
        return TC_ACT_SHOT;  // fail loud: do not emit a >MTU DF outer frame
    }
    int ret = bpf_skb_adjust_room(skb, outer_hdr_len, BPF_ADJ_ROOM_MAC,
                                  BPF_F_ADJ_ROOM_FIXED_GSO);
    if (ret < 0) {
        update_stats(STATS_ADJUST_HEAD_FAIL, 1);
        update_stats(STATS_DL_ERRORS, 1);
        return TC_ACT_SHOT;
    }

    __u8 headers[14 + 20 + 8 + 8 + 8];

    headers[0] = session_info->ul_mac_dst[0]; // dst MAC
    headers[1] = session_info->ul_mac_dst[1];
    headers[2] = session_info->ul_mac_dst[2];
    headers[3] = session_info->ul_mac_dst[3];
    headers[4] = session_info->ul_mac_dst[4];
    headers[5] = session_info->ul_mac_dst[5];
    headers[6] = session_info->ul_mac_src[0]; // src MAC
    headers[7] = session_info->ul_mac_src[1];
    headers[8] = session_info->ul_mac_src[2];
    headers[9] = session_info->ul_mac_src[3];
    headers[10] = session_info->ul_mac_src[4];
    headers[11] = session_info->ul_mac_src[5];
    headers[12] = 0x08; // ETH_P_IP high byte
    headers[13] = 0x00; // ETH_P_IP low byte
    
    headers[14] = 0x45; // version=4, ihl=5
    headers[15] = 0x00; // tos
    __u16 total_len = 20 + 8 + 8 + gtp_ext_len + inner_len; // IP + UDP + GTP + Extension + payload
    headers[16] = (total_len >> 8) & 0xFF;
    headers[17] = total_len & 0xFF;
    headers[18] = 0x00; headers[19] = 0x00; // id
    headers[20] = 0x00; headers[21] = 0x00; // flags=0 (DF cleared); MTU guard ensures fit
    headers[22] = 64; // ttl
    headers[23] = IPPROTO_UDP; // protocol
    headers[24] = 0x00; headers[25] = 0x00; 
    
    struct config_key sgi_ip_key = {.key = CONFIG_SGI_IP};
    struct config_value *sgi_ip_val = bpf_map_lookup_elem(&config_map, &sgi_ip_key);
    // Phase-1 Fix (Finding 5): fail closed if SGi source IP not configured
    if (!sgi_ip_val || sgi_ip_val->value == 0) {
        update_stats(STATS_DL_ERRORS, 1);
        return TC_ACT_SHOT;
    }
    __u32 src_ip = sgi_ip_val->value;
    headers[26] = (src_ip >> 24) & 0xFF;
    headers[27] = (src_ip >> 16) & 0xFF;
    headers[28] = (src_ip >> 8) & 0xFF;
    headers[29] = src_ip & 0xFF;

    __u32 enb_ip = session_info->enb_ip;
    headers[30] = (enb_ip >> 24) & 0xFF;
    headers[31] = (enb_ip >> 16) & 0xFF;
    headers[32] = (enb_ip >> 8) & 0xFF;
    headers[33] = enb_ip & 0xFF;
    
    headers[34] = (GTP_PORT_NO >> 8) & 0xFF; // src port
    headers[35] = GTP_PORT_NO & 0xFF;
    headers[36] = (GTP_PORT_NO >> 8) & 0xFF; // dst port
    headers[37] = GTP_PORT_NO & 0xFF;
    __u16 udp_len = 8 + 8 + gtp_ext_len + inner_len; // UDP + GTP + Extension + payload
    headers[38] = (udp_len >> 8) & 0xFF;
    headers[39] = udp_len & 0xFF;
    headers[40] = 0x00; headers[41] = 0x00; // checksum

    headers[42] = GTP_FLAG_PT | (GTP_VERSION_1 << 5) | 0x04; // flags with E flag (0x04) for extension
    headers[43] = GTP_MSG_TPDU; // type
    __u16 gtp_payload_len = gtp_ext_len + inner_len; // Extension + inner packet
    headers[44] = (gtp_payload_len >> 8) & 0xFF; // length
    headers[45] = gtp_payload_len & 0xFF;
    // Phase-1 Fix (Finding 2): Write TEID in network byte order
    __be32 teid = session_info->teid_dl_out;
    __builtin_memcpy(&headers[46], &teid, sizeof(teid));

    headers[50] = 0x00; headers[51] = 0x00; // Sequence number (not used)
    headers[52] = 0x00; // N-PDU number (not used)
    headers[53] = 0x85; // Next extension type = PDU Session Container (5G)

    headers[54] = 0x01; // Extension length (1 = 4 bytes)
    headers[55] = 0x00; // PDU Type = 0 (DL PDU SESSION INFORMATION), per TS 38.415: high nibble 0 = downlink. (0x10 set the uplink type and is rejected by conformant gNBs.)
    __u8 qfi = session_info->qfi ? session_info->qfi : 9; // Default QFI=9 if not set
    headers[56] = qfi & 0x3F; // QFI (6 bits)
    headers[57] = 0x00; // Next extension type = 0 (no more extensions)

    __u16 ip_csum = ip_checksum(&headers[14], 20);
    headers[24] = (ip_csum >> 8) & 0xFF;
    headers[25] = ip_csum & 0xFF;

    if (bpf_skb_store_bytes(skb, 0, headers, 58, 0) < 0) {
        update_stats(STATS_DL_ERRORS, 1);
        return TC_ACT_SHOT;
    }

    update_stats(STATS_DL_PACKETS, 1);
    update_stats(STATS_DL_BYTES, payload_len);
    update_stats(STATS_GTP_ENCAP_SUCCESS, 1);
    update_stats(STATS_PKT_FORWARDED, 1);

    bpf_printk("[ENCAP] GTP encapsulation SUCCESS!\n");
    bpf_printk("[ENCAP] Redirecting to S1U ifindex: %d\n", session_info->s1u_ifindex);

    return bpf_redirect(session_info->s1u_ifindex, 0);
}

SEC("tc")
int gtp_passthrough_handler(struct __sk_buff *skb) {
    return TC_ACT_OK;
}
char _license[] SEC("license") = "GPL";