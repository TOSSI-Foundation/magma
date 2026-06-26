/*
 * gtp_maps.h - Shared libbpf map/struct/constant definitions for the Magma
 * eBPF GTP-U datapath. Single source of truth for gtp_decap.c, gtp_encap.c
 * and gtp_mark.c.
 *
 * The three TC programs are compiled into separate objects and loaded onto
 * different interfaces, but they MUST share one ue_session_map / config_map /
 * stats_map instance. That is achieved with LIBBPF_PIN_BY_NAME: the loader sets
 * a common pin_root_path (e.g. /sys/fs/bpf/magma_gtp) and libbpf reuses the
 * already-pinned map across objects. For that reuse to be valid every object
 * must declare identical map definitions -- hence this shared header.
 *
 * Byte-order convention (Decision #2, 2026-06-18): the UE-IP session-map key is
 * stored in HOST byte order. Datapath programs MUST bpf_ntohl() the on-wire
 * address before keying, and the userspace populator MUST pack host order.
 */
#ifndef _GTP_MAPS_H
#define _GTP_MAPS_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ---- Fallbacks (normally provided by the uapi headers above) ---- */
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

/* ---- GTP-U protocol constants (3GPP TS 29.281) ---- */
#define GTP_PORT_NO 2152
#define GTP_HDR_SIZE_MIN 8
#define GTP_VERSION_1 0x01
#define GTP_PT_FLAG 0x01
#define GTP_MSG_TPDU 0xFF
#define GTP_FLAG_VERSION_MASK 0xE0
#define GTP_FLAG_PT 0x10
#define GTP_FLAG_E 0x04
#define GTP_FLAG_S 0x02
#define GTP_FLAG_PN 0x01

struct gtp1_header {
    __u8 flags;
    __u8 type;
    __be16 length;
    __be32 teid;
} __attribute__((packed));

/* ---- Session map ABI ---- */
struct ue_session_key {
    __u32 ue_ip;            /* UE IPv4 address, HOST byte order (Decision #2) */
};

struct ue_session_info {
    __be32 enb_ip;
    __u32 teid_ul_in;       /* TEID for uplink (eNB->UE) */
    __u32 teid_ul_out;      /* TEID for uplink response */
    __u32 teid_dl_in;       /* TEID for downlink (UE->eNB) */
    __u32 teid_dl_out;      /* TEID for downlink response */
    __u32 s1u_ifindex;
    __u32 sgi_ifindex;
    __u32 ovs_ifindex;
    __u8 ul_mac_src[ETH_ALEN];
    __u8 ul_mac_dst[ETH_ALEN];
    __u32 qos_mark;
    __u32 bearer_id;
    __u64 ul_bytes;
    __u64 dl_bytes;
    __u64 ul_packets;
    __u64 dl_packets;
    __u64 last_seen;
    __u32 session_flags;    /* bit 0 = active */
    __u8 imsi[16];
    __u32 imsi_len;
    __u64 encoded_imsi;
    __u8 qfi;               /* QoS Flow Identifier (5G) */
    __u32 tunnel_id;
    __be32 tun_ipv4_dst;
    __u8 tun_flags;
    __u8 direction;
    __u32 original_port;
    __u8 reserved[3];
    __u32 metadata_mark;    /* mark stashed by decap, restored on gtp_veth0 ingress */
};

/* ---- Config map ABI ---- */
struct config_key {
    __u32 key;
};
struct config_value {
    __u32 value;
};

/* ---- Maps (pinned by name -> shared across the three TC objects) ---- */
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

/* ---- Statistics counter indices (unified across all handlers) ---- */
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
#define STATS_NON_IPV4_SKIPPED 22       /* F3: non-IPv4 passthrough, not a drop */
/* gtp_veth0 mark-restore handler counters */
#define STATS_VETH0_PACKETS_PROCESSED 50
#define STATS_VETH0_MARK_RESTORED 51
#define STATS_VETH0_MARK_FALLBACK 52
#define STATS_VETH0_SESSION_MISS 53
#define STATS_MAX_COUNTERS 64

/* ---- Config map keys ---- */
#define CONFIG_S1U_IFINDEX 0
#define CONFIG_SGI_IFINDEX 1
#define CONFIG_OVS_IFINDEX 2
#define CONFIG_DEBUG_LEVEL 3
#define CONFIG_SGI_IP 4
#define CONFIG_EBPF_VETH_IFINDEX 5
#define CONFIG_LINK_MTU 6       /* L3 (IP-payload) MTU of the S1-U egress link */

/* ---- Shared inline helpers ---- */
static __always_inline void update_stats(__u32 counter_id, __u64 value) {
    __u64 *count = bpf_map_lookup_elem(&stats_map, &counter_id);
    if (count)
        *count += value;
}

/* One's-complement IPv4 header checksum over a 20-byte header. */
static __always_inline __attribute__((unused)) __u16 ip_checksum(__u8 *data, int len) {
    __u32 sum = 0;

#pragma unroll
    for (int i = 0; i < 10; i++) {
        if (i * 2 < len)
            sum += ((__u16)data[i * 2] << 8) | (__u16)data[i * 2 + 1];
    }

#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

#endif /* _GTP_MAPS_H */
