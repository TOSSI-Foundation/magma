#!/bin/bash
# Phase 2: control-plane-managed OVS flows bridging the eBPF datapath into Magma's gtp_br0.
#
# Jordan's requirement is "OVS keeps flow management; QFI handling migrates from OVS into
# eBPF." This installer demonstrates exactly that:
#   - eBPF decap reads the QFI off the PDU Session Container and stamps skb->mark (the mark
#     handler restores it on gtp_veth0 ingress). OVS then sees it as pkt_mark.
#   - The session adapter installs one pkt_mark=<QFI> classifier flow per *live* QFI (dynamic,
#     using the value NMS/policy assigned), so OVS does flow management using the eBPF-provided
#     QFI. QFI extraction is no longer OVS's job, and no QFI value is hardcoded here.
#
# SGi NAT note: Magma itself NATs via host iptables (POSTROUTING -o eth0 MASQUERADE) and
# uplink_br0 has no NAT flows, so handing UE uplink to the host for routing/NAT is consistent
# with Magma's own design, not a shortcut.
#
# Resolves the gtp_veth0 OF port dynamically (it changes whenever the port is re-added), so
# this survives infra re-setup — unlike hand-typed in_port numbers. Idempotent (cookie-tagged).
set -uo pipefail
[ -r /etc/magma/ebpf.env ] && . /etc/magma/ebpf.env
OVS_BR=${OVS_BR:-gtp_br0}
UE_SUBNET=${UE_SUBNET:-192.168.128.0/24}
COOKIE=0xeb9f                     # tag for our boot-time managed flows (per-QFI flows: 0xeb90)

PORT=$(ovs-ofctl show "$OVS_BR" | sed -n 's/^ *\([0-9]\+\)(gtp_veth0).*/\1/p')
[ -z "$PORT" ] && { echo "[ovs-flows] ERROR: gtp_veth0 is not a port on $OVS_BR" >&2; exit 1; }
BRMAC=$(cat /sys/class/net/"$OVS_BR"/address)
echo "[ovs-flows] gtp_veth0 OF port=$PORT  ${OVS_BR}_mac=$BRMAC"

# Remove ONLY our own managed flows (cookie-tagged). Do NOT match by in_port/nw_dst —
# that would also delete Magma's per-session gtp0 flows (same match fields, different
# priority), which the adapter reads as its source of truth.
ovs-ofctl del-flows "$OVS_BR" "cookie=$COOKIE/-1" 2>/dev/null || true

# UPLINK: decapped UE traffic -> Magma SGi (host route/NAT). QFI-agnostic forwarding flow — carries
# traffic for ANY QFI. The per-QFI classifier flows (pkt_mark=<QFI>) that prove OVS keys on the
# eBPF-set mark are installed DYNAMICALLY by the session adapter, one per live QFI (cookie 0xeb90),
# so nothing here is tied to a specific QFI value.
ovs-ofctl add-flow "$OVS_BR" "cookie=$COOKIE,priority=65534,in_port=$PORT,ip,actions=mod_dl_dst:$BRMAC,LOCAL"

# DOWNLINK: anything destined to the UE subnet -> eBPF encap via gtp_veth0 (encap looks up the
# per-UE session for TEID/QFI). One flow covers all UEs.
ovs-ofctl add-flow "$OVS_BR" "cookie=$COOKIE,priority=65535,in_port=LOCAL,ip,nw_dst=$UE_SUBNET,actions=output:$PORT"

echo "[ovs-flows] installed UL(QFI-agnostic forward) + DL($UE_SUBNET) on $OVS_BR; per-QFI classifiers are adapter-managed"
