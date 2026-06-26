#!/bin/bash
# Magma eBPF GTP-U datapath — INFRASTRUCTURE setup.
#
# Addresses Lucas Review #1: infrastructure (veth / eBPF load / TC attach / map pin /
# OVS port / static config) is declarative + persistent here, set up once by systemd
# (magma-ebpf-gtp.service) BEFORE the control plane. Per-UE sessions are NOT programmed
# here — that is the control plane's job (ebpf_session_adapter.py / sessiond hook).
#
# Idempotent: safe to re-run (clears prior clsact, re-attaches, --may-exist port).
set -uo pipefail

# Deployment config (S1U_IF, OVS_BR, UE_SUBNET, BPFTOOL) — written by install-ebpf.sh / ansible.
[ -r /etc/magma/ebpf.env ] && . /etc/magma/ebpf.env

EBPF_DIR=${EBPF_DIR:-/var/opt/magma/ebpf}
LOADER=${LOADER:-$EBPF_DIR/tc_loader}
S1U_IF=${S1U_IF:-eth1}            # N3 / S1-U interface the gNB/eNB sends GTP-U to
OVS_BR=${OVS_BR:-gtp_br0}
log(){ echo "[setup-ebpf-gtp] $*"; }

# 1. BPF filesystem (pinned maps live here)
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf

# 2. veth pair: gtp_veth0 (OVS side) <-> gtp_veth1 (eBPF encap side)
if ! ip link show gtp_veth0 >/dev/null 2>&1; then
    ip link add gtp_veth0 type veth peer name gtp_veth1
    log "created veth gtp_veth0<->gtp_veth1"
fi
ip link set gtp_veth0 up
ip link set gtp_veth1 up

# 3. clear any previous attach so re-runs are idempotent
for d in "$S1U_IF" gtp_veth0 gtp_veth1; do tc qdisc del dev "$d" clsact 2>/dev/null || true; done

# 4. attach the three TC programs (tc_loader pins LIBBPF_PIN_BY_NAME maps to /sys/fs/bpf)
"$LOADER" "$EBPF_DIR/gtp_decap.o" gtp_decap_handler      "$S1U_IF"  ingress
"$LOADER" "$EBPF_DIR/gtp_mark.o"  gtp_veth0_mark_handler gtp_veth0  ingress
"$LOADER" "$EBPF_DIR/gtp_encap.o" gtp_encap_handler      gtp_veth1  ingress
log "attached decap($S1U_IF) + mark(gtp_veth0) + encap(gtp_veth1)"

# 5. add gtp_veth0 as an OVS port (replaces the broken kernel gtp0 vport)
ovs-vsctl --may-exist add-port "$OVS_BR" gtp_veth0

# 6. static config_map (ifindexes resolved live — they change across reboots!).
#    SGI_IP = the S1-U source address used as the GTP-U outer src on downlink encap.
S1U_IDX=$(cat /sys/class/net/"$S1U_IF"/ifindex)
OVS_IDX=$(cat /sys/class/net/gtp_veth0/ifindex)
S1U_IP=$(ip -4 -o addr show "$S1U_IF" | awk '{print $4}' | cut -d/ -f1)
# Real L3 MTU of the S1-U egress link -> encap fail-loud guard (adapts to jumbo).
S1U_MTU=$(cat /sys/class/net/"$S1U_IF"/mtu 2>/dev/null || echo 1500)
EBPF_DIR="$EBPF_DIR" python3 - "$S1U_IDX" "$OVS_IDX" "$S1U_IP" "$S1U_MTU" <<'PY'
import sys, os
sys.path.insert(0, os.environ["EBPF_DIR"])
import ebpf_control as e
s1u, ovs, s1u_ip, mtu = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
e.populate_config(s1u_ifindex=s1u, sgi_ifindex=0, ovs_ifindex=ovs,
                  sgi_ip=s1u_ip, ebpf_veth_ifindex=ovs, debug_level=1, link_mtu=mtu)
print("[setup-ebpf-gtp] config_map: s1u_ifindex=%d ovs_ifindex=%d sgi_ip=%s link_mtu=%d"
      % (s1u, ovs, s1u_ip, mtu))
PY

# 7. control-plane-managed OVS flows (eBPF<->Magma bridge; QFI rides pkt_mark)
[ -x /usr/local/bin/install-ebpf-ovs-flows.sh ] && /usr/local/bin/install-ebpf-ovs-flows.sh || true

# 8. SGi egress for the UE subnet. Magma itself NATs via host iptables (POSTROUTING -o eth0
#    MASQUERADE), so this is consistent with Magma's design. Both eth0/eth1 since the UE route
#    may pick either (both on the access subnet). Per-UE static neigh is added by the adapter.
UE_SUBNET=${UE_SUBNET:-192.168.128.0/24}
sysctl -wq net.ipv4.ip_forward=1
for oif in eth0 eth1; do
    iptables -t nat -C POSTROUTING -s "$UE_SUBNET" -o "$oif" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s "$UE_SUBNET" -o "$oif" -j MASQUERADE
done
iptables -C FORWARD -s "$UE_SUBNET" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -s "$UE_SUBNET" -j ACCEPT
iptables -C FORWARD -d "$UE_SUBNET" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -d "$UE_SUBNET" -j ACCEPT

log "infrastructure READY (veth + 3 TC progs + pinned maps + OVS port + config_map + OVS flows + SGi NAT)"
