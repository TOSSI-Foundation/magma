#!/bin/bash
# Magma eBPF GTP-U datapath — infrastructure teardown (ExecStop for magma-ebpf-gtp.service).
# Removes the datapath but leaves pinned maps by default (control plane may still hold them).
set -uo pipefail
OVS_BR=${OVS_BR:-gtp_br0}
S1U_IF=${S1U_IF:-eth1}

ovs-vsctl --if-exists del-port "$OVS_BR" gtp_veth0 || true
for d in "$S1U_IF" gtp_veth0 gtp_veth1; do tc qdisc del dev "$d" clsact 2>/dev/null || true; done
ip link del gtp_veth0 2>/dev/null || true   # deletes the peer too

# Pinned maps are intentionally NOT removed (uncomment to fully reset):
# rm -f /sys/fs/bpf/ue_session_map /sys/fs/bpf/config_map /sys/fs/bpf/stats_map

echo "[teardown-ebpf-gtp] datapath removed (pinned maps left in place)"
