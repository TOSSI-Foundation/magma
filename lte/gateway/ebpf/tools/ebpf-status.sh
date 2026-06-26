#!/bin/bash
# ebpf-status.sh - read-only health/inspection dump for the Magma eBPF GTP-U datapath (magma#15649).
# Usage:  sudo ebpf-status.sh        (root: runs commands directly)
#         ./ebpf-status.sh           (non-root: prefixes privileged commands with sudo)
# Honors /etc/magma/ebpf.env (S1U_IF, OVS_BR, OVS_VETH).
set -uo pipefail
[ -r /etc/magma/ebpf.env ] && . /etc/magma/ebpf.env
BPF=/sys/fs/bpf
S1U=${S1U_IF:-eth1}; OVS_BR=${OVS_BR:-gtp_br0}; VETH=${OVS_VETH:-gtp_veth0}
SUDO=""; [ "$(id -u)" != 0 ] && SUDO="sudo"
sec(){ printf '\n========== %s ==========\n' "$*"; }
prog(){ $SUDO tc filter show dev "$1" ingress 2>/dev/null \
        | grep -oE 'gtp_[a-z0-9_]+:\[[0-9]+\].*tag [0-9a-f]+' | head -1; }

sec "SERVICES"
for s in magma-ebpf-gtp magma-ebpf-adapter; do
  printf '  %-22s %s\n' "$s" "$($SUDO systemctl is-active "$s.service" 2>/dev/null)"
done

sec "eBPF PROGRAMS (3 clsact-ingress TC programs)"
printf '  %-24s %s\n' "$S1U (decap / UL)"    "$(prog "$S1U")"
printf '  %-24s %s\n' "$VETH (mark)"          "$(prog "$VETH")"
printf '  %-24s %s\n' "gtp_veth1 (encap / DL)" "$(prog gtp_veth1)"

sec "PINNED MAPS"
for m in ue_session_map config_map stats_map; do
  [ -e "$BPF/$m" ] && echo "  $BPF/$m  (pinned)" || echo "  $BPF/$m  MISSING"
done

sec "config_map"
$SUDO bpftool map dump pinned "$BPF/config_map" 2>/dev/null | python3 -c '
import sys,json,ipaddress
N={0:"S1U_IFINDEX",1:"SGI_IFINDEX",2:"OVS_IFINDEX",3:"DEBUG_LEVEL",4:"SGI_IP",5:"VETH_IFINDEX",6:"LINK_MTU"}
try: d=json.load(sys.stdin)
except Exception: sys.exit()
def num(x): return int(list(x.values())[0]) if isinstance(x,dict) else int(x)
for e in d:
  k,v=num(e["key"]),num(e["value"])
  print("  %-13s = %s"%(N.get(k,"idx%d"%k), str(ipaddress.IPv4Address(v)) if k==4 and v else v))
' 2>/dev/null

sec "stats_map (nonzero counters)"
$SUDO bpftool map dump pinned "$BPF/stats_map" 2>/dev/null | python3 -c '
import sys,json
N={0:"UL_PKTS",1:"UL_BYTES",2:"DL_PKTS",3:"DL_BYTES",4:"UL_ERR",5:"DL_ERR",6:"SESSION_MISS",
   7:"TEID_MISMATCH",8:"GTP_DECAP_OK(UL)",9:"GTP_ENCAP_OK(DL)",10:"PKT_TOO_SHORT",12:"ADJUST_HEAD_FAIL",
   13:"TOTAL_PROCESSED",16:"PKT_FORWARDED",17:"PKT_DROPPED",22:"IP_OK",23:"UDP_OK",24:"GTP2152_HIT"}
try: d=json.load(sys.stdin)
except Exception: sys.exit()
def num(x): return int(list(x.values())[0]) if isinstance(x,dict) else int(x)
m={num(e["key"]):num(e["value"]) for e in d}
for k in sorted(m):
  if m[k]: print("  %-18s = %s"%(N.get(k,"idx%d"%k), m[k]))
' 2>/dev/null

sec "ue_session_map (active per-UE sessions: TEID/QFI + UL/DL counters)"
$SUDO bpftool map dump pinned "$BPF/ue_session_map" 2>/dev/null | python3 -c '
import sys,json,ipaddress
try: d=json.load(sys.stdin)
except Exception: sys.exit()
n=0
for e in d:
  v=e.get("value",{})
  if not isinstance(v,dict) or not v.get("session_flags"): continue
  kk=e["key"]; ip=int(kk.get("ue_ip") if isinstance(kk,dict) else kk)
  print("  UE %-15s qfi=%s  UL %s pkts/%s B   DL %s pkts/%s B"%(
        ipaddress.IPv4Address(ip), v.get("qfi"),
        v.get("ul_packets"), v.get("ul_bytes"), v.get("dl_packets"), v.get("dl_bytes")))
  n+=1
if not n: print("  (no active sessions)")
' 2>/dev/null

sec "OVS - adapter QFI classifier flows (cookie=0xeb): where UL/DL actually count"
$SUDO ovs-ofctl dump-flows "$OVS_BR" 2>/dev/null | grep "cookie=0xeb" \
  | sed -E 's/(duration|idle_age|table)=[^,]*,?//g' | sed 's/^/  /'

sec "OVS - PipelineD kernel-GTP session flows"
$SUDO ovs-ofctl dump-flows "$OVS_BR" 2>/dev/null | grep -E 'NXM_NX_TUN_ID|tun_id=0x.*qfi=' \
  | grep -oE 'n_packets=[0-9]+.*(tun_id=0x[0-9a-f]+|nw_dst=[0-9.]+)' | sed 's/^/  /'
echo "  NOTE: n_packets=0 here is EXPECTED - these target the old gtp0 vport / TUN_ID actions"
echo "        that eBPF replaced. The QFI/GTP work moved into eBPF (skb->mark <-> pkt_mark)."

sec "trace_pipe (bpf_printk, 3s snapshot - only emits if DEBUG_LEVEL>0)"
$SUDO timeout 3 cat /sys/kernel/debug/tracing/trace_pipe 2>/dev/null | sed 's/^/  /' | head -8
echo
echo "done."
