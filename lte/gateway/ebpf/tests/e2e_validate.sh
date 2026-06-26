#!/bin/bash
# =============================================================================
# e2e_validate.sh — ONE end-to-end validation of the Magma eBPF GTP-U datapath.
#
# Run ON the AGW after `install-ebpf.sh` and with a gNB/UE simulator reachable. It asserts the
# whole stack in one shot — infra (services/attach/maps/OVS), control plane (NGAP + auto-programmed
# session), data plane (drives a UE ping, checks decap/encap counters + the on-wire QFI), and the
# Phase-2 unit/loader suites — then prints PASS/FAIL and exits non-zero on any failure.
#
#   sudo ./e2e_validate.sh [SIM_SSH] [UE_IFACE] [PING_TARGET]
#     SIM_SSH      ssh target of the simulator VM   (default: ubuntu@192.168.4.13)
#     UE_IFACE     UE tun iface on the sim          (default: oaitun_ue1)
#     PING_TARGET  what the UE pings via the AGW    (default: 192.168.128.1 = gtp_br0 gw)
# =============================================================================
set -uo pipefail
[ -r /etc/magma/ebpf.env ] && . /etc/magma/ebpf.env
S1U_IF="${S1U_IF:-eth1}"; OVS_BR="${OVS_BR:-gtp_br0}"; OVS_VETH="${OVS_VETH:-gtp_veth0}"
BT="${BPFTOOL:-bpftool}"
SIM_SSH="${1:-ubuntu@192.168.4.13}"; UE_IFACE="${2:-oaitun_ue1}"; PING_TARGET="${3:-192.168.128.1}"
# Run the sim-ssh as the invoking user (the script itself runs under sudo for tc/bpftool, but the
# ssh key + known_hosts live with the normal user, not root).
SIM_USER="${SUDO_USER:-ubuntu}"
SSH="sudo -u $SIM_USER ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10"
S1U_IP="$(ip -4 -o addr show "$S1U_IF" 2>/dev/null | awk '{print $4}' | cut -d/ -f1)"
# QFI is dynamic (assigned by NMS/policy; read off Magma's per-session gtp_br0 flow). Derive it so
# the QFI checks assert the *real* value rather than a hardcoded one. Fall back to 0x9 if no session.
LIVE_QFI="$(sudo ovs-ofctl dump-flows "$OVS_BR" 2>/dev/null | grep -oE 'load:0x[0-9a-f]+->NXM_NX_QFI' | head -1 | grep -oE '0x[0-9a-f]+')"
LIVE_QFI="${LIVE_QFI:-0x9}"
PASS=0; FAIL=0
ok(){   echo "  PASS  $1"; PASS=$((PASS+1)); }
no(){   echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
chk(){ if eval "$2" >/dev/null 2>&1; then ok "$1"; else no "$1"; fi; }     # chk "name" 'test-cmd'

dump_ue(){ sudo "$BT" map dump pinned /sys/fs/bpf/ue_session_map 2>/dev/null; }
ul_pkts(){ dump_ue | grep -oE '"ul_packets": [0-9]+' | grep -oE '[0-9]+' | awk '{s+=$1} END{print s+0}'; }
dl_pkts(){ dump_ue | grep -oE '"dl_packets": [0-9]+' | grep -oE '[0-9]+' | awk '{s+=$1} END{print s+0}'; }
qfi_hits(){ sudo ovs-ofctl dump-flows "$OVS_BR" 2>/dev/null | grep "pkt_mark=$LIVE_QFI" | grep -oE 'n_packets=[0-9]+' | grep -oE '[0-9]+' | awk '{s+=$1} END{print s+0}'; }

echo "== eBPF GTP-U E2E validation =="
echo "   S1U=$S1U_IF($S1U_IP) bridge=$OVS_BR veth=$OVS_VETH sim=$SIM_SSH ue_if=$UE_IFACE target=$PING_TARGET"

echo "-- [A] infrastructure --"
chk "services active (gtp + adapter)" '[ "$(systemctl is-active magma-ebpf-gtp)" = active ] && [ "$(systemctl is-active magma-ebpf-adapter)" = active ]'
chk "decap attached on $S1U_IF"   "sudo tc filter show dev $S1U_IF ingress | grep -q bpf"
chk "mark attached on $OVS_VETH"  "sudo tc filter show dev $OVS_VETH ingress | grep -q bpf"
chk "encap attached on gtp_veth1" "sudo tc filter show dev gtp_veth1 ingress | grep -q bpf"
chk "3 maps pinned" '[ "$(ls /sys/fs/bpf | grep -cE "ue_session_map|config_map|stats_map")" -ge 3 ]'
chk "config_map populated"        "[ \"\$(sudo $BT map dump pinned /sys/fs/bpf/config_map | grep -c key)\" -ge 4 ]"
chk "$OVS_VETH is an OVS port"    "sudo ovs-vsctl port-to-br $OVS_VETH"
chk "kernel gtp0 vport removed"  "! sudo ovs-vsctl port-to-br gtp0"
chk "managed OVS flows present"  "sudo ovs-ofctl dump-flows $OVS_BR | grep -q 0xeb9f"
chk "QFI pkt_mark flow installed (QFI=$LIVE_QFI)" "sudo ovs-ofctl dump-flows $OVS_BR | grep -q \"pkt_mark=$LIVE_QFI\""
chk "NGAP (SCTP 38412) listening" "sudo ss -lan | grep -q 38412"

echo "-- [B] control + data plane (drives UE traffic) --"
chk "auto-programmed UE session present" '[ "$(dump_ue | grep -c session_flags)" -ge 1 ]'
UL0=$(ul_pkts); DL0=$(dl_pkts); Q0=$(qfi_hits)
echo "   driving ping from $SIM_SSH ($UE_IFACE -> $PING_TARGET) ..."
PINGOUT="$($SSH "$SIM_SSH" "sudo ping -c 20 -i 0.2 -W 1 -I $UE_IFACE $PING_TARGET" 2>&1 | tail -3)"
echo "$PINGOUT" | sed 's/^/     /'
sleep 2; UL1=$(ul_pkts); DL1=$(dl_pkts); Q1=$(qfi_hits)
chk "uplink decap counter advanced ($UL0->$UL1)"  "[ ${UL1:-0} -gt ${UL0:-0} ]"
chk "downlink encap counter advanced ($DL0->$DL1)" "[ ${DL1:-0} -gt ${DL0:-0} ]"
chk "OVS classified on eBPF QFI=$LIVE_QFI ($Q0->$Q1)" "[ ${Q1:-0} -gt ${Q0:-0} ]"
chk "ping 0% packet loss"  "echo \"\$PINGOUT\" | grep -q ' 0% packet loss'"
# on-wire proof: capture a downlink GTP-U *while* driving fresh traffic, then check the packet
# carries the PDU Session Container (next-ext 0x85, len 01, DL-type 10, QFI).
( $SSH "$SIM_SSH" "sudo timeout 9 ping -i 0.2 -W1 -I $UE_IFACE $PING_TARGET" >/dev/null 2>&1 & )
sleep 1
FILT="udp port 2152 and src host $S1U_IP"
WIRE="$(sudo timeout 7 tcpdump -i "$S1U_IF" -nxc1 "$FILT" 2>/dev/null | tr -d ' \n')"
chk "downlink GTP-U has PDU Session Container + QFI (0x85 0110 ..)" "echo \"$WIRE\" | grep -qiE '850110'"

echo "-- [C] Phase-2 suites --"
HERE="$(cd "$(dirname "$0")" && pwd)"
chk "protocol suite (10/10)" "python3 $HERE/test_phase2_protocol.py | tail -1 | grep -q '10/10 passed'"
chk "shared-map suite (on AGW)" "BPFTOOL=$BT sudo -E python3 $HERE/test_phase2_loader.py | tail -1 | grep -qE '4 passed'"

echo
echo "================  RESULT: $PASS passed, $FAIL failed  ================"
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
