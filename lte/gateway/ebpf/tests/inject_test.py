#!/usr/bin/env python3
"""
inject_test.py - end-to-end smoke test for the eBPF GTP-U decap datapath.

Programs a UE session + config via ebpf_control, then crafts and injects a real
GTP-U T-PDU (with a 5G PDU Session Container carrying a QFI) so it lands on the TC
ingress hook where gtp_decap is attached. Verify afterwards via stats_map counters
and the bpf_printk trace.

Usage: sudo python3 inject_test.py <tx_iface> <ovs_ifindex> [count]
  tx_iface    : veth end to TX on (its peer has gtp_decap on TC ingress)
  ovs_ifindex : ifindex decap should redirect the decapped packet to
"""
import socket
import struct
import sys

sys.path.insert(0, "/home/ubuntu")
import ebpf_control as ec  # noqa: E402

UE_IP = "10.0.0.1"
TEID = 100
QFI = 5


def inet(a):
    return socket.inet_aton(a)


def macb(s):
    return bytes.fromhex(s.replace(":", ""))


def build_gtpu(ue_ip=UE_IP, dst_ip="8.8.8.8", enb="192.168.4.71", sgi="192.168.4.70",
               teid=TEID, qfi=QFI):
    # inner IP packet (UE -> internet)
    inner_payload = b"\xde\xad\xbe\xef" * 2
    inner = bytearray(20)
    inner[0] = 0x45
    struct.pack_into("!H", inner, 2, 20 + len(inner_payload))
    inner[8] = 64          # ttl
    inner[9] = 17          # proto (udp; not validated by decap)
    inner[12:16] = inet(ue_ip)
    inner[16:20] = inet(dst_ip)
    inner = bytes(inner) + inner_payload

    # GTP-U: flags=0x34 (ver1|PT|E), type=0xFF (T-PDU)
    opt = bytes([0x00, 0x00, 0x00, 0x85])           # seq, npdu, next_ext = PDU Session Container
    # PDU Session Container (3GPP TS 38.415): Length=1, PDU-type octet (0x10=UL), QFI octet, NextExtType=0
    extn = bytes([0x01, 0x10, qfi & 0x3F, 0x00])
    gtp = bytes([0x34, 0xFF]) + struct.pack("!H", 4 + 4 + len(inner)) + struct.pack("!I", teid)
    udp_payload = gtp + opt + extn + inner

    udp = struct.pack("!HHHH", 2152, 2152, 8 + len(udp_payload), 0)
    oip = bytearray(20)
    oip[0] = 0x45
    struct.pack_into("!H", oip, 2, 20 + 8 + len(udp_payload))
    oip[8] = 64
    oip[9] = 17            # udp
    oip[12:16] = inet(enb)
    oip[16:20] = inet(sgi)
    eth = macb("02:00:00:00:00:bb") + macb("02:00:00:00:00:aa") + struct.pack("!H", 0x0800)
    return eth + bytes(oip) + udp + udp_payload


def main():
    tx_if = sys.argv[1]
    ovs_ifindex = int(sys.argv[2])
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 3

    ec.add_ue_session(UE_IP, "192.168.4.71", teid_ul_in=TEID, teid_dl_out=200, qfi=9,
                      ul_mac_src="02:00:00:00:00:01", ul_mac_dst="02:00:00:00:00:02",
                      ovs_ifindex=ovs_ifindex)
    ec.populate_config(s1u_ifindex=0, sgi_ifindex=0, ovs_ifindex=ovs_ifindex, sgi_ip="192.168.4.70")

    frame = build_gtpu()
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((tx_if, 0))
    for _ in range(n):
        s.send(frame)
    print("injected %d GTP-U frame(s) of %d bytes on %s (UE=%s TEID=%d QFI=%d -> redirect ifindex %d)"
          % (n, len(frame), tx_if, UE_IP, TEID, QFI, ovs_ifindex))


main()
