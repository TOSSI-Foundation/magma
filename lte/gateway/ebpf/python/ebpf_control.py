#!/usr/bin/env python3
"""
ebpf_control.py - control-plane primitives for the Magma eBPF GTP-U datapath.

Programs the PINNED maps created by the host loader (LIBBPF_PIN_BY_NAME), so this
works whether it runs standalone or inside the pipelined container (with /sys/fs/bpf
mounted). Uses bpftool for map I/O (swap for libbpf bindings later if desired).

CRITICAL byte-order/layout contract (must match lte/gateway/ebpf/bpf/*.c, derived
from the compiled BTF):
  * ue_session_key   = { __u32 ue_ip }  -> 4 bytes, HOST byte order (Decision #2).
    The datapath does bpf_ntohl(wire) before keying, so userspace packs the host
    integer little-endian ('<I') on x86. (Micky's stub used '!I' -> never matched.)
  * ue_session_info  = 160 bytes, field offsets below.
    - enb_ip, ifindexes, qos_mark, bearer_id, session_flags, metadata_mark: host
      order ('<I') - the handlers treat them as host integers.
    - teid_*: NETWORK order ('>I') - encap memcpy's teid_dl_out straight onto the
      wire, and decap compares against the wire TEID read as a big-endian field.
    - ul_mac_src/dst: raw 6 bytes. qfi: u8 @128.
  * config_map: key=config_key{__u32}, value=config_value{__u32}, both host order.
"""
import socket
import struct
import subprocess

BPF_DIR = "/sys/fs/bpf"
UE_SESSION_MAP = BPF_DIR + "/ue_session_map"
CONFIG_MAP = BPF_DIR + "/config_map"
STATS_MAP = BPF_DIR + "/stats_map"

# ue_session_info field byte offsets (size = 160).
SESSION_SIZE = 160
OFF = {
    "enb_ip": 0, "teid_ul_in": 4, "teid_ul_out": 8, "teid_dl_in": 12, "teid_dl_out": 16,
    "s1u_ifindex": 20, "sgi_ifindex": 24, "ovs_ifindex": 28,
    "ul_mac_src": 32, "ul_mac_dst": 38, "qos_mark": 44, "bearer_id": 48,
    "ul_bytes": 56, "dl_bytes": 64, "ul_packets": 72, "dl_packets": 80, "last_seen": 88,
    "session_flags": 96, "imsi": 100, "imsi_len": 116, "encoded_imsi": 120,
    "qfi": 128, "tunnel_id": 132, "tun_ipv4_dst": 136, "tun_flags": 140, "direction": 141,
    "original_port": 144, "reserved": 148, "metadata_mark": 152,
}
SESSION_FLAG_ACTIVE = 0x1

# config_map keys (mirror CONFIG_* in gtp_maps.h / the handlers).
CONFIG_S1U_IFINDEX = 0
CONFIG_SGI_IFINDEX = 1
CONFIG_OVS_IFINDEX = 2
CONFIG_DEBUG_LEVEL = 3
CONFIG_SGI_IP = 4
CONFIG_EBPF_VETH_IFINDEX = 5
CONFIG_LINK_MTU = 6  # L3 (IP-payload) MTU of the S1-U egress link (encap fail-loud guard)


def ip_to_host_int(ip):
    """Dotted IPv4 -> host integer (e.g. '10.0.0.1' -> 0x0A000001)."""
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def mac_to_bytes(mac):
    return bytes(int(b, 16) for b in mac.split(":"))


def _hex(b):
    return " ".join("0x%02x" % x for x in b)


def _run(args):
    r = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if r.returncode != 0:
        raise RuntimeError("cmd failed (%d): %s\n%s"
                           % (r.returncode, " ".join(args), r.stdout.decode(errors="replace")))
    return r.stdout.decode(errors="replace")


def _map_update(path, key, value):
    _run(["bpftool", "map", "update", "pinned", path]
         + ["key"] + _hex(key).split() + ["value"] + _hex(value).split())


def _map_delete(path, key):
    _run(["bpftool", "map", "delete", "pinned", path] + ["key"] + _hex(key).split())


def session_key(ue_ip):
    return struct.pack("<I", ip_to_host_int(ue_ip))


def pack_session(enb_ip, teid_ul_in, teid_dl_out, qfi=9,
                 ul_mac_src="00:00:00:00:00:00", ul_mac_dst="00:00:00:00:00:00",
                 s1u_ifindex=0, sgi_ifindex=0, ovs_ifindex=0,
                 teid_ul_out=0, teid_dl_in=0, qos_mark=0, bearer_id=5, active=True):
    buf = bytearray(SESSION_SIZE)
    struct.pack_into("<I", buf, OFF["enb_ip"], ip_to_host_int(enb_ip))      # host order
    struct.pack_into(">I", buf, OFF["teid_ul_in"], teid_ul_in & 0xFFFFFFFF)  # network order
    struct.pack_into(">I", buf, OFF["teid_ul_out"], teid_ul_out & 0xFFFFFFFF)
    struct.pack_into(">I", buf, OFF["teid_dl_in"], teid_dl_in & 0xFFFFFFFF)
    struct.pack_into(">I", buf, OFF["teid_dl_out"], teid_dl_out & 0xFFFFFFFF)
    struct.pack_into("<I", buf, OFF["s1u_ifindex"], s1u_ifindex)
    struct.pack_into("<I", buf, OFF["sgi_ifindex"], sgi_ifindex)
    struct.pack_into("<I", buf, OFF["ovs_ifindex"], ovs_ifindex)
    buf[OFF["ul_mac_src"]:OFF["ul_mac_src"] + 6] = mac_to_bytes(ul_mac_src)
    buf[OFF["ul_mac_dst"]:OFF["ul_mac_dst"] + 6] = mac_to_bytes(ul_mac_dst)
    struct.pack_into("<I", buf, OFF["qos_mark"], qos_mark)
    struct.pack_into("<I", buf, OFF["bearer_id"], bearer_id)
    struct.pack_into("<I", buf, OFF["session_flags"], SESSION_FLAG_ACTIVE if active else 0)
    buf[OFF["qfi"]] = qfi & 0x3F
    return bytes(buf)


def add_ue_session(ue_ip, enb_ip, teid_ul_in, teid_dl_out, qfi=9, **kw):
    """Program one UE session into the shared ue_session_map."""
    _map_update(UE_SESSION_MAP, session_key(ue_ip),
                pack_session(enb_ip, teid_ul_in, teid_dl_out, qfi=qfi, **kw))


def remove_ue_session(ue_ip):
    _map_delete(UE_SESSION_MAP, session_key(ue_ip))


def set_config(key_id, value):
    _map_update(CONFIG_MAP, struct.pack("<I", key_id), struct.pack("<I", value))


def populate_config(s1u_ifindex, sgi_ifindex, ovs_ifindex, sgi_ip, ebpf_veth_ifindex=0,
                    debug_level=1, link_mtu=1500):
    """Populate config_map. Setting SGI_IP here is the F5 root-cause fix (encap
    otherwise fails closed). link_mtu is the L3 (IP-payload) MTU of the S1-U egress
    link; the encap program drops any downlink whose outer frame would exceed it
    (fail-loud) instead of black-holing a >MTU DF frame on the wire. Pass the real
    egress MTU (cat /sys/class/net/<S1U_IF>/mtu) so this adapts to jumbo frames."""
    set_config(CONFIG_S1U_IFINDEX, s1u_ifindex)
    set_config(CONFIG_SGI_IFINDEX, sgi_ifindex)
    set_config(CONFIG_OVS_IFINDEX, ovs_ifindex)
    set_config(CONFIG_SGI_IP, ip_to_host_int(sgi_ip))
    set_config(CONFIG_EBPF_VETH_IFINDEX, ebpf_veth_ifindex)
    set_config(CONFIG_DEBUG_LEVEL, debug_level)
    set_config(CONFIG_LINK_MTU, link_mtu)


if __name__ == "__main__":
    # Self-test: program one session + config (maps must be pinned by the loader).
    add_ue_session("10.0.0.1", "192.168.4.71", teid_ul_in=100, teid_dl_out=200, qfi=9,
                   ul_mac_src="02:00:00:00:00:01", ul_mac_dst="02:00:00:00:00:02",
                   ovs_ifindex=2, s1u_ifindex=3)
    populate_config(s1u_ifindex=3, sgi_ifindex=4, ovs_ifindex=2, sgi_ip="192.168.4.70")
    print("programmed: session 10.0.0.1 (teid_ul_in=100 teid_dl_out=200 qfi=9) + config")
