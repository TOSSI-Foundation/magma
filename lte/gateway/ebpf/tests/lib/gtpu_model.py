"""
gtpu_model.py — pure-Python golden model for the Magma eBPF GTP-U datapath (Phase-2 tests).

No scapy / no root. Encodes the *intended* behaviour of bpf/gtp_decap.c, gtp_encap.c, gtp_mark.c
so tests fail when the implementation is wrong (not when it matches its current bugs). In particular
it pins the QFI position (PDU Session Container octet 3 = ext index 2 — the offset we fixed) and the
160-byte ue_session_info ABI + byte-order contract.
"""
import socket
import struct

# ---- 3GPP GTP-U constants (TS 29.281 / 38.415) ----
GTP_FLAGS_BASE = 0x30           # version 1 (0x20) | PT (0x10)
GTP_FLAG_E = 0x04               # extension-header flag
GTP_TYPE_TPDU = 0xFF
EXT_PDU_SESSION_CONTAINER = 0x85
PDU_TYPE_DL = 0x10              # DL PDU SESSION INFORMATION (PDU type 1 in high nibble)
PDU_TYPE_UL = 0x00
GTP_PORT = 2152
# The QFI lives at index 2 of the 4-byte PDU Session Container [len, pdu_type, QFI, next-ext].
QFI_EXT_OCTET = 2              # gtp_decap.c reads ext_hdr[2]; the bug read ext_hdr[1] (PDU type)


def host_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]


# ---------- packet builders / parsers ----------
def ipv4(src, dst, proto=1, payload=b"\x08\x00abcdefgh"):
    tot = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, tot, 0, 0x4000, 64, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + payload


def ipv4_src(pkt):
    return socket.inet_ntoa(pkt[12:16])


def ipv4_dst(pkt):
    return socket.inet_ntoa(pkt[16:20])


def build_pdu_session_container(qfi, pdu_type=PDU_TYPE_DL):
    """4-byte GTP extension header: [len=1][pdu_type][QFI][next-ext=0]. QFI at index 2."""
    if not 0 <= qfi <= 0x3F:
        raise ValueError("QFI out of range")
    return bytes([0x01, pdu_type, qfi & 0x3F, 0x00])


def build_gtpu(teid, qfi, inner, pdu_type=PDU_TYPE_DL):
    """A GTP-U T-PDU with a PDU Session Container carrying QFI, then the inner IP packet."""
    ext = build_pdu_session_container(qfi, pdu_type)
    opt = struct.pack(">HBB", 0, 0, EXT_PDU_SESSION_CONTAINER)   # seq, npdu, next-ext
    payload = opt + ext + inner
    hdr = struct.pack(">BBHI", GTP_FLAGS_BASE | GTP_FLAG_E, GTP_TYPE_TPDU, len(payload), teid)
    return hdr + payload


def parse_gtpu(pkt):
    """Decode a GTP-U T-PDU -> {teid, qfi, inner}. QFI read from PDU-container octet index 2."""
    flags, typ, length, teid = struct.unpack(">BBHI", pkt[:8])
    off = 8
    qfi = None
    if flags & GTP_FLAG_E:
        next_ext = pkt[off + 3]          # next-ext field of the optional header
        off += 4
        while next_ext != 0x00 and off < len(pkt):
            total = pkt[off] * 4         # ext length is in 4-octet units
            block = pkt[off:off + total]
            if next_ext == EXT_PDU_SESSION_CONTAINER:
                qfi = block[QFI_EXT_OCTET] & 0x3F
            next_ext = block[total - 1]
            off += total
    return {"flags": flags, "type": typ, "teid": teid, "qfi": qfi, "inner": pkt[off:]}


# ---------- golden datapath functions ----------
def golden_decap(gtpu_pkt):
    """Uplink: strip GTP-U -> (inner_ip_bytes, qfi). Mirrors gtp_decap.c's intent."""
    p = parse_gtpu(gtpu_pkt)
    if p["type"] != GTP_TYPE_TPDU:
        raise ValueError("not a T-PDU")
    return p["inner"], p["qfi"]


def golden_encap(inner_ip, teid_dl_out, qfi, pdu_type=PDU_TYPE_DL):
    """Downlink: wrap inner IP in GTP-U with the DL TEID + QFI. Mirrors gtp_encap.c's intent."""
    return build_gtpu(teid_dl_out, qfi, inner_ip, pdu_type)


# ---------- ue_session_info ABI (must match bpf/gtp_maps.h + python/ebpf_control.py) ----------
SESSION_SIZE = 160
SESSION_OFF = {
    "enb_ip": 0, "teid_ul_in": 4, "teid_ul_out": 8, "teid_dl_in": 12, "teid_dl_out": 16,
    "s1u_ifindex": 20, "sgi_ifindex": 24, "ovs_ifindex": 28, "ul_mac_src": 32, "ul_mac_dst": 38,
    "qos_mark": 44, "bearer_id": 48, "session_flags": 96, "qfi": 128, "metadata_mark": 152,
}
SESSION_FLAG_ACTIVE = 0x1


def session_key(ue_ip):
    """UE-IP key in HOST byte order (decap calls bpf_ntohl before lookup)."""
    return struct.pack("<I", host_int(ue_ip))


def pack_session(enb_ip, teid_ul_in, teid_dl_out, qfi=9, active=True):
    """Pack the 160-byte value; teids NETWORK order, enb_ip/ifindex HOST order, qfi @128."""
    buf = bytearray(SESSION_SIZE)
    struct.pack_into("<I", buf, SESSION_OFF["enb_ip"], host_int(enb_ip))
    struct.pack_into(">I", buf, SESSION_OFF["teid_ul_in"], teid_ul_in & 0xFFFFFFFF)
    struct.pack_into(">I", buf, SESSION_OFF["teid_dl_out"], teid_dl_out & 0xFFFFFFFF)
    struct.pack_into("<I", buf, SESSION_OFF["session_flags"], SESSION_FLAG_ACTIVE if active else 0)
    buf[SESSION_OFF["qfi"]] = qfi & 0x3F
    return bytes(buf)


# ---------- decision-table oracle (Lucas R3 Step 6) ----------
# Mirrors the handlers' pass/drop/redirect decision so tests are table-driven over all paths.
ACT_OK = "TC_ACT_OK"            # passthrough (not our packet, or benign)
ACT_SHOT = "TC_ACT_SHOT"        # drop
ACT_REDIRECT = "REDIRECT"       # decap->gtp_veth0 / encap->eth1


def golden_action(hook, pkt, session, config):
    """
    hook: 'decap' (eth1 ingress) | 'encap' (gtp_veth1 ingress)
    pkt:  {'l3','l4','udp_dst','teid','qfi','inner_src','inner_dst'}
    session: dict keyed by UE-IP -> {'active','teid_dl_out'} (or {} for none)
    config:  {'sgi_ip'}
    returns (action, mark)  where mark is the QFI stamped into skb->mark (decap) or None
    """
    if pkt.get("l3") != "ipv4":
        return ACT_OK, None
    if hook == "decap":
        if pkt.get("l4") != "udp":
            return ACT_OK, None                         # SCTP/etc pass — control plane safe
        if pkt.get("udp_dst") != GTP_PORT:
            return ACT_OK, None
        s = session.get(pkt.get("inner_src"))
        if not s:
            return ACT_SHOT, None                       # session miss
        if not s.get("active"):
            return ACT_SHOT, None
        return ACT_REDIRECT, pkt.get("qfi")             # mark = QFI from wire
    elif hook == "encap":
        s = session.get(pkt.get("inner_dst"))
        if not s:
            return ACT_SHOT, None                       # unknown UE
        if not s.get("teid_dl_out"):
            return ACT_SHOT, None
        if not config.get("sgi_ip"):
            return ACT_SHOT, None                       # Finding 5: fail closed
        return ACT_REDIRECT, None
    raise ValueError("unknown hook")
