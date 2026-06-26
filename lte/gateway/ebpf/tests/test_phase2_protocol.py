#!/usr/bin/env python3
"""
Phase-2 protocol / golden / decision-table tests (Lucas R3 Step 6).

Pure-Python, no root, no scapy — runnable anywhere with `pytest` OR `python3 test_phase2_protocol.py`.
Validates the *intended* GTP-U behaviour of the eBPF handlers: the QFI position (the offset bug we
fixed), the GTP-U encode/decode roundtrip, the 160-byte session ABI + byte-order contract, and the
full pass/drop/redirect decision table for decap and encap.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import gtpu_model as g  # noqa: E402

UE = "192.168.128.12"
GNB = "192.168.4.13"
UL_TEID = 0x7FFFFFFF
DL_TEID = 0xBB036220
QFI = 9


# ---------- GTP-U encode/decode + the QFI offset ----------
def test_gtpu_roundtrip():
    inner = g.ipv4(UE, "8.8.8.8")
    pkt = g.build_gtpu(UL_TEID, QFI, inner, pdu_type=g.PDU_TYPE_UL)
    p = g.parse_gtpu(pkt)
    assert p["teid"] == UL_TEID
    assert p["qfi"] == QFI
    assert p["inner"] == inner


def test_qfi_is_at_container_octet_3():
    """Regression for the ext_hdr[2] fix: QFI is octet index 2; index 1 is the PDU type (0x10)."""
    container = g.build_pdu_session_container(QFI, pdu_type=g.PDU_TYPE_DL)
    assert container == bytes([0x01, 0x10, 0x09, 0x00])
    assert container[g.QFI_EXT_OCTET] & 0x3F == QFI        # correct read (the fix)
    assert container[1] & 0x3F != QFI                      # the buggy read would get 0x10, not 9
    assert container[1] == g.PDU_TYPE_DL


def test_decap_extracts_inner_and_qfi():
    inner = g.ipv4(UE, "8.8.8.8")
    out_inner, out_qfi = g.golden_decap(g.build_gtpu(UL_TEID, QFI, inner, g.PDU_TYPE_UL))
    assert out_inner == inner and out_qfi == QFI
    assert g.ipv4_src(out_inner) == UE                     # decap keys session on inner src


def test_encap_builds_correct_gtpu():
    inner = g.ipv4("8.8.8.8", UE)                          # downlink reply
    pkt = g.golden_encap(inner, DL_TEID, QFI, g.PDU_TYPE_DL)
    p = g.parse_gtpu(pkt)
    assert p["teid"] == DL_TEID                            # DL TEID on the wire
    assert p["qfi"] == QFI
    assert g.ipv4_dst(p["inner"]) == UE                    # encap keys session on inner dst


def test_encap_teid_is_network_order_on_wire():
    pkt = g.golden_encap(g.ipv4("8.8.8.8", UE), DL_TEID, QFI)
    assert pkt[4:8] == bytes([0xBB, 0x03, 0x62, 0x20])     # 0xBB036220 big-endian


# ---------- session table ABI / byte-order contract ----------
def test_session_abi_layout():
    assert g.SESSION_SIZE == 160
    assert g.SESSION_OFF["qfi"] == 128
    assert g.SESSION_OFF["teid_dl_out"] == 16
    assert g.SESSION_OFF["enb_ip"] == 0


def test_session_key_is_host_order():
    # 192.168.128.12 -> 0xC0A8800C ; host (little-endian) bytes = 0c 80 a8 c0
    assert g.session_key(UE) == bytes([0x0C, 0x80, 0xA8, 0xC0])


def test_pack_session_fields():
    v = g.pack_session(GNB, UL_TEID, DL_TEID, qfi=QFI, active=True)
    assert len(v) == 160
    assert v[g.SESSION_OFF["qfi"]] == QFI
    assert v[16:20] == bytes([0xBB, 0x03, 0x62, 0x20])     # teid_dl_out network order
    assert struct.unpack("<I", v[0:4])[0] == g.host_int(GNB)   # enb_ip host order
    assert struct.unpack("<I", v[96:100])[0] == g.SESSION_FLAG_ACTIVE


# ---------- decision-table oracle ----------
def _sess(active=True, teid_dl_out=DL_TEID):
    return {UE: {"active": active, "teid_dl_out": teid_dl_out}}


def test_decap_decision_table():
    cfg = {"sgi_ip": g.host_int("192.168.4.71")}
    base = {"l3": "ipv4", "l4": "udp", "udp_dst": 2152, "teid": UL_TEID, "qfi": QFI, "inner_src": UE}
    cases = [
        ({**base},                                    g.ACT_REDIRECT, QFI),   # happy path -> mark=QFI
        ({**base, "l3": "arp"},                        g.ACT_OK,       None),  # non-IPv4 pass
        ({**base, "l4": "sctp"},                       g.ACT_OK,       None),  # SCTP (NGAP) pass!
        ({**base, "udp_dst": 53},                      g.ACT_OK,       None),  # non-2152 pass
        ({**base, "inner_src": "10.9.9.9"},            g.ACT_SHOT,     None),  # session miss
    ]
    for pkt, exp_act, exp_mark in cases:
        act, mark = g.golden_action("decap", pkt, _sess(), cfg)
        assert (act, mark) == (exp_act, exp_mark), (pkt, act, mark)
    # inactive session drops
    act, _ = g.golden_action("decap", base, _sess(active=False), cfg)
    assert act == g.ACT_SHOT


def test_encap_decision_table():
    cfg_ok = {"sgi_ip": g.host_int("192.168.4.71")}
    base = {"l3": "ipv4", "inner_dst": UE}
    assert g.golden_action("encap", base, _sess(), cfg_ok)[0] == g.ACT_REDIRECT
    assert g.golden_action("encap", {**base, "inner_dst": "10.9.9.9"}, _sess(), cfg_ok)[0] == g.ACT_SHOT
    assert g.golden_action("encap", base, _sess(teid_dl_out=0), cfg_ok)[0] == g.ACT_SHOT
    assert g.golden_action("encap", base, _sess(), {"sgi_ip": 0})[0] == g.ACT_SHOT   # Finding 5 fail-closed
    assert g.golden_action("encap", {**base, "l3": "arp"}, _sess(), cfg_ok)[0] == g.ACT_OK


if __name__ == "__main__":
    fns = sorted(n for n in dir() if n.startswith("test_"))
    npass = 0
    for n in fns:
        try:
            globals()[n]()
            print("PASS %s" % n)
            npass += 1
        except AssertionError as e:
            print("FAIL %s : %s" % (n, e))
        except Exception as e:
            print("ERROR %s : %r" % (n, e))
    print("\n%d/%d passed" % (npass, len(fns)))
    sys.exit(0 if npass == len(fns) else 1)
