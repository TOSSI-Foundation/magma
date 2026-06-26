#!/usr/bin/env python3
"""
ebpf_session_adapter.py — control-plane adapter that auto-programs the eBPF GTP-U datapath.

(Lucas Review #3, Step 7: a *thin adapter* that bridges Magma's existing per-session flow
programming to the eBPF maps, instead of modifying pipelined or hand-populating maps.)

Magma's pipelined installs per-PDU-session GTP flows on gtp_br0:
  DL:  ip,in_port=LOCAL,nw_dst=<UE_IP> actions=load:0x<DL_TEID>->NXM_NX_TUN_ID,
                                               load:0x<gNB_IP>->NXM_NX_TUN_IPV4_DST,
                                               load:0x<QFI>->NXM_NX_QFI, ...
  UL:  tun_id=0x<UL_TEID>,qfi=<QFI>,in_port=<gtp0> ...
This daemon watches those flows and programs ue_session_map via ebpf_control — automatically,
as UEs attach/detach. It is *event-driven*: a one-shot initial sync catches sessions already
present, then `ovs-ofctl monitor` streams flow changes and each change triggers an idempotent,
change-only reconcile (debounced to coalesce a burst); a slow periodic re-sync is a safety
backstop, and it falls back to polling if flow monitoring is unavailable. All of it runs
host-side — pipelined and the Magma container images are untouched (no image rebuild).
It resolves the correct egress interface and L2 next-hop toward each gNB (on-link gNB/simulator
OR a gNB reached via a router), so NO per-deployment tuning is needed for an external gNB, and
it maintains a per-UE static neigh so the host can deliver downlink into gtp_br0.

Config (env, e.g. /etc/magma/ebpf.env): S1U_IF, OVS_BR, OVS_VETH;
  ADAPTER_DEBOUNCE (coalesce a burst of flow events, s), ADAPTER_RESYNC (safety re-sync, s);
  ADAPTER_POLL (interval for the poll fallback, s).
"""
import os
import re
import select
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ebpf_control as e  # noqa: E402

try:                              # flush each log line promptly to the journal (stdout is piped)
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass


def _env(*names, default=None):
    for n in names:
        if os.environ.get(n):
            return os.environ[n]
    return default


OVS_BR = _env("OVS_BR", "EBPF_OVS_BR", default="gtp_br0")
S1U_IF = _env("S1U_IF", "EBPF_S1U_IF", default="eth1")
OVS_VETH = _env("OVS_VETH", "EBPF_OVS_VETH", default="gtp_veth0")
POLL = float(_env("ADAPTER_POLL", "EBPF_ADAPTER_POLL", default="3"))      # poll fallback only
DEBOUNCE = float(_env("ADAPTER_DEBOUNCE", default="0.4"))   # coalesce a burst of flow events
RESYNC = float(_env("ADAPTER_RESYNC", default="60"))        # slow safety re-sync (backstop)
RECONNECT = float(_env("ADAPTER_RECONNECT", default="2"))   # backoff before re-subscribing
QFI_COOKIE = "0xeb90"   # adapter-managed per-QFI OVS classifier flows (boot installer uses 0xeb9f)


def sh(cmd):
    return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT).stdout.decode(errors="replace")


def ifindex(name):
    return int(open("/sys/class/net/%s/ifindex" % name).read())


def mac(name):
    return open("/sys/class/net/%s/address" % name).read().strip()


def arp_mac(ip):
    m = re.search(r"lladdr ([0-9a-f:]{17})", sh("ip neigh show %s" % ip))
    return m.group(1) if m else None


def l2_toward(ip):
    """Resolve (egress_ifname, next_hop_mac) toward `ip`.
    Handles on-link (next hop = ip itself) and via-router (next hop = gateway)."""
    out = sh("ip route get %s" % ip)
    dev = re.search(r"\bdev (\S+)", out)
    via = re.search(r"\bvia (\S+)", out)
    oif = dev.group(1) if dev else None
    target = via.group(1) if via else ip          # router IP if off-link, else the gNB itself
    m = arp_mac(target)
    if not m:
        sh("ping -c1 -W1 %s >/dev/null 2>&1" % target)   # populate ARP
        m = arp_mac(target)
    return oif, m


def hexip(h):  # "c0a8040d" -> "192.168.4.13"
    v = int(h, 16)
    return "%d.%d.%d.%d" % ((v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF)


def ovs_port(br, veth):
    """OpenFlow port number of `veth` on `br` (changes when the port is re-added)."""
    m = re.search(r"^\s*(\d+)\(%s\)" % re.escape(veth), sh("ovs-ofctl show %s" % br), re.M)
    return m.group(1) if m else None


def add_qfi_flow(br, port, brmac, qfi):
    sh("ovs-ofctl add-flow %s 'cookie=%s,priority=65535,in_port=%s,pkt_mark=%d,ip,"
       "actions=mod_dl_dst:%s,LOCAL'" % (br, QFI_COOKIE, port, qfi, brmac))


def del_qfi_flow(br, port, qfi):
    sh("ovs-ofctl del-flows %s 'cookie=%s/-1,in_port=%s,pkt_mark=%d,ip'"
       % (br, QFI_COOKIE, port, qfi))


def sync_qfi_flows(br, cur, installed, port, brmac):
    """Reconcile one cookie-tagged pkt_mark=<QFI> classifier flow per *live* QFI.

    The QFI is whatever NMS/policy assigned (discover() reads it off each session); OVS then
    classifies uplink on the eBPF-set mark — QFI extraction has migrated into eBPF. Add/prune on
    change only so OVS counters survive across reconciles. Returns the new installed-QFI set.
    """
    if not port:
        return installed
    desired = {p["qfi"] for p in cur.values()}
    for q in sorted(desired - installed):
        add_qfi_flow(br, port, brmac, q)
        print("[adapter] +QFI classifier flow pkt_mark=%d" % q)
    for q in sorted(installed - desired):
        del_qfi_flow(br, port, q)
        print("[adapter] -QFI classifier flow pkt_mark=%d" % q)
    return desired


def discover():
    """Parse Magma's gtp_br0 flows -> {ue_ip: {dl_teid, gnb_ip, qfi, ul_teid}}."""
    flows = sh("ovs-ofctl dump-flows %s" % OVS_BR)
    sessions = {}
    for ln in flows.splitlines():
        if "NXM_NX_TUN_ID" not in ln or "nw_dst=" not in ln:
            continue
        ue = re.search(r"nw_dst=([0-9.]+)", ln)
        dl = re.search(r"load:0x([0-9a-f]+)->NXM_NX_TUN_ID", ln)
        gnb = re.search(r"load:0x([0-9a-f]+)->NXM_NX_TUN_IPV4_DST", ln)
        qfi = re.search(r"load:0x([0-9a-f]+)->NXM_NX_QFI", ln)
        if not (ue and dl and gnb):
            continue
        ip = ue.group(1)
        if ip.endswith(".1") or ip.endswith(".0"):   # skip gw / network addr
            continue
        s = sessions.setdefault(ip, {})
        s["dl_teid"] = int(dl.group(1), 16)
        s["gnb_ip"] = hexip(gnb.group(1))
        s["qfi"] = int(qfi.group(1), 16) if qfi else 9
    ul_teids = set(re.findall(r"tun_id=0x([0-9a-f]+),qfi=", flows))
    ul = int(next(iter(ul_teids)), 16) if len(ul_teids) == 1 else 0
    for s in sessions.values():
        s["ul_teid"] = ul
    return sessions


def reconcile(ctx):
    """One idempotent reconcile pass: discover Magma's live sessions, (re)program only the
    changed ones into ue_session_map, prune detached ones, and sync the per-QFI classifier flows.
    Change-only programming keeps the map's per-session counters across reconciles."""
    try:
        cur = discover()
    except Exception as ex:           # never die on a transient parse/cmd error
        print("[adapter] discover error: %s" % ex)
        return
    programmed = ctx["programmed"]
    for ip, p in cur.items():
        gnb = p["gnb_ip"]
        oif, gmac = l2_toward(gnb)
        if not gmac:
            print("[adapter] no L2 next-hop for gNB %s yet, skipping %s" % (gnb, ip))
            continue
        src_mac = mac(oif) if oif else ctx["def_mac"]
        s1u_ix = ifindex(oif) if oif else ctx["def_idx"]
        sig = (gnb, gmac, src_mac, s1u_ix, p["dl_teid"], p["ul_teid"], p["qfi"])
        if programmed.get(ip) == sig:
            continue                  # unchanged -> don't rewrite (keeps ul/dl counters)
        e.add_ue_session(ip, gnb, teid_ul_in=p["ul_teid"], teid_dl_out=p["dl_teid"],
                         qfi=p["qfi"], ul_mac_src=src_mac, ul_mac_dst=gmac,
                         s1u_ifindex=s1u_ix, ovs_ifindex=ctx["ovs_idx"])
        sh("ip neigh replace %s lladdr 02:00:00:00:00:%02x dev %s"
           % (ip, int(ip.split(".")[-1]) & 0xFF, OVS_BR))
        print("[adapter] %s session %s -> gNB %s via %s dl_teid=0x%x ul_teid=0x%x qfi=%d"
              % ("+" if ip not in programmed else "~", ip, gnb, oif or S1U_IF,
                 p["dl_teid"], p["ul_teid"], p["qfi"]))
        programmed[ip] = sig
    for ip in list(programmed):
        if ip not in cur:
            try:
                e.remove_ue_session(ip)
            except Exception:
                pass
            sh("ip neigh del %s dev %s" % (ip, OVS_BR))
            del programmed[ip]
            print("[adapter] - session %s (detached)" % ip)
    ctx["qflows"] = sync_qfi_flows(OVS_BR, cur, ctx["qflows"],
                                   ovs_port(OVS_BR, OVS_VETH), ctx["br_mac"])


# A monitor line worth reconciling on: a GTP session flow changed, or any OpenFlow event marker.
_HINT = ("TUN_ID", "tun_id", "NXM_NX_QFI", "qfi=", "nw_dst", "event=")


def watch_once(ctx):
    """Event-driven leg: stream gtp_br0 flow changes via `ovs-ofctl monitor` and reconcile on
    each change (debounced to coalesce a burst). Returns True if the monitor ran for a while and
    then dropped (-> reconnect), or False if it could not be established (-> caller may fall back
    to polling)."""
    stdbuf = "stdbuf -oL " if shutil.which("stdbuf") else ""
    cmd = "%sovs-ofctl monitor %s watch: 2>&1" % (stdbuf, OVS_BR)
    try:
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, bufsize=1, text=True)
    except Exception as ex:
        print("[adapter] monitor spawn failed: %s" % ex)
        return False
    print("[adapter] event-driven: watching %s flow changes (debounce=%ss resync=%ss)"
          % (OVS_BR, DEBOUNCE, RESYNC))
    started = time.monotonic()
    last_sync = started
    dirty = False
    try:
        while True:
            if proc.poll() is not None:
                return time.monotonic() - started > 5     # ran a while -> reconnect; else unsupported
            timeout = DEBOUNCE if dirty else 1.0          # debounce while dirty; else a 1s backstop tick
            r, _, _ = select.select([proc.stdout], [], [], timeout)
            if r:
                line = proc.stdout.readline()
                if not line:
                    return time.monotonic() - started > 5  # EOF
                if any(h in line for h in _HINT):
                    dirty = True
                continue
            # select timed out
            if dirty:                                      # quiet for DEBOUNCE -> one reconcile for the burst
                reconcile(ctx)
                dirty = False
                last_sync = time.monotonic()
            elif time.monotonic() - last_sync >= RESYNC:   # slow safety backstop (catches any missed event)
                reconcile(ctx)
                last_sync = time.monotonic()
    finally:
        try:
            proc.terminate()
        except Exception:
            pass


def poll_loop(ctx):
    """Fallback only: reconcile on a fixed interval (used if flow monitoring is unavailable)."""
    print("[adapter] flow monitoring unavailable; polling every %ss" % POLL)
    while True:
        reconcile(ctx)
        time.sleep(POLL)


def main():
    ctx = {
        "ovs_idx": ifindex(OVS_VETH),
        "def_idx": ifindex(S1U_IF),      # fallback egress if route lookup fails
        "def_mac": mac(S1U_IF),
        "br_mac": mac(OVS_BR),           # gtp_br0 MAC; uplink classifier rewrites dst to it -> LOCAL
        "programmed": {},                # ue_ip -> signature; (re)program on change only
        "qflows": set(),                 # QFIs we currently have an OVS classifier flow for
    }
    sh("ovs-ofctl del-flows %s 'cookie=%s/-1'" % (OVS_BR, QFI_COOKIE))  # clear stale adapter flows
    print("[adapter] up: s1u=%s ovs=%s(%d)" % (S1U_IF, OVS_VETH, ctx["ovs_idx"]))
    reconcile(ctx)                       # one-shot initial sync — catch sessions already present
    fails = 0
    while True:
        ok = watch_once(ctx)             # event-driven; returns when the monitor stream drops
        reconcile(ctx)                   # re-sync after a drop (e.g. OVS restart)
        if ok is False:
            fails += 1
            if fails >= 3:
                poll_loop(ctx)           # monitor unavailable -> fall back to polling (never returns)
        else:
            fails = 0
        time.sleep(RECONNECT)            # small backoff before re-subscribing


if __name__ == "__main__":
    main()
