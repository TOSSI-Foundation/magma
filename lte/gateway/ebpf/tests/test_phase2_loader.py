#!/usr/bin/env python3
"""
Phase-2 shared-map verification (Lucas R3 Step 6: "shared maps across handlers").

The libbpf equivalent of the old merged-source map-sharing: decap/encap/mark are separate .o but,
via LIBBPF_PIN_BY_NAME, must bind the SAME pinned ue_session_map / stats_map. This test reads the
loaded programs + pinned maps with bpftool and asserts the sharing. Runs on the AGW (where the
programs are attached); auto-skips elsewhere.

Run:  pytest test_phase2_loader.py     or     sudo python3 test_phase2_loader.py
Env:  BPFTOOL=/path/to/bpftool   (default: the kernel-bump-safe 5.4.0-182 binary, then $PATH)
"""
import json
import os
import shutil
import subprocess
import sys

try:
    import pytest
    def skip(msg):
        pytest.skip(msg)
except ImportError:                       # plain-python fallback
    class _Skip(Exception):
        pass
    def skip(msg):
        raise _Skip(msg)

BPFTOOL = os.environ.get("BPFTOOL") or (
    "/usr/lib/linux-tools/5.4.0-182-generic/bpftool"
    if os.path.exists("/usr/lib/linux-tools/5.4.0-182-generic/bpftool")
    else shutil.which("bpftool"))
BPF_DIR = "/sys/fs/bpf"
PROG_PREFIXES = {                          # bpftool truncates prog names to 15 chars
    "decap": "gtp_decap",
    "encap": "gtp_encap",
    "mark": "gtp_veth0_mark",
}


def _bt(*args):
    out = subprocess.run([BPFTOOL, "-j"] + list(args), stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL)
    return json.loads(out.stdout.decode() or "null")


def _prereqs():
    if not BPFTOOL or not os.path.exists(BPFTOOL):
        skip("bpftool not available")
    if os.geteuid() != 0:
        skip("needs root (bpftool)")
    for m in ("ue_session_map", "config_map", "stats_map"):
        if not os.path.exists(os.path.join(BPF_DIR, m)):
            skip("eBPF maps not pinned (run on the AGW with the datapath up)")


def _map_id(name):
    return _bt("map", "show", "pinned", os.path.join(BPF_DIR, name))["id"]


def _progs():
    """Return {role: prog_dict} for the three datapath programs found loaded."""
    found = {}
    for p in _bt("prog", "show") or []:
        nm = p.get("name", "")
        for role, pref in PROG_PREFIXES.items():
            if nm.startswith(pref[:15]):
                found[role] = p
    return found


def test_three_programs_loaded():
    _prereqs()
    progs = _progs()
    for role in PROG_PREFIXES:
        assert role in progs, "%s program not loaded" % role


def test_ue_session_map_shared_by_all_handlers():
    _prereqs()
    sid = _map_id("ue_session_map")
    progs = _progs()
    for role, p in progs.items():
        assert sid in p.get("map_ids", []), "ue_session_map (id %d) not bound by %s" % (sid, role)


def test_stats_map_shared_by_all_handlers():
    _prereqs()
    sid = _map_id("stats_map")
    for role, p in _progs().items():
        assert sid in p.get("map_ids", []), "stats_map not shared by %s" % role


def test_config_map_shared_by_decap_and_encap():
    _prereqs()
    cid = _map_id("config_map")
    progs = _progs()
    for role in ("decap", "encap"):
        assert cid in progs[role].get("map_ids", []), "config_map not bound by %s" % role


if __name__ == "__main__":
    fns = sorted(n for n in dir() if n.startswith("test_"))
    npass = nskip = 0
    for n in fns:
        try:
            globals()[n]()
            print("PASS %s" % n)
            npass += 1
        except BaseException as e:
            if type(e).__name__ in ("Skipped", "_Skip"):
                print("SKIP %s : %s" % (n, e))
                nskip += 1
            else:
                print("FAIL %s : %r" % (n, e))
    print("\n%d passed, %d skipped, %d total" % (npass, nskip, len(fns)))
    sys.exit(0 if npass + nskip == len(fns) else 1)
