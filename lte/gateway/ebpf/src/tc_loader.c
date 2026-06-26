// tc_loader.c - libbpf (>=1.x) based TC loader for the Magma eBPF GTP-U datapath.
//
// Loads a compiled handler object (pinning its LIBBPF_PIN_BY_NAME maps under
// /sys/fs/bpf) and attaches the named program to an interface's TC ingress/egress
// hook. The TC filter + program persist after this process exits (the kernel holds
// the references), and the maps stay pinned for the control plane to program.
//
// This is the host-side loader for the declarative-infra model (analysis Decision
// #3): infra (veth/clsact/attach/pin) is set up out-of-band; the control plane only
// touches the pinned maps.
//
// Build: gcc tc_loader.c -I/usr/local/include -L/usr/local/lib -lbpf -lelf -lz -o tc_loader
// Usage: tc_loader <obj.o> <prog_name> <ifname> <ingress|egress>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s <obj.o> <prog_name> <ifname> <ingress|egress>\n", argv[0]);
        return 2;
    }
    const char *obj_path = argv[1], *prog_name = argv[2], *ifname = argv[3], *dir = argv[4];
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) { fprintf(stderr, "unknown interface: %s\n", ifname); return 1; }
    bool ingress = strcmp(dir, "ingress") == 0;

    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    if (!obj || libbpf_get_error(obj)) { fprintf(stderr, "open %s failed\n", obj_path); return 1; }
    int err = bpf_object__load(obj);
    if (err) { fprintf(stderr, "load %s failed: %d\n", obj_path, err); return 1; }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, prog_name);
    if (!prog) { fprintf(stderr, "program %s not found in %s\n", prog_name, obj_path); return 1; }
    int prog_fd = bpf_program__fd(prog);

    LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex,
                .attach_point = ingress ? BPF_TC_INGRESS : BPF_TC_EGRESS);
    LIBBPF_OPTS(bpf_tc_opts, opts, .handle = 1, .priority = 1, .prog_fd = prog_fd);

    err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) { fprintf(stderr, "tc_hook_create failed: %d\n", err); return 1; }
    err = bpf_tc_attach(&hook, &opts);
    if (err) { fprintf(stderr, "tc_attach failed: %d\n", err); return 1; }

    printf("attached %s from %s -> %s %s (ifindex %d)\n",
           prog_name, obj_path, ifname, dir, ifindex);
    return 0;
}
