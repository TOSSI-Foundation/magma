# Makefile for building eBPF GTP programs (libbpf compatible)

CLANG ?= clang
LLC ?= llc

ARCH := $(shell uname -m | sed 's/x86_64/x86/')

# Multiarch include dir (e.g. x86_64-linux-gnu) where <asm/*.h> live. The bpf
# clang target does not add this automatically, so <linux/types.h> -> <asm/types.h>
# fails without it on Debian/Ubuntu.
MULTIARCH := $(shell gcc -dumpmachine)

KERNEL_HEADERS ?= /usr/src/linux-headers-$(shell uname -r)

# Path to libbpf headers providing <bpf/bpf_helpers.h> and <bpf/bpf_endian.h>.
# Override (e.g. LIBBPF_INCLUDE=/opt/libbpf/include) if libbpf-dev is not at the
# default prefix.
LIBBPF_INCLUDE ?= /usr/include

BPF_CFLAGS := -O2 -g -Wall -Werror \
              -target bpf \
              -D__TARGET_ARCH_$(ARCH) \
              -I$(LIBBPF_INCLUDE) \
              -I$(LIBBPF_INCLUDE)/$(MULTIARCH) \
              -I.

# eBPF source files
BPF_SRCS := \
    gtp_decap.c \
    gtp_encap.c \
    gtp_mark.c

# Output objects
BPF_OBJS := $(BPF_SRCS:.c=.o)

.PHONY: all clean

# Build all handlers
all: $(BPF_OBJS)

# Compile each handler to a BPF object (recipe lines MUST be tab-indented)
%.o: %.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Clean build outputs
clean:
	rm -f $(BPF_OBJS)
