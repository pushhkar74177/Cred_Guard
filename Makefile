# CredGuard demo build.
#   make            - build the agent (bpf object, skeleton, daemon)
#   make vmlinux    - regenerate bpf/vmlinux.h from the running kernel
#   make clean      - remove build artifacts
CLANG   ?= clang
CC      ?= gcc
BPFTOOL ?= bpftool

ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')

BPF_SRC := bpf/credguard.bpf.c
BPF_OBJ := build/credguard.bpf.o
SKEL    := build/credguard.skel.h
APP_SRC := src/credguard.c
APP     := build/credguard

CFLAGS  := -g -O2 -Wall
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -Ibpf -Isrc

.PHONY: all clean vmlinux
all: $(APP)

# Regenerate kernel type definitions from the running kernel (run after moving
# to a new machine or kernel, e.g. WSL -> Arch Linux).
vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

build:
	mkdir -p build

$(BPF_OBJ): $(BPF_SRC) bpf/vmlinux.h src/credguard.h | build
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $@

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $@

$(APP): $(APP_SRC) $(SKEL) src/credguard.h | build
	$(CC) $(CFLAGS) -Ibuild -Isrc $(APP_SRC) -o $@ -lbpf -lelf -lz

clean:
	rm -rf build
