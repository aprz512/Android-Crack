OUTPUT := .output
CLANG ?= clang
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
BPFTOOL ?= bpftool


all: lsm_prevent

.output:
	mkdir -p $(OUTPUT)

# 1. 编译 BPF 代码 -> .o
$(OUTPUT)/lsm_prevent.bpf.o: lsm_prevent.bpf.c vmlinux.h | .output
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I. -c $< -o $@

# 2. 生成 Skeleton 头文件
$(OUTPUT)/lsm_prevent.skel.h: $(OUTPUT)/lsm_prevent.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# 3. 编译用户态程序
lsm_prevent: lsm_prevent.c $(OUTPUT)/lsm_prevent.skel.h | .output
	$(CLANG) -g -O2 -Wall -I. -I$(OUTPUT) $< -lbpf -lelf -z noexecstack -o $@

clean:
	rm -rf $(OUTPUT) lsm_prevent