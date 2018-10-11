#
# Arch-specific network modules
#
ifeq ($(CONFIG_PPC64),y)
# 64 version not yet enabled
#obj-$(CONFIG_BPF_JIT) += bpf_jit_asm64.o bpf_jit_comp64.o
obj-$(CONFIG_BPF_JIT) += bpf_jit_64.o bpf_jit_comp.o
endif
