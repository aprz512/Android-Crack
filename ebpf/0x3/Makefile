TARGETS = hello

all: $(TARGETS)
.PHONY: all

$(TARGETS): %: %.bpf.o 

%.bpf.o: %.bpf.c
	clang \
	    -target bpf \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-g \
	    -O2 -o $@ -c $<

clean: 
	- rm *.bpf.o
	- rm -f /sys/fs/bpf/hello 
# 	- rm -f /sys/fs/bpf/hello-func

# -target bpf  # 编译目标为BPF虚拟机架构
# -I/usr/include/$(shell uname -m)-linux-gnu 头文件包含路径
# -g  生成调试信息，包含源码行号、变量名等
# -O2  二级优化，平衡编译时间和执行效率
# -c  只编译，不链接，生成目标文件(.o)
# Make变量   $< 第一个依赖文件 (输入文件)     -o $@ 输出到目标文件
