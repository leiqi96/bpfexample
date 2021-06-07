all: vmlinux.h bpf_target go_target

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

bpf_target: simplebpf.c
	clang -g -O2 -c -target bpf -o simplebpf.o simplebpf.c

go_target: simplebpf.o main.go
	CC=gcc CGO_CFLAGS="-I /usr/include/bpf" CGO_LDFLAGS="/usr/lib64/libbpf.a" go build -o libbpfgo-prog

clean:
	rm simplebpf.o libbpfgo-prog vmlinux.h