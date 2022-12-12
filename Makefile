# all: vmlinux.h bpf_target go_target

# vmlinux.h:
# 	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# bpf_target: simplebpf.c
# 	clang -g -O2 -c -target bpf -o simplebpf.o simplebpf.c

# go_target: simplebpf.o main.go
# 	CC=gcc CGO_CFLAGS="-I /usr/include/bpf" CGO_LDFLAGS="/usr/lib64/libbpf.a" go build -o libbpfgo-prog

# clean:
# 	rm simplebpf.o libbpfgo-prog vmlinux.h




all: pre-build vmlinux.h bpf_target go_target

LIBBPF_CFLAGS = "-fPIC"
LIBBPF_LDLAGS =
LIBBPF_SRC = ./3rdparty/libbpf/src

LIBBPF_UAPI := $(abspath $(LIBBPF)/include/uapi)
LIBBPF_OBJ := $(abspath $(BUILDLIB)/libbpf/libbpf.a)

BUILD := $(abspath ./build/)
DIST_DIR := $(abspath ./build/dist/)
DIST_BINDIR := $(abspath ./build/dist/bin)
DIST_LIBDIR := $(abspath ./build/dist/libs)
LIB_ELF ?= libelf
CMD_PKGCONFIG ?= pkg-config

define pkg_config
	$(CMD_PKGCONFIG) --libs $(1)
endef


CUSTOM_CGO_CFLAGS = "-I$(abspath $(DIST_LIBDIR)/libbpf)"
CUSTOM_CGO_LDFLAGS = "$(shell $(call pkg_config, $(LIB_ELF))) $(abspath $(DIST_LIBDIR)/libbpf/libbpf.a)"



.PHONY: pre-build
pre-build:
	$(info Build started)
	$(info MKDIR build directories)

	@mkdir -p $(DIST_DIR)
	@mkdir -p $(DIST_BINDIR)
	@mkdir -p $(DIST_LIBDIR)




$(DIST_LIBDIR)/libbpf/libbpf.a: \
	$(LIBBPF_SRC) \

#
	CC="clang" \
		CFLAGS="$(LIBBPF_CFLAGS)" \
		LD_FLAGS="$(LIBBPF_LDFLAGS)" \
		$(MAKE) \
		-C $(LIBBPF_SRC) \
		BUILD_STATIC_ONLY=1 \
		DESTDIR=$(DIST_LIBDIR)/libbpf \
		OBJDIR=$(DIST_LIBDIR)/libbpf/obj \
		INCLUDEDIR= LIBDIR= UAPIDIR= prefix= libdir= \
		install install_uapi_headers

$(LIBBPF_SRC): 
#
ifeq ($(wildcard $@), )
	@$(CMD_GIT) submodule update --init --recursive
endif
	

GO_ENV_BPF =
GO_ENV_BPF += GOOS=linux
GO_ENV_BPF += CC=clang
GO_ENV_BPF += GOARCH=amd64
GO_ENV_BPF += CGO_CFLAGS=$(CUSTOM_CGO_CFLAGS)
GO_ENV_BPF += CGO_LDFLAGS=$(CUSTOM_CGO_LDFLAGS)
DEBUG_GO_GCFLAGS := -gcflags=all="-N -l"

# patch:
# 	cd ./3rdparty/libbpf/ && git am --signoff ../*.patch

# unpatch:
# 	cd ./3rdparty/libbpf/ && git reset HEAD~1 --hard

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

bpf_target: $(DIST_LIBDIR)/libbpf/libbpf.a simple.bpf.c
	clang -g  -O2 -target bpf -D__TARGET_ARCH_amd64 -I$(DIST_LIBDIR)/libbpf -c simple.bpf.c -o simple.bpf.o

go_target: simple.bpf.o main.go
	$(GO_ENV_BPF) go build $(DEBUG_GO_GCFLAGS) \
		-v -o libbpfgo-prog main.go


clean:
	rm -r $(BUILD)/*
	rm simple.bpf.o vmlinux.h libbpf*-prog
