# Prerequisite

 Ubuntu 21.04 (GNU/Linux 5.11.0-18-generic x86_64)

```
apt install build-essential libelf-dev  libbpf-dev 
apt install clang
apt install llvm
```



# compile

To build simply run **make** and run the resulting **libbpfgo-prog** binary.



# output

```
4026531836 11738 420 apt-get /var/lib/apt/lists/cn.archive.ubuntu.com_ubuntu_dists_hirsute-security_InRelease
```



# Issue

1. When I execute this command "chmod 777 filepath", I don't get any output, so I might have to look at the chmod code to find out why
-----------
chmod command is use fchmodat function




# Reference

1. [BPF Portability and CO-RE](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html)

