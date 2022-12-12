# Prerequisite

  Ubuntu 21.10 (5.13.0-52-generic)

```
apt install build-essential libelf-dev 
apt install clang
apt install llvm
```



# compile

To build simply run **make** and run the resulting **libbpfgo-prog** binary.



# output

```
# ./libbpfgo-prog
4026532391 3771110 chmod /root/a.txt 0777
4026531836 3771404 python3 /var/log/ubuntu-advantage.log 0600
```






# Reference

1. [BPF Portability and CO-RE](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html)

