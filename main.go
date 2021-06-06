package main

import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"

	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {

	bpfModule, err := bpf.NewModuleFromFile("simplebpf.o")
	if err != nil {
		os.Exit(-1)
	}
	defer bpfModule.Close()

	bpfModule.BPFLoadObject()
	prog, err := bpfModule.GetProgram("tracepoint__syscalls__sys_enter_chmod")
	if err != nil {
		os.Exit(-1)
	}

	_, err = prog.AttachTracepoint("__x64_sys_enter_chmod")
	if err != nil {
		os.Exit(-1)
	}

	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		os.Exit(-1)
	}

	rb.Start()

	for {
		event := <-eventsChannel
		pid_ns := int(binary.LittleEndian.Uint32(event[0:4])) // Treat first 4 bytes as LittleEndian Uint32
		pid := int(binary.LittleEndian.Uint32(event[4:8]))
		mode := short(binary.LittleEndian.Uint16(event[8:10]))
		comm := string(bytes.TrimRight(event[10:26], "\x00")) // Remove excess 0's from comm, treat as string
		filename := string(bytes.TrimRight(event[26:], "\x00")) // Remove excess 0's from comm, treat as string
		fmt.Printf("%d %d %d %v %v\n", pid_ns,pid, mode, comm,filename)
	
	}

	rb.Stop()
	rb.Close()
}
