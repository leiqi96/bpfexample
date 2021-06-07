package main

import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"

	bpf "github.com/aquasecurity/tracee/libbpfgo"
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

	_, err = prog.AttachTracepoint("syscalls:sys_enter_chmod")
	if err != nil {
		os.Exit(-1)
	}

	prog2, err := bpfModule.GetProgram("tracepoint__syscalls__sys_enter_fchmod")
	if err != nil {
		os.Exit(-1)
	}

	_, err = prog2.AttachTracepoint("syscalls:sys_enter_fchmod")
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
		pid_ns := int(binary.LittleEndian.Uint32(event[0:4]))
		pid := int(binary.LittleEndian.Uint32(event[4:8]))
		mode := uint16(binary.LittleEndian.Uint16(event[8:12]))
		comm := string(event[12:28]) 
		filename := string(bytes.TrimRight(event[28:], "\x00"))
		fmt.Printf("%d %d %d %v %v\n", pid_ns,pid, mode, comm,filename)

	}

	rb.Stop()
	rb.Close()
}
