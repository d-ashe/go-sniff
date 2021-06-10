
package main

import (
	"github.com/d-ashe/go-sniff/cmd"
)

func main() {
	if err := cmd.SniffCmd().Execute(); err != nil {
		panic(err)
	}
}