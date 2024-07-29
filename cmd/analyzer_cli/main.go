// Package main is an example of using analyzer as a CLI
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/erh/gonmea/analyzer/cli"
	"github.com/erh/gonmea/common"
)

func main() {
	cli, err := cli.New(os.Args)
	handleErr(err)
	handleErr(cli.Run())
}

func handleErr(err error) {
	if err == nil {
		return
	}
	var exitErr *common.ExitError
	if errors.As(err, &exitErr) {
		os.Exit(exitErr.Code)
	}
	fmt.Fprint(os.Stderr, err.Error())
	os.Exit(1)
}
