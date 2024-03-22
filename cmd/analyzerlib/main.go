// Package main is an example of using analyzer as a library
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/erh/gonmea/analyzer"
	"github.com/erh/gonmea/common"
)

func main() {
	logger := common.NewLogger(io.Discard)
	conf := analyzer.NewConfigForLibrary(logger)

	var err error
	conf.ShowJSON = true
	conf.InFile, err = os.Open("./analyzer/tests/navlink2-test.in")
	if err != nil {
		panic(err)
	}
	ana, err := analyzer.NewAnalyzer(conf)
	if err != nil {
		panic(err)
	}
	for {
		msg, err := ana.ReadMessage()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			panic(err)
		}
		var msgJSON map[string]interface{}
		if err := json.Unmarshal(msg, &msgJSON); err != nil {
			panic(err)
		}
		md, err := json.MarshalIndent(msgJSON, "", "  ")
		if err != nil {
			panic(err)
		}
		fmt.Fprintln(os.Stdout, string(md))
	}
}
