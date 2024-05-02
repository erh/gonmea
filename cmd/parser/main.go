// Package main is an example of using analyzer as a library
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/erh/gonmea/analyzer"
)

func main() {
	if len(os.Args) != 2 {
		panic("need file to parse")
	}
	dataFile, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	parser, err := analyzer.NewParser()
	if err != nil {
		panic(err)
	}
	reader := bufio.NewReader(dataFile)
	for {
		line, _, err := reader.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			panic(err)
		}
		msg, err := parser.ParseMessage(line)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			panic(err)
		}
		md, err := json.MarshalIndent(msg, "", "  ")
		if err != nil {
			panic(err)
		}
		fmt.Fprintln(os.Stdout, string(md))
	}
}
