// Package main is an example of using analyzer as a library
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strings"

	"github.com/erh/gonmea/analyzer"
)

func main() {
	err := realMain()
	if err != nil {
		panic(err)
	}
}

func realMain() error {
	if len(os.Args) < 2 {
		return errors.New("need file/path/net to parse")
	}

	if len(os.Args) >= 3 && os.Args[2] == "-roundtrip" {
		roundTripTesting = true
	}

	path := os.Args[1]
	if strings.HasPrefix(path, "net:") {
		host := path[4:]
		conn, err := net.Dial("tcp", host)
		if err != nil {
			return fmt.Errorf("couldn't connect to host (%s): %w", host, err)
		}
		return processData(conn)
	}

	dataFile, err := os.Open(os.Args[1])
	if err != nil {
		return err
	}

	return processData(dataFile)
}

var roundTripTesting = false

func processData(in io.ReadCloser) error {
	//nolint:errcheck
	defer in.Close()

	reader, err := analyzer.NewMessageReader(in)
	if err != nil {
		return err
	}

	for {
		fmt.Fprintln(os.Stdout, "===========================================")
		msg, err := reader.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		md, err := json.MarshalIndent(msg, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, string(md))

		if roundTripTesting {
			rawMsg, err := analyzer.MarshalMessageToRaw(msg)
			if err != nil {
				return err
			}
			rtMsg, err := analyzer.ConvertRawMessage(rawMsg)
			if err != nil {
				return err
			}

			if !reflect.DeepEqual(msg.Fields, rtMsg.Fields) {
				fmt.Fprintln(os.Stderr, "(BYTES NEED NOT BE EXACTLY EQUAL)")
				fmt.Fprintf(os.Stderr, "WANTED % 0b\n", msg.CachedRawData)
				fmt.Fprintf(os.Stderr, "GOT    % 0b\n", rawMsg.Data)
				{
					rtMsg, err := analyzer.ConvertRawMessage(rawMsg)
					if err == nil {
						if possibleMd, err := json.MarshalIndent(rtMsg, "", "  "); err == nil {
							fmt.Fprintf(os.Stderr, "And it would have looked like: %s\n", string(possibleMd))
						}
					}
				}
				return errors.New("bad round trip")
			}

			fmt.Fprintln(os.Stdout, "rawMsg", rawMsg)
			md, err := json.MarshalIndent(rtMsg, "", "  ")
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stdout, "rtMsg", string(md))
		}
	}
}
