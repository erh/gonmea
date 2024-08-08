// Package main is an example of using analyzer as a library
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strings"

	"github.com/erh/gonmea/analyzer"
	"github.com/erh/gonmea/common"
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
			rtMsg, ok, err := analyzer.ConvertRawMessage(rawMsg)
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("insufficient data in a single message")
			}

			checkEqual := func(roundTripped *common.Message) error {
				if !reflect.DeepEqual(msg.Fields, roundTripped.Fields) {
					fmt.Fprintln(os.Stderr, "(BYTES NEED NOT BE EXACTLY EQUAL)")
					fmt.Fprintf(os.Stderr, "WANTED % 0b\n", msg.CachedRawData)
					fmt.Fprintf(os.Stderr, "GOT    % 0b\n", rawMsg.Data)
					{
						roundTripped, ok, err := analyzer.ConvertRawMessage(rawMsg)
						if !ok {
							return errors.New("insufficient data in a single message")
						}
						if err == nil {
							if possibleMd, err := json.MarshalIndent(roundTripped, "", "  "); err == nil {
								fmt.Fprintf(os.Stderr, "And it would have looked like: %s\n", string(possibleMd))
							}
						}
					}
					return errors.New("bad round trip")
				}
				return nil
			}
			if err := checkEqual(rtMsg); err != nil {
				return nil
			}

			md, err := json.MarshalIndent(rtMsg, "", "  ")
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stdout, "rtMsg", string(md))

			md, err = analyzer.MarshalMessage(msg)
			if err != nil {
				return err
			}

			reader, err := analyzer.NewMessageReader(bytes.NewReader(md))
			if err != nil {
				return err
			}
			rtMsg2, err := reader.Read()
			if err != nil {
				return err
			}
			if err := checkEqual(rtMsg2); err != nil {
				return nil
			}

			md, err = json.MarshalIndent(rtMsg2, "", "  ")
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stdout, "rtMsg2", string(md))
		}
	}
}
