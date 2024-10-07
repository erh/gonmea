package common

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"
)

var AllParsers = []TextLineParser{}

type TextLineParser interface {
	Parse(msg string, m *RawMessage) error

	Detect(msg string) bool

	MultiPacketsCoalesced() bool

	Name() string
}

func init() {
	AllParsers = append(AllParsers, &navLink2Parser{})
}

// ----------------------

type navLink2Parser struct{}

// ParseRawFormatNavLink2 parses Digital Yacht NavLink 2 messages.
// https://github.com/digitalyacht/iKonvert/wiki/4.-Serial-Protocol#41-rx-pgn-sentence
// !PDGY,<pgn#>,p,src,dst,timer,<pgn_data> CR LF
//
// # Key
//
// <pgn#> = NMEA2000 PGN number between 0 and 999999
//
// p = Priority 0-7 with 0 being highest and 7 lowest
//
// src = Source Address of the device sending the PGN between 0-251
//
// dst = Destination Address of the device receiving the PGN between 0-255 (255 = global)
//
// timer = internal timer of the gateway in milliseconds 0-999999
//
// <pgn_data> = The binary payload of the PGN encoded in Base64.
func (p *navLink2Parser) Parse(msg string, m *RawMessage) error {
	var prio, src, dst uint8
	var pgn uint32
	var timer float64
	var pgnData string
	r, _ := fmt.Sscanf(string(msg), "!PDGY,%d,%d,%d,%d,%f,%s ", &pgn, &prio, &src, &dst, &timer, &pgnData)
	if r != 6 {
		return fmt.Errorf("wrong amount of fields in message: %d", r)
	}

	// there's no time but we can start from the beginning of time.
	m.Timestamp = time.Time{}.Add(time.Microsecond * time.Duration(timer*1e3))

	gotHex := false
	if true {
		// this is to work around a dy bug where sometimes it sends hex, and sometimes base64
		allHex := true
		for _, d := range pgnData {
			if (d >= '0' && d <= '9') || (d >= 'A' && d <= 'F') {
				continue
			}
			allHex = false
		}

		if allHex && len(pgnData) > 40 {
			decoded, err := hex.DecodeString(pgnData)
			if err == nil {
				m.Data = decoded
				gotHex = true
			}
		}
	}

	if !gotHex {
		decoded, err := base64.RawStdEncoding.DecodeString(pgnData)
		if err != nil {
			return fmt.Errorf("error decoding base64 data: %s", err)
		}
		m.Data = decoded
	}

	m.setParsedValues(prio, pgn, dst, src, uint8(len(m.Data)))
	return nil
}

func (p *navLink2Parser) Detect(msg string) bool {
	var a, b, c, d int
	var e float64
	var f string
	r, _ := fmt.Sscanf(msg, "!PDGY,%d,%d,%d,%d,%f,%s ", &a, &b, &c, &d, &e, &f)
	return r == 6
}

func (p *navLink2Parser) MultiPacketsCoalesced() bool {
	return true
}

func (p *navLink2Parser) Name() string {
	return "NavLink2"
}
