package common

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
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
	AllParsers = append(AllParsers, &ydwg02Parser{})
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

// -----

type ydwg02Parser struct {
}

//nolint:dupword
/*
ParseRawFormatYDWG02 parses YDWG-02 messages.

Yacht Digital, YDWG-02

   Example output: 00:17:55.475 R 0DF50B23 FF FF FF FF FF 00 00 FF

   Example usage:

pi@yacht:~/canboat/analyzer $ netcat 192.168.3.2 1457 | analyzer -json
INFO 2018-10-16T09:57:39.665Z [analyzer] Detected YDWG-02 protocol with all data on one line
INFO 2018-10-16T09:57:39.665Z [analyzer] New PGN 128267 for device 35 (heap 5055 bytes)
{"timestamp":"2018-10-16T22:25:25.166","prio":3,"src":35,"dst":255,"pgn":128267,"description":"Water
Depth","fields":{"Offset":0.000}} INFO 2018-10-16T09:57:39.665Z [analyzer] New PGN 128259 for device 35 (heap 5070 bytes)
{"timestamp":"2018-10-16T22:25:25.177","prio":2,"src":35,"dst":255,"pgn":128259,"description":"Speed","fields":{"Speed Water
Referenced":0.00,"Speed Water Referenced Type":"Paddle wheel"}} INFO 2018-10-16T09:57:39.666Z [analyzer] New PGN 128275 for device
35 (heap 5091 bytes)
{"timestamp":"2018-10-16T22:25:25.179","prio":6,"src":35,"dst":255,"pgn":128275,"description":"Distance
Log","fields":{"Date":"1980.05.04"}} INFO 2018-10-16T09:57:39.666Z [analyzer] New PGN 130311 for device 35 (heap 5106 bytes)
{"timestamp":"2018-10-16T22:25:25.181","prio":5,"src":35,"dst":255,"pgn":130311,"description":"Environmental
Parameters","fields":{"Temperature Source":"Sea Temperature","Temperature":13.39}}
{"timestamp":"2018-10-16T22:25:25.181","prio":6,"src":35,"dst":255,"pgn":128275,"description":"Distance
Log","fields":{"Date":"2006.11.06", "Time": "114:38:39.07076","Log":1940}}
{"timestamp":"2018-10-16T22:25:25.185","prio":6,"src":35,"dst":255,"pgn":128275,"description":"Distance
Log","fields":{"Date":"1970.07.14"}} INFO 2018-10-16T09:57:39.666Z [analyzer] New PGN 130316 for device 35 (heap 5121 bytes)
{"timestamp":"2018-10-16T22:25:25.482","prio":5,"src":35,"dst":255,"pgn":130316,"description":"Temperature Extended
Range","fields":{"Instance":0,"Source":"Sea Temperature","Temperature":13.40}}
{"timestamp":"2018-10-16T22:25:25.683","prio":5,"src":35,"dst":255,"pgn":130311,"description":"Environmental
Parameters","fields":{"Temperature Source":"Sea Temperature","Temperature":13.39}}
*/
// Note(UNTESTED): See README.md.
func (p *ydwg02Parser) Parse(msg string, m *RawMessage) error {
	var msgid uint
	var prio, src, dst uint8
	var pgn uint32

	// parse timestamp. YDWG doesn't give us date so let's figure it out ourself
	splitBySpaces := strings.Split(string(msg), " ")
	if len(splitBySpaces) == 1 {
		return fmt.Errorf("invalid ydwg format")
	}
	tiden := Now().Unix()
	//nolint:gosmopolitan
	m.Timestamp = time.Unix(tiden, 0).Local()

	// parse direction, not really used in analyzer
	splitBySpaces = splitBySpaces[1:]
	if len(splitBySpaces) == 0 {
		return fmt.Errorf("invalid ydwg format")
	}

	// parse msgid
	splitBySpaces = splitBySpaces[1:]
	if len(splitBySpaces) == 0 {
		return fmt.Errorf("invalid ydwg format")
	}
	//nolint:errcheck
	n, _ := strconv.ParseInt(splitBySpaces[0], 16, 64)
	msgid = uint(n)
	prio, pgn, src, dst = GetISO11783BitsFromCanID(msgid)

	// parse data
	i := 0
	for splitBySpaces = splitBySpaces[1:]; len(splitBySpaces) != 0; splitBySpaces = splitBySpaces[1:] {
		//nolint:errcheck
		n, _ := strconv.ParseInt(splitBySpaces[0], 16, 64)
		m.Data = append(m.Data, byte(n))
		i++
		if i > FastPacketMaxSize {
			return fmt.Errorf("invalid ydwg format")
		}
	}

	m.setParsedValues(prio, pgn, dst, src, uint8(i))
	return nil
}

func (p *ydwg02Parser) Detect(msg string) bool {
	var a, b, c, d, f int
	var e rune
	r, _ := fmt.Sscanf(msg, "%d:%d:%d.%d %c %02X ", &a, &b, &c, &d, &e, &f)
	return r == 6 && (e == 'R' || e == 'T')
}

func (p *ydwg02Parser) MultiPacketsCoalesced() bool {
	return false
}

func (p *ydwg02Parser) Name() string {
	return "ydwg02"
}
