package common

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
)

var AllParsers = []TextLineParser{}

func FindParser(msg string) TextLineParser {
	for _, p := range AllParsers {
		if p.Detect(msg) {
			return p
		}
	}
	return nil
}

func FindParserByName(n string) TextLineParser {
	for _, p := range AllParsers {
		if p.Name() == n {
			return p
		}
	}
	return nil
}

type TextLineParser interface {
	Parse(msg string, m *RawMessage) error
	Detect(msg string) bool
	Marshal(rawMsg *RawMessage, packetTypeFast bool, multi MultiPackets) (string, error)
	MultiPacketsCoalesced() bool
	SkipFirstLine() bool
	Name() string
}

var PlainOrFastParserInstance = &plainOrFastParser{}
var NavLink2Instance = &navLink2Parser{}
var GarminCSV1Instance = &garminCSV1{}
var GarminCSV2Instance = &garminCSV2{}

func init() {
	AllParsers = append(AllParsers, NavLink2Instance)
	AllParsers = append(AllParsers, &ydwg02Parser{})
	AllParsers = append(AllParsers, PlainOrFastParserInstance)
	AllParsers = append(AllParsers, GarminCSV1Instance)
	AllParsers = append(AllParsers, GarminCSV2Instance)
	AllParsers = append(AllParsers, &chetcoParser{})
	AllParsers = append(AllParsers, &airmarParser{})
	AllParsers = append(AllParsers, &actisenseParser{})

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

func (p *navLink2Parser) Marshal(rawMsg *RawMessage, packetTypeFast bool, multi MultiPackets) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (p *navLink2Parser) MultiPacketsCoalesced() bool {
	return true
}

func (p *navLink2Parser) SkipFirstLine() bool {
	return false
}

func (p *navLink2Parser) Name() string {
	return "NAVLINK2"
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

func (p *ydwg02Parser) Marshal(rawMsg *RawMessage, packetTypeFast bool, multi MultiPackets) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (p *ydwg02Parser) MultiPacketsCoalesced() bool {
	return false
}

func (p *ydwg02Parser) SkipFirstLine() bool {
	return false
}

func (p *ydwg02Parser) Name() string {
	return "YDWG02"
}

// ---------

type plainOrFastParser struct {
}

func (p *plainOrFastParser) Parse(msg string, m *RawMessage) error {
	numBytes, ok := DataLengthInPlainOrFast(msg)
	if !ok {
		return fmt.Errorf("not plain or fast")
	}
	if numBytes <= 8 {
		return p.parsePlain(msg, m)
	}
	return p.parseFast(msg, m)
}

// ParseRawFormatPlain parses PLAIN messages.
func (p *plainOrFastParser) parsePlain(msg string, m *RawMessage) error {
	var prio, src, dst, dataLen uint8
	var pgn uint32
	var junk, r int
	var data [8]int

	pIdx := findOccurrence(msg, ',', 1)
	if pIdx == -1 {
		return fmt.Errorf("not a plain format")
	}
	pIdx-- // Back to comma

	tm, err := ParseTimestamp(string(msg[:pIdx]))
	if err != nil {
		return err
	}
	m.Timestamp = tm

	r, _ = fmt.Sscanf(string(msg[pIdx:]),
		",%d,%d,%d,%d,%d"+
			",%x,%x,%x,%x,%x,%x,%x,%x,%x",
		&prio,
		&pgn,
		&src,
		&dst,
		&dataLen,
		&data[0],
		&data[1],
		&data[2],
		&data[3],
		&data[4],
		&data[5],
		&data[6],
		&data[7],
		&junk)
	if r < 5 {
		return fmt.Errorf("Error reading message, scanned %d from %s", r, string(msg))
	}

	if dataLen > 8 {
		return fmt.Errorf("This is not PLAIN format but FAST format")
	}

	m.Data = make([]byte, dataLen)
	if r <= 5+8 {
		for i := uint8(0); i < dataLen; i++ {
			m.Data[i] = uint8(data[i])
		}
	} else {
		return fmt.Errorf("invalid plain format")
	}

	m.setParsedValues(prio, pgn, dst, src, dataLen)
	return nil
}

// ParseRawFormatFast parses FAST messages.
func (p *plainOrFastParser) parseFast(msg string, m *RawMessage) error {
	var prio, src, dst, dataLen uint8
	var pgn uint32

	var r int

	pIdx := findOccurrence(msg, ',', 1)
	if pIdx == -1 {
		return fmt.Errorf("not fast")
	}
	pIdx-- // Back to comma

	tm, err := ParseTimestamp(string(msg[:pIdx]))
	if err != nil {
		return err
	}
	m.Timestamp = tm

	r, _ = fmt.Sscanf(string(msg[pIdx:]), ",%d,%d,%d,%d,%d ", &prio, &pgn, &src, &dst, &dataLen)
	if r < 5 {
		return fmt.Errorf("Error reading message, scanned %d from %s", r, string(msg))
	}

	nextIdx := findOccurrence(msg[pIdx:], ',', 6)
	if nextIdx == -1 {
		return fmt.Errorf("Error reading message, scanned %d bytes from %s", pIdx, string(msg))
	}
	m.Data = make([]byte, dataLen)
	pIdx += nextIdx
	for i := uint8(0); i < dataLen; i++ {
		advancedBy, ok := scanHex(msg[pIdx:], &m.Data[i])
		if !ok {
			return fmt.Errorf("Error reading message, scanned %d bytes from %s/%s, index %d", pIdx, string(msg), string(msg[pIdx:]), i)
		}
		pIdx += advancedBy
		if i < dataLen && pIdx < len(msg) {
			if msg[pIdx] != ',' && !unicode.IsSpace(rune(msg[pIdx])) {
				return fmt.Errorf("Error reading message, scanned %d bytes from %s", pIdx, string(msg))
			}
			pIdx++
		}
	}

	m.setParsedValues(prio, pgn, dst, src, dataLen)
	return nil
}

func (p *plainOrFastParser) Detect(msg string) bool {
	_, ok := DataLengthInPlainOrFast(msg)
	return ok
}

func (p *plainOrFastParser) Marshal(rawMsg *RawMessage, packetTypeFast bool, multi MultiPackets) (string, error) {
	if packetTypeFast {
		return MarshalRawMessageToFastFormat(rawMsg, multi)
	}

	if multi == MultiPacketsCoalesced {
		return MarshalRawMessageToPlainFormat(rawMsg, multi)
	}

	if len(rawMsg.Data) > 8 {
		return MarshalRawMessageToFastFormat(rawMsg, multi)
	}

	return MarshalRawMessageToPlainFormat(rawMsg, multi)
}

func (p *plainOrFastParser) MultiPacketsCoalesced() bool {
	return true
}

func (p *plainOrFastParser) SkipFirstLine() bool {
	return false
}

func (p *plainOrFastParser) Name() string {
	return "PLAIN_OR_FAST"
}

func DataLengthInPlainOrFast(msg string) (int, bool) {
	var prio, src, dst, dataLen uint8
	var pgn uint32
	var junk, r int

	pIdx := findOccurrence(msg, ',', 1)
	if pIdx == -1 {
		return 0, false
	}
	pIdx-- // Back to comma

	_, err := ParseTimestamp(string(msg[:pIdx]))
	if err != nil {
		return 0, false
	}

	r, _ = fmt.Sscanf(string(msg[pIdx:]),
		",%d,%d,%d,%d,%d"+
			",%x,%x,%x,%x,%x,%x,%x,%x,%x",
		&prio,
		&pgn,
		&src,
		&dst,
		&dataLen,
		&junk,
		&junk,
		&junk,
		&junk,
		&junk,
		&junk,
		&junk,
		&junk,
		&junk)
	if r < 5 {
		return 0, false
	}

	return int(dataLen), true
}

// --------------

type garminCSV1 struct {
}

func (p *garminCSV1) Parse(msg string, m *RawMessage) error {
	return parseRawFormatGarminCSV(msg, m, false)
}

func (p *garminCSV1) Marshal(rawMsg *RawMessage, packetTypeFast bool, multi MultiPackets) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (p *garminCSV1) MultiPacketsCoalesced() bool {
	return true
}

func (p *garminCSV1) SkipFirstLine() bool {
	return true
}

func (p *garminCSV1) Name() string {
	return "GARMIN_CSV1"
}

func (p *garminCSV1) Detect(msg string) bool {
	return msg == "Sequence #,Timestamp,PGN,Name,Manufacturer,Remote Address,Local Address,Priority,Single Frame,Size,packet\n"
}

type garminCSV2 struct {
}

func (p *garminCSV2) Parse(msg string, m *RawMessage) error {
	return parseRawFormatGarminCSV(msg, m, true)
}

func (p *garminCSV2) Marshal(rawMsg *RawMessage, packetTypeFast bool, multi MultiPackets) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (p *garminCSV2) MultiPacketsCoalesced() bool {
	return true
}

func (p *garminCSV2) SkipFirstLine() bool {
	return true
}

func (p *garminCSV2) Name() string {
	return "GARMIN_CSV2"
}

func (p *garminCSV2) Detect(msg string) bool {
	return msg == "Sequence #,Timestamp,PGN,Name,Manufacturer,Remote Address,Local Address,Priority,Single Frame,Size,packet\n"
}

/*
parseRawFormatGarminCSV parses Garmin CSV (1 and 2) messages.

Sequence #,Timestamp,PGN,Name,Manufacturer,Remote Address,Local Address,Priority,Single Frame,Size,Packet
0,486942,127508,Battery Status,Garmin,6,255,2,1,8,0x017505FF7FFFFFFF
129,491183,129029,GNSS Position Data,Unknown
Manufacturer,3,255,3,0,43,0xFFDF40A6E9BB22C04B3666C18FBF0600A6C33CA5F84B01A0293B140000000010FC01AC26AC264A12000000
*/
// Note(UNTESTED): See README.md.
func parseRawFormatGarminCSV(msg string, m *RawMessage, absolute bool) error {
	var seq, tstamp, pgn, src, dst, prio, single, count uint
	var t int

	if len(msg) == 0 || msg[0] == '\n' {
		return fmt.Errorf("not a valid garmin csv msg")
	}

	var pIdx int
	if absolute {
		var month, day, year, hours, minutes, seconds, ms uint

		if r, _ := fmt.Sscanf(
			string(msg),
			"%d,%d_%d_%d_%d_%d_%d_%d,%d,",
			&seq, &month, &day, &year, &hours, &minutes, &seconds, &ms, &pgn); r < 9 {
			return fmt.Errorf("Error reading Garmin CSV message: %s", msg)
		}

		//nolint:gosmopolitan
		m.Timestamp = time.Date(
			int(year),
			time.Month(month),
			int(day),
			int(hours),
			int(minutes),
			int(seconds),
			int((ms%1000)*1e6),
			time.Local,
		)

		pIdx = findOccurrence(msg, ',', 6)
	} else {
		if r, _ := fmt.Sscanf(string(msg), "%d,%d,%d,", &seq, &tstamp, &pgn); r < 3 {
			return fmt.Errorf("Error reading Garmin CSV message: %s", msg)
		}

		t = int(tstamp / 1000)
		//nolint:gosmopolitan
		m.Timestamp = time.Unix(int64(t), 0).Local()

		pIdx = findOccurrence(msg, ',', 5)
	}

	if len(msg[pIdx:]) == 0 {
		return fmt.Errorf("Error reading Garmin CSV message: %s", msg)
	}

	var restOfData string
	if r, _ := fmt.Sscanf(string(msg[pIdx:]), "%d,%d,%d,%d,%d,0x%s", &src, &dst, &prio, &single, &count, &restOfData); r < 5 {
		return fmt.Errorf("Error reading Garmin CSV message: %s", msg)
	}
	pIdx += strings.Index(string(msg[pIdx:]), ",0x") + 3

	m.Data = make([]byte, count)
	var i uint
	for i = 0; len(msg[pIdx:]) != 0 && i < count; i++ {
		advancedBy, ok := scanHex(msg[pIdx:], &m.Data[i])
		if !ok {
			return fmt.Errorf("Error reading message, scanned %d bytes from %s/%s, index %d", pIdx, string(msg), string(msg[pIdx:]), i)
		}
		pIdx += advancedBy
	}

	m.setParsedValues(uint8(prio), uint32(pgn), uint8(dst), uint8(src), uint8(i+1))
	return nil
}

// ----------------

type chetcoParser struct {
}

func (p *chetcoParser) Detect(msg string) bool {
	return msg[0] == '$' && msg == "$PCDIN"
}

func (p *chetcoParser) Marshal(rawMsg *RawMessage, packetTypeFast bool, multi MultiPackets) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (p *chetcoParser) MultiPacketsCoalesced() bool {
	return true
}

func (p *chetcoParser) SkipFirstLine() bool {
	return false
}

func (p *chetcoParser) Name() string {
	return "CHETCO"
}

// ParseRawFormatChetco parses Chetco messages.
// Note(UNTESTED): See README.md.
func (p *chetcoParser) Parse(msg string, m *RawMessage) error {
	var tstamp uint

	if len(msg) == 0 || msg[0] == '\n' {
		return fmt.Errorf("invalid chetco")
	}

	if r, _ := fmt.Sscanf(string(msg), "$PCDIN,%x,%x,%x,", &m.PGN, &tstamp, &m.Src); r < 3 {
		return fmt.Errorf("Error reading Chetco message: %s", msg)
	}

	t := int(tstamp / 1000)
	//nolint:gosmopolitan
	m.Timestamp = time.Unix(int64(t), 0).Local()

	pIdx := len("$PCDIN,01FD07,089C77D!,03,") // Fixed length where data bytes start;

	var i uint
	for i = 0; msg[pIdx] != '*'; i++ {
		m.Data = append(m.Data, 0x00)
		advancedBy, ok := scanHex(msg[pIdx:], &m.Data[i])
		if !ok {
			return fmt.Errorf("Error reading message, scanned %d bytes from %s/%s, index %d", pIdx, string(msg), string(msg[pIdx:]), i)
		}
		pIdx += advancedBy
	}

	m.Prio = 0
	m.Dst = 255
	m.Len = uint8(i + 1)
	return nil
}

// --------------

type airmarParser struct {
}

func (p *airmarParser) Detect(msg string) bool {
	idx := strings.Index(msg, " ")
	return idx != -1 && (msg[idx+1] == '-' || msg[idx+2] == '-')
}

func (p *airmarParser) Marshal(rawMsg *RawMessage, packetTypeFast bool, multi MultiPackets) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (p *airmarParser) MultiPacketsCoalesced() bool {
	return true
}

func (p *airmarParser) SkipFirstLine() bool {
	return false
}

func (p *airmarParser) Name() string {
	return "AIRMAR"
}

// ParseRawFormatAirmar parses Airmar messages.
// Note(UNTESTED): See README.md.
func (p *airmarParser) Parse(msg string, m *RawMessage) error {
	var dataLen uint
	var prio, src, dst uint8
	var pgn uint32

	var id uint

	pIdx := findOccurrence(msg, ' ', 1)
	if pIdx < 4 || pIdx >= 60 {
		return fmt.Errorf("not airmar")
	}

	tm, err := ParseTimestamp(string(msg[:pIdx-1]))
	if err != nil {
		return err
	}
	m.Timestamp = tm
	pIdx += 3

	r, _ := fmt.Sscanf(string(msg[pIdx:]), "%d", &pgn)
	if r != 1 {
		return fmt.Errorf("Error reading message, scanned %d bytes from %s", pIdx, string(msg))
	}
	pIdx += len(strconv.FormatUint(uint64(pgn), 10))
	if msg[pIdx] == ' ' {
		pIdx++

		r, _ := fmt.Sscanf(string(msg[pIdx:]), "%x", &id)
		if r != 1 {
			return fmt.Errorf("Error reading message, scanned %d bytes from %s", pIdx, string(msg))
		}
		pIdx += len(strconv.FormatUint(uint64(id), 16))
	}
	if msg[pIdx] != ' ' {
		return fmt.Errorf("Error reading message, scanned %d bytes from %s", pIdx, string(msg))
	}

	prio, pgn, src, dst = GetISO11783BitsFromCanID(id)

	pIdx++
	dataLen = uint(len(msg[pIdx:]) / 2)
	m.Data = make([]byte, dataLen)
	for i := uint(0); i < dataLen; i++ {
		advancedBy, ok := scanHex(msg[pIdx:], &m.Data[i])
		if !ok {
			return fmt.Errorf("Error reading message, scanned %d bytes from %s/%s, index %d", pIdx, string(msg), string(msg[pIdx:]), i)
		}
		pIdx += advancedBy
		if i < dataLen {
			if msg[pIdx] != ',' && msg[pIdx] != ' ' {
				return fmt.Errorf("Error reading message, scanned %d bytes from %s", pIdx, string(msg))
			}
			pIdx++
		}
	}

	m.setParsedValues(prio, pgn, dst, src, uint8(dataLen))
	return nil
}

// -------------

type actisenseParser struct {
	tiden int
}

func (p *actisenseParser) Detect(msg string) bool {
	var a, b, c, d int
	r1, _ := fmt.Sscanf(msg, "A%d.%d %x %x ", &a, &b, &c, &d)
	r2, _ := fmt.Sscanf(msg, "A%d %x %x ", &a, &b, &c)
	return r1 == 4 || r2 == 3
}

func (p *actisenseParser) Marshal(rawMsg *RawMessage, packetTypeFast bool, multi MultiPackets) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (p *actisenseParser) MultiPacketsCoalesced() bool {
	return true
}

func (p *actisenseParser) SkipFirstLine() bool {
	return false
}

func (p *actisenseParser) Name() string {
	return "ACTISENSE_N2K_ASCII"
}

// ParseRawFormatActisenseN2KAscii parses Actisense N2K ASCII messages.
func (ppp *actisenseParser) Parse(msg string, m *RawMessage) error {
	scanned := 0

	// parse timestamp. Actisense doesn't give us date so let's figure it out ourself
	splitBySpaces := strings.Split(string(msg), " ")
	if len(splitBySpaces) == 1 || splitBySpaces[0][0] != 'A' {
		return fmt.Errorf("No message or does not start with 'A'\n")
	}

	var secs, millis int
	r, _ := fmt.Sscanf(splitBySpaces[0][1:], "%d.%d", &secs, &millis)
	if r < 1 {
		return fmt.Errorf("invalida airmar")
	}

	if ppp.tiden == 0 {
		ppp.tiden = int(Now().Unix()) - secs
	}
	now := ppp.tiden + secs

	//nolint:gosmopolitan
	m.Timestamp = time.Unix(int64(now), 0).Add(time.Millisecond * time.Duration(millis)).Local()

	// parse <SRC><DST><P>
	scanned += len(splitBySpaces[0]) + 1
	splitBySpaces = splitBySpaces[1:]
	if len(splitBySpaces) == 0 {
		return fmt.Errorf("invalid airmar")
	}
	//nolint:errcheck
	n, _ := strconv.ParseInt(splitBySpaces[0], 16, 64)
	m.Prio = uint8(n & 0xf)
	m.Dst = uint8((n >> 4) & 0xff)
	m.Src = uint8((n >> 12) & 0xff)

	// parse <PGN>
	scanned += len(splitBySpaces[0]) + 1
	splitBySpaces = splitBySpaces[1:]
	if len(splitBySpaces) == 0 {
		return fmt.Errorf("Incomplete message airmark")
	}
	//nolint:errcheck
	n, _ = strconv.ParseInt(splitBySpaces[0], 16, 64)
	m.PGN = uint32(n)

	// parse DATA
	scanned += len(splitBySpaces[0]) + 1
	p := strings.Join(splitBySpaces[1:], " ")
	var i uint8
	m.Data = make([]byte, FastPacketMaxSize)
	for i = 0; i < FastPacketMaxSize; i++ {
		if len(p) == 0 || unicode.IsSpace(rune(p[0])) {
			break
		}
		advancedBy, ok := scanHex(p, &m.Data[i])
		if !ok {
			return fmt.Errorf("Error reading message, scanned %d bytes from %s/%s, index %d", len(msg)-scanned, string(msg), string(p), i)
		}
		scanned += advancedBy
		p = p[advancedBy:]
	}
	m.Len = i

	return nil
}
