// Package analyzer analyzes NMEA 2000 PGN messages
package analyzer

// Originally from https://github.com/canboat/canboat (Apache License, Version 2.0)
// (C) 2009-2023, Kees Verruijt, Harlingen, The Netherlands.

// This file is part of CANboat.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"go.viam.com/rdk/logging"

	"github.com/erh/gonmea/common"
)

func init() {
	initLookupTypes()
	initFieldTypes()
	initPGNs()
	fillLookups()
	if err := fillFieldType(); err != nil {
		panic(err)
	}
	if err := checkPGNs(); err != nil {
		panic(err)
	}
}

// An Analyzer analyzes NMEA 2000 PGN messages.
type Analyzer interface {
	// ProcessMessage attempts to process and read a message given by msgData.
	// If if it is not yet complete due to fragementation or other reasons,
	// a false will be returned indicating this should be called again.
	ProcessMessage(msgData []byte) (*common.Message, bool, error)

	// ProcessRawMessage attempts to process and read a raw message given by msgData.
	// If if it is not yet complete due to fragementation or other reasons,
	// a false will be returned indicating this should be called again.
	ProcessRawMessage(msgData []byte) (*common.RawMessage, bool, error)

	ConvertRawMessage(rawMsg *common.RawMessage) (*common.Message, bool, error)
}

type analyzerImpl struct {
	Config
	state AnalyzerState
}

// this should be kept in sync with analyzerImp in cli.
type analyzerImplIfc interface {
	State() *AnalyzerState

	SetCurrentFieldMetadata(
		fieldName string,
		data []byte,
		startBit int,
		numBits int,
	)
	ExtractNumberNotEmpty(
		field *PGNField,
		data []byte,
		startBit int,
		numBits int,
		value *int64,
		maxValue *int64,
	) (bool, int64) // int is exceptionValue
}

var _ = analyzerImplIfc(&analyzerImpl{})

type AnalyzerState struct {
	SelectedFormat RawFormat
	MultiPackets   common.MultiPackets

	VariableFieldRepeat [2]int64
	RefPgn              int64 // Remember this over the entire set of fields
	Length              int64
	Skip                bool
	PreviousFieldValue  int64
	FTF                 *PGNField

	ReassemblyBuffer [ReassemblyBufferSize]Packet
}

func newAnalyzer(conf *Config) (*analyzerImpl, error) {
	ana := &analyzerImpl{
		Config: *conf,
		state: AnalyzerState{
			SelectedFormat:      conf.DesiredFormat,
			MultiPackets:        conf.MultiPacketsHint,
			VariableFieldRepeat: [2]int64{0, 0}, // Actual number of repetitions
		},
	}
	return ana, nil
}

// NewAnalyzer returns a new analyzer using the given config.
func NewAnalyzer(conf *Config) (Analyzer, error) {
	return newAnalyzer(conf)
}

// Config is used to configure an Analyzer.
type Config struct {
	DesiredFormat    RawFormat
	MultiPacketsHint common.MultiPackets
	Logger           logging.Logger
}

// NewConfig returns a new default config.
func NewConfig(logger logging.Logger) *Config {
	return &Config{
		DesiredFormat:    RawFormatUnknown,
		MultiPacketsHint: common.MultiPacketsSeparate,
		Logger:           logger,
	}
}

func (ana *analyzerImpl) State() *AnalyzerState {
	return &ana.state
}

// ProcessMessage returns the next message read, if available.
func (ana *analyzerImpl) ProcessMessage(msgData []byte) (*common.Message, bool, error) {
	rawMsg, hasMsg, err := ana.ProcessRawMessage(msgData)
	if err != nil {
		return nil, false, err
	}
	if !hasMsg {
		return nil, false, nil
	}
	if rawMsg == nil {
		return nil, true, err
	}
	converted, hasMsg, err := ana.convertRawMessage(rawMsg)
	if err != nil {
		return nil, false, err
	}
	if !hasMsg {
		return nil, false, nil
	}
	return converted, true, nil
}

/*
 *
 * This is perhaps as good a place as any to explain how CAN messages are laid out by the
 * NMEA. Basically, it's a mess once the bytes are recomposed into bytes (the on-the-wire
 * format is fine).
 *
 * For fields that are aligned on bytes there isn't much of an issue, they appear in our
 * buffers in standard Intel 'least endian' format.
 * For instance the MMSI # 244050447 is, in hex: 0x0E8BEA0F. This will be found in the CAN data as:
 * byte x+0: 0x0F
 * byte x+1: 0xEA
 * byte x+2: 0x8B
 * byte x+3: 0x0e
 *
 * To gather together we loop over the bytes, and keep increasing the magnitude of what we are
 * adding:
 *    for (i = 0, magnitude = 0; i < 4; i++)
 *    {
 *      value += data[i] << magnitude;
 *      magnitude += 8;
 *    }
 *
 * However, when there are two bit fields after each other, lets say A of 2 and then B of 6 bits:
 * then that is laid out MSB first, so the bit mask is 0b11000000 for the first
 * field and 0b00111111 for the second field.
 *
 * This means that if we have a bit field that crosses a byte boundary and does not start on
 * a byte boundary, the bit masks are like this (for a 16 bit field starting at the 3rd bit):
 *
 * 0b00111111 0b11111111 0b11000000
 *     ------   --------   --
 *     000000   11110000   11
 *     543210   32109876   54
 *
 * So we are forced to mask bits 0 and 1 of the first byte. Since we need to process the previous
 * field first, we cannot repeatedly shift bits out of the byte: if we shift left we get the first
 * field first, but in MSB order. We need bit values in LSB order, as the next byte will be more
 * significant. But we can't shift right as that will give us bits in LSB order but then we get the
 * two fields in the wrong order...
 *
 * So for that reason we explicitly test, per byte, how many bits we need and how many we have already
 * used.
 *
 */

// ProcessRawMessage returns the next raw message read, if available.
func (ana *analyzerImpl) ProcessRawMessage(msgData []byte) (*common.RawMessage, bool, error) {
	var msg common.RawMessage

	if len(msgData) == 0 || msgData[0] == '\r' || msgData[0] == '\n' || msgData[0] == '#' {
		if len(msgData) != 0 && msgData[0] == '#' {
			if bytes.Equal(msgData[1:], []byte("SHOWBUFFERS")) {
				ana.showBuffers()
			}
		}

		return nil, false, nil
	}

	if msgData[0] == '$' && len(msgData) > 12 && string(msgData[1:12]) == "PDGY,000000" {
		// digital yacht special $PDGY,000000,0,0,2,28830,0,0
		// is there something better to return??
		return nil, true, nil
	}

	if ana.state.SelectedFormat == RawFormatUnknown {
		ana.state.SelectedFormat = ana.detectFormat(string(msgData))
		if ana.state.SelectedFormat == RawFormatGarminCSV1 || ana.state.SelectedFormat == RawFormatGarminCSV2 {
			// Skip first line containing header line
			return nil, true, nil
		}
	}

	var r int
	switch ana.state.SelectedFormat {
	case RawFormatPlainOrFast:
		numBytes, ok := common.DataLengthInPlainOrFast(msgData, ana.Logger)
		if !ok {
			r = -1
			break
		}
		if numBytes <= 8 {
			r = common.ParseRawFormatPlain(msgData, &msg, ana.Logger)
			ana.Logger.Debugf("plain_or_fast: plain r=%d\n", r)
		} else {
			r = common.ParseRawFormatFast(msgData, &msg, ana.Logger)
			ana.Logger.Debugf("plain_or_fast: fast r=%d\n", r)
			if r >= 0 {
				ana.state.MultiPackets = common.MultiPacketsCoalesced
				ana.state.SelectedFormat = RawFormatFast
			}
		}

	case RawFormatPlainMixFast:
		numBytes, ok := common.DataLengthInPlainOrFast(msgData, ana.Logger)
		if !ok {
			r = -1
			break
		}
		if numBytes <= 8 {
			r = common.ParseRawFormatPlain(msgData, &msg, ana.Logger)
			ana.Logger.Debugf("plain_mix_fast: plain r=%d\n", r)
		} else {
			r = common.ParseRawFormatFast(msgData, &msg, ana.Logger)
			ana.Logger.Debugf("plain_mix_fast: fast r=%d\n", r)
		}

	case RawFormatPlain:
		r = common.ParseRawFormatPlain(msgData, &msg, ana.Logger)

	case RawFormatFast:
		r = common.ParseRawFormatFast(msgData, &msg, ana.Logger)

	case RawFormatAirmar:
		r = common.ParseRawFormatAirmar(msgData, &msg, ana.Logger)

	case RawFormatChetco:
		r = common.ParseRawFormatChetco(msgData, &msg, ana.Logger)

	case RawFormatGarminCSV1, RawFormatGarminCSV2:
		r = common.ParseRawFormatGarminCSV(msgData, &msg, ana.state.SelectedFormat == RawFormatGarminCSV2, ana.Logger)

	case RawFormatYDWG02:
		r = common.ParseRawFormatYDWG02(msgData, &msg, ana.Logger)

	case RawFormatNavLink2:
		r = common.ParseRawFormatNavLink2(msgData, &msg, ana.Logger)

	case RawFormatActisenseN2KASCII:
		r = common.ParseRawFormatActisenseN2KAscii(msgData, &msg, ana.Logger)

	case RawFormatUnknown:
		fallthrough
	default:
		return nil, false, errors.New("Unknown message format")
	}

	if r == 0 {
		return &msg, true, nil
	}
	ana.Logger.Error("Unknown message error %d: '%s'\n", r, msgData)

	return nil, false, nil
}

// RawFormat is the format that raw data is serialized into.
type RawFormat string

// All supported/known raw formats.
const (
	RawFormatUnknown           RawFormat = "UNKNOWN"
	RawFormatPlain             RawFormat = "PLAIN"
	RawFormatFast              RawFormat = "FAST"
	RawFormatPlainOrFast       RawFormat = "PLAIN_OR_FAST"
	RawFormatPlainMixFast      RawFormat = "PLAIN_MIX_FAST"
	RawFormatAirmar            RawFormat = "AIRMAR"
	RawFormatChetco            RawFormat = "CHETCO"
	RawFormatGarminCSV1        RawFormat = "GARMIN_CSV1"
	RawFormatGarminCSV2        RawFormat = "GARMIN_CSV2"
	RawFormatYDWG02            RawFormat = "YDWG02"
	RawFormatNavLink2          RawFormat = "NAVLINK2"
	RawFormatActisenseN2KASCII RawFormat = "ACTISENSE_N2K_ASCII"
)

// RawFormats is the list of all supported/known raw formats.
var RawFormats = []RawFormat{
	RawFormatUnknown,
	RawFormatPlain,
	RawFormatFast,
	RawFormatPlainOrFast,
	RawFormatPlainMixFast,
	RawFormatAirmar,
	RawFormatChetco,
	RawFormatGarminCSV1,
	RawFormatGarminCSV2,
	RawFormatYDWG02,
	RawFormatNavLink2,
	RawFormatActisenseN2KASCII,
}

type Packet struct {
	Size      int
	Data      [common.FastPacketMaxSize]uint8
	Frames    uint32 // Bit is one when frame is received
	AllFrames uint32 // Bit is one when frame needs to be present
	PGN       int
	Src       int
	Used      bool
}

const ReassemblyBufferSize = 64

func (ana *analyzerImpl) showBuffers() {
	var p *Packet

	for buffer := 0; buffer < ReassemblyBufferSize; buffer++ {
		p = &ana.state.ReassemblyBuffer[buffer]

		if p.Used {
			ana.Logger.Errorf("ReassemblyBuffer[%d] PGN %d: size %d frames=%x mask=%x", buffer, p.PGN, p.Size, p.Frames, p.AllFrames)
		} else {
			ana.Logger.Debugf("ReassemblyBuffer[%d]: inUse=false", buffer)
		}
	}
}

func (ana *analyzerImpl) detectFormat(msg string) RawFormat {
	if msg[0] == '$' && msg == "$PCDIN" {
		ana.Logger.Info("Detected Chetco protocol with all data on one line")
		ana.state.MultiPackets = common.MultiPacketsCoalesced
		return RawFormatChetco
	}

	if msg == "Sequence #,Timestamp,PGN,Name,Manufacturer,Remote Address,Local Address,Priority,Single Frame,Size,packet\n" {
		ana.Logger.Info("Detected Garmin CSV protocol with relative timestamps")
		ana.state.MultiPackets = common.MultiPacketsCoalesced
		return RawFormatGarminCSV1
	}

	if msg ==
		"Sequence #,Month_Day_Year_Hours_Minutes_Seconds_msTicks,PGN,Processed PGN,Name,Manufacturer,Remote Address,Local "+
			"Address,Priority,Single Frame,Size,packet\n" {
		ana.Logger.Info("Detected Garmin CSV protocol with absolute timestamps")
		ana.state.MultiPackets = common.MultiPacketsCoalesced
		return RawFormatGarminCSV2
	}

	p := strings.Index(msg, " ")
	if p != -1 && (msg[p+1] == '-' || msg[p+2] == '-') {
		ana.Logger.Info("Detected Airmar protocol with all data on one line")
		ana.state.MultiPackets = common.MultiPacketsCoalesced
		return RawFormatAirmar
	}

	{
		var a, b, c, d, f int
		var e rune
		r, _ := fmt.Sscanf(msg, "%d:%d:%d.%d %c %02X ", &a, &b, &c, &d, &e, &f)
		if r == 6 && (e == 'R' || e == 'T') {
			ana.Logger.Info("Detected YDWG-02 protocol with one line per frame")
			ana.state.MultiPackets = common.MultiPacketsSeparate
			return RawFormatYDWG02
		}
	}

	{
		var a, b, c, d int
		var e float64
		var f string
		r, _ := fmt.Sscanf(msg, "!PDGY,%d,%d,%d,%d,%f,%s ", &a, &b, &c, &d, &e, &f)
		if r == 6 {
			ana.Logger.Info("Detected Digital Yacht NavLink2 protocol with one line per frame")
			ana.state.MultiPackets = common.MultiPacketsCoalesced
			return RawFormatNavLink2
		}
	}

	{
		var a, b, c, d int
		r1, _ := fmt.Sscanf(msg, "A%d.%d %x %x ", &a, &b, &c, &d)
		r2, _ := fmt.Sscanf(msg, "A%d %x %x ", &a, &b, &c)
		if r1 == 4 || r2 == 3 {
			ana.Logger.Info("Detected Actisense N2K Ascii protocol with all frames on one line")
			ana.state.MultiPackets = common.MultiPacketsCoalesced
			return RawFormatActisenseN2KASCII
		}
	}

	numBytes, ok := common.DataLengthInPlainOrFast([]byte(msg), ana.Logger)
	if ok && numBytes > 0 {
		if numBytes > 8 {
			ana.Logger.Info("Detected FAST format with all frames on one line")
			ana.state.MultiPackets = common.MultiPacketsCoalesced
			return RawFormatFast
		}
		ana.Logger.Info("Assuming PLAIN_OR_FAST format with one line per frame or one line per message\n")
		return RawFormatPlainOrFast
	}

	return RawFormatUnknown
}

type hexScanner struct {
	val   int
	isSet bool
}

func (h *hexScanner) Scan(state fmt.ScanState, _ rune) error {
	n, err := fmt.Fscanf(state, "%x", &h.val)
	if n > 0 {
		h.isSet = true
	}
	return err
}

func (ana *analyzerImpl) ConvertRawMessage(rawMsg *common.RawMessage) (*common.Message, bool, error) {
	msg, hasMsg, err := ana.convertRawMessage(rawMsg)
	if err != nil {
		return nil, false, err
	}
	if !hasMsg {
		return nil, false, nil
	}
	return msg, true, nil
}

func (ana *analyzerImpl) convertRawMessage(rawMsg *common.RawMessage) (*common.Message, bool, error) {
	if rawMsg == nil {
		return nil, false, nil
	}

	pgn, _ := SearchForPgn(rawMsg.PGN)
	if ana.state.MultiPackets == common.MultiPacketsSeparate && pgn == nil {
		var err error
		pgn, err = SearchForUnknownPgn(rawMsg.PGN, ana.Logger)
		if err != nil {
			return nil, false, err
		}
	}

	if ana.state.MultiPackets == common.MultiPacketsCoalesced ||
		pgn == nil ||
		pgn.PacketType != PacketTypeFast ||
		len(rawMsg.Data) > 8 {
		// No reassembly needed
		if len(rawMsg.Data) < int(rawMsg.Len) {
			return nil, false, fmt.Errorf("raw messsage data shorter than expected length %d", rawMsg.Len)
		}
		msg, err := ana.convertPGN(rawMsg, rawMsg.Data[:rawMsg.Len])
		if err != nil {
			return nil, false, err
		}
		msg.Sequence = rawMsg.Sequence
		return msg, true, nil
	}

	// Fast packet requires re-asssembly
	// We only get here if we know for sure that the PGN is fast-packet
	// Possibly it is of unknown length when the PGN is unknown.

	var buffer int
	var p *Packet
	for buffer = 0; buffer < ReassemblyBufferSize; buffer++ {
		p = &ana.state.ReassemblyBuffer[buffer]

		if p.Used && p.PGN == int(rawMsg.PGN) && p.Src == int(rawMsg.Src) {
			// Found existing slot
			break
		}
	}
	if buffer == ReassemblyBufferSize {
		// Find a free slot
		for buffer = 0; buffer < ReassemblyBufferSize; buffer++ {
			p = &ana.state.ReassemblyBuffer[buffer]
			if !p.Used {
				break
			}
		}
		if buffer == ReassemblyBufferSize {
			return nil, false, fmt.Errorf("out of reassembly buffers for PGN %d", rawMsg.PGN)
		}
		p.Used = true
		p.Src = int(rawMsg.Src)
		p.PGN = int(rawMsg.PGN)
		p.Frames = 0
	}

	{
		// YDWG can receive frames out of Order, so handle this.
		seq := uint8(rawMsg.Data[0]&0xe0) >> 5
		frame := uint8(rawMsg.Data[0] & 0x1f)
		rawMsg.Sequence = seq
		rawMsg.Frame = frame

		idx := uint32(0)
		frameLen := common.FastPacketBucket0Size
		msgIdx := common.FastPacketBucket0Offset

		if frame != 0 {
			idx = common.FastPacketBucket0Size + uint32(frame-1)*common.FastPacketBucketNSize
			frameLen = common.FastPacketBucketNSize
			msgIdx = common.FastPacketBucketNOffset
		}

		if (p.Frames & (1 << frame)) != 0 {
			ana.Logger.Errorf("Received duplicate fast packet tuple (PGN/src/frame)  (%d/%d/%d)", rawMsg.PGN, rawMsg.Src, frame)
			p.Frames = 0
		}

		if frame == 0 && p.Frames == 0 {
			p.Size = int(rawMsg.Data[1])
			p.AllFrames = (1 << (1 + (p.Size / 7))) - 1
		}

		if len(rawMsg.Data[msgIdx:]) < frameLen {
			return nil, false, fmt.Errorf("frame (len=%d) smaller than expected (len=%d)", len(rawMsg.Data[msgIdx:]), frameLen)
		}
		copy(p.Data[idx:], rawMsg.Data[msgIdx:msgIdx+frameLen])
		p.Frames |= 1 << frame

		ana.Logger.Debugf("Using buffer %d for reassembly of PGN %d: size %d frame %d sequence %d idx=%d frames=%x mask=%x",
			buffer,
			rawMsg.PGN,
			p.Size,
			frame,
			seq,
			idx,
			p.Frames,
			p.AllFrames)
		if p.Frames == p.AllFrames {
			// Received all data
			msg, err := ana.convertPGN(rawMsg, p.Data[:p.Size])
			if err != nil {
				return nil, false, err
			}
			p.Used = false
			p.Frames = 0
			msg.Sequence = seq
			return msg, true, nil
		}
	}
	return nil, false, nil
}

func (ana *analyzerImpl) convertPGN(rawMsg *common.RawMessage, data []byte) (*common.Message, error) {
	if rawMsg == nil {
		return nil, errors.New("expected message")
	}
	pgn, err := GetMatchingPgn(rawMsg.PGN, data, ana.Logger)
	if err != nil {
		return nil, err
	}
	if pgn == nil {
		return nil, fmt.Errorf("no PGN definition found for PGN %d", rawMsg.PGN)
	}

	convertedMsg := &common.Message{
		Timestamp:     rawMsg.Timestamp,
		Priority:      int(rawMsg.Prio),
		Src:           int(rawMsg.Src),
		Dst:           int(rawMsg.Dst),
		PGN:           int(rawMsg.PGN),
		Description:   pgn.Description,
		CachedRawData: data,
	}
	if pgn.FieldCount == 0 {
		return convertedMsg, nil
	}
	convertedMsg.Fields = make(map[string]interface{}, pgn.FieldCount)

	ana.Logger.Debugf("FieldCount=%d RepeatingStart1=%d", pgn.FieldCount, pgn.RepeatingStart1)

	ana.state.VariableFieldRepeat[0] = 255 // Can be overridden by '# of parameters'
	ana.state.VariableFieldRepeat[1] = 0   // Can be overridden by '# of parameters'
	repetition := 0
	variableFields := int64(0)

	startBit := 0
	variableFieldStart := 0
	variableFieldCount := 0
	var repeatingList []interface{}
	var repeatingListName string
	var repeatedObj map[string]interface{}
	for i := 0; (startBit >> 3) < len(data); i++ {
		field := &pgn.FieldList[i]

		if variableFields == 0 {
			repetition = 0
		}

		if pgn.RepeatingCount1 > 0 && field.Order == pgn.RepeatingStart1 && repetition == 0 {
			// Only now is ana.state.VariableFieldRepeat set
			variableFields = int64(pgn.RepeatingCount1) * ana.state.VariableFieldRepeat[0]
			repeatingList = make([]interface{}, 0, variableFields)
			repeatingListName = "list"
			variableFieldCount = int(pgn.RepeatingCount1)
			variableFieldStart = int(pgn.RepeatingStart1)
			repetition = 1
		}
		if pgn.RepeatingCount2 > 0 && field.Order == pgn.RepeatingStart2 && repetition == 0 {
			// Only now is ana.state.VariableFieldRepeat set
			variableFields = int64(pgn.RepeatingCount2) * ana.state.VariableFieldRepeat[1]
			if repeatingList != nil {
				if repeatedObj != nil {
					repeatingList = append(repeatingList, repeatedObj)
					repeatedObj = nil
				}
				if len(repeatingList) != 0 {
					convertedMsg.Fields[repeatingListName] = repeatingList
				}
			}
			repeatingList = make([]interface{}, 0, variableFields)
			repeatingListName = "list2"
			variableFieldCount = int(pgn.RepeatingCount2)
			variableFieldStart = int(pgn.RepeatingStart2)
			repetition = 1
		}

		if variableFields > 0 {
			if i+1 == variableFieldStart+variableFieldCount {
				i = variableFieldStart - 1
				field = &pgn.FieldList[i]
				repetition++

				if repeatedObj != nil {
					repeatingList = append(repeatingList, repeatedObj)
					repeatedObj = nil
				}
			}
			ana.Logger.Debugf("variableFields: repetition=%d field=%d variableFieldStart=%d variableFieldCount=%d remaining=%d",
				repetition,
				i+1,
				variableFieldStart,
				variableFieldCount,
				variableFields)
			variableFields--
		}

		if field.CamelName == "" && field.Name == "" {
			ana.Logger.Debugf("PGN %d has unknown bytes at end: %d", rawMsg.PGN, len(data)-(startBit>>3))
			break
		}

		fieldName := field.Name
		if field.CamelName != "" {
			fieldName = field.CamelName
		}

		var countBits int
		fieldValue, ok, err := ana.convertField(field, fieldName, data, startBit, &countBits)
		if err != nil {
			return nil, err
		}
		if ok {
			if repeatingList == nil {
				convertedMsg.Fields[fieldName] = fieldValue
			} else {
				if repeatedObj == nil {
					repeatedObj = map[string]interface{}{}
				}
				repeatedObj[fieldName] = fieldValue
			}
		}

		startBit += countBits
	}

	if repeatingList != nil {
		if repeatedObj != nil {
			repeatingList = append(repeatingList, repeatedObj)
		}
		if len(repeatingList) != 0 {
			convertedMsg.Fields[repeatingListName] = repeatingList
		}
	}
	return convertedMsg, nil
}

func (ana *analyzerImpl) convertField(
	field *PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (interface{}, bool, error) {
	resolution := field.Resolution
	if resolution == 0.0 {
		resolution = field.FT.Resolution
	}

	ana.Logger.Debugf("PGN %d: convertField(<%s>, \"%s\", ..., startBit=%d) resolution=%g",
		field.PGN.PGN,
		field.Name,
		fieldName,
		startBit,
		resolution)

	var bytes int
	if field.Size != 0 || field.FT != nil {
		if field.Size != 0 {
			*bits = int(field.Size)
		} else {
			*bits = int(field.FT.Size)
		}
		bytes = (*bits + 7) / 8
		bytes = common.Min(bytes, len(data)-startBit/8)
		*bits = common.Min(bytes*8, *bits)
	} else {
		*bits = 0
	}

	ana.SetCurrentFieldMetadata(field.Name, data, startBit, *bits)

	ana.Logger.Debugf("PGN %d: convertField <%s>, \"%s\": bits=%d Proprietary=%t RefPgn=%d",
		field.PGN.PGN,
		field.Name,
		fieldName,
		*bits,
		field.Proprietary,
		ana.state.RefPgn)

	if field.Proprietary {
		if (ana.state.RefPgn >= 65280 && ana.state.RefPgn <= 65535) ||
			(ana.state.RefPgn >= 126720 && ana.state.RefPgn <= 126975) ||
			(ana.state.RefPgn >= 130816 && ana.state.RefPgn <= 131071) {
			// Proprietary, allow field
		} else {
			// standard PGN, skip field
			*bits = 0
			return nil, false, nil
		}
	}

	if field.FT != nil && field.FT.CF != nil {
		ana.Logger.Debugf(
			"PGN %d: convertField <%s>, \"%s\": calling function for %s", field.PGN.PGN, field.Name, fieldName, field.FieldType)
		ana.state.Skip = false
		return field.FT.CF(ana, field, fieldName, data, startBit, bits)
	}
	return nil, false, fmt.Errorf("PGN %d: no function found to convert field '%s'", field.PGN.PGN, fieldName)
}

func (ana *analyzerImpl) SetCurrentFieldMetadata(
	fieldName string,
	data []byte,
	startBit int,
	numBits int,
) {
	var value int64
	var maxValue int64

	if fieldName == "PGN" {
		ExtractNumber(nil, data, startBit, numBits, &value, &maxValue, ana.Logger)
		ana.Logger.Debugf("Reference PGN = %d", value)
		ana.state.RefPgn = value
		return
	}

	if fieldName == "Length" {
		ExtractNumber(nil, data, startBit, numBits, &value, &maxValue, ana.Logger)
		ana.Logger.Debugf("for next field: length = %d", value)
		ana.state.Length = value
		return
	}
}
