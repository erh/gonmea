package common

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
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode"
)

const (
	timestampFormat = "2006-01-02-15:04:05.000"
	// others seen in pgn-test.in.
	timestampFormatAlt  = "2006-01-02T15:04:05.000Z"
	timestampFormatAlt2 = "2006-01-02T15:04:05Z"
)

// RawMessage is a raw NMEA 2000 PGN message.
type RawMessage struct {
	// if relative, then it's from January 1, year 1, 00:00:00.000000000 UTC
	Timestamp time.Time
	Prio      uint8
	PGN       uint32
	Dst       uint8
	Src       uint8
	Len       uint8
	Data      []byte

	// Only set when this is a fast packet
	Sequence uint8 // 3 bits max, unvalidated
	Frame    uint8 // 5 bits max, unvalidated
}

func (rm *RawMessage) setParsedValues(prio uint8, pgn uint32, dst, src, dataLen uint8) {
	rm.Prio = prio
	rm.PGN = pgn
	rm.Dst = dst
	rm.Src = src
	rm.Len = dataLen
}

func (rm *RawMessage) SeparateSingleOrFastPackets(isFastPacket bool) ([]*RawMessage, error) {
	if isFastPacket || len(rm.Data) > 8 {
		return rm.SeparateFastPackets()
	}
	newRaw := *rm
	newRaw.Data = make([]byte, len(rm.Data))
	copy(newRaw.Data, rm.Data)
	return []*RawMessage{&newRaw}, nil
}

func (rm *RawMessage) SeparateFastPackets() ([]*RawMessage, error) {
	totalRawSize := len(rm.Data)
	if totalRawSize == 0 {
		return nil, errors.New("message has no data")
	}
	if totalRawSize > FastPacketMaxSize {
		return nil, fmt.Errorf("data (%d) cannot fit into max combined packet size %d", totalRawSize, FastPacketMaxSize)
	}

	numFrames := 1 + int(math.Ceil((float64(totalRawSize-FastPacketBucket0Size) / FastPacketBucketNSize)))

	frameEnvelopeSize := FastPacketBucketNSize + 1

	var rawMsgs []*RawMessage
	remData := rm.Data
	for frameIdx := 0; frameIdx < numFrames; frameIdx++ {
		frameBuf := make([]byte, frameEnvelopeSize)
		for i := 0; i < frameEnvelopeSize; i++ {
			frameBuf[i] = 0xff
		}
		var frameSize, frameOffset int

		if frameIdx == 0 { // up to 6 inner bytes in 8 byte envelope -- first two bytes are seqFrame and numFrames
			frameSize = FastPacketBucket0Size
			frameOffset = FastPacketBucket0Offset
			frameBuf[FastPacketBucket0Offset-1] = byte(totalRawSize)
		} else { // up to 7 inner bytes in 8 byte envelope -- first byte is seqFrame
			frameSize = FastPacketBucketNSize
			frameOffset = FastPacketBucketNOffset
		}
		var seqFrame byte
		seqFrame |= (byte(rm.Sequence) << 5) & 0xe0 // sequence, upper 3 bits
		seqFrame |= byte(frameIdx) & 0x1f           // frame, lower 5 bits
		frameBuf[0] = seqFrame

		dataSpanSize := Min(len(remData), frameSize)
		rawFrameData := remData[:dataSpanSize]
		if len(rawFrameData) > len(frameBuf[frameOffset:]) {
			return nil, fmt.Errorf(
				"invariant: expected raw frame data (len=%d) to fit into FAST frame (len=%d)",
				len(rawFrameData),
				len(frameBuf[frameOffset:]),
			)
		}
		copy(frameBuf[frameOffset:], rawFrameData)
		remData = remData[dataSpanSize:]

		newRaw := *rm
		newRaw.Data = frameBuf
		rawMsgs = append(rawMsgs, &newRaw)
	}
	return rawMsgs, nil
}

// Message is a NMEA 2000 PGN message.
type Message struct {
	// if relative, then it's from January 1, year 1, 00:00:00.000000000 UTC
	Timestamp     time.Time              `json:"timestamp"`
	Priority      int                    `json:"prio"`
	Src           int                    `json:"src"`
	Dst           int                    `json:"dst"`
	PGN           int                    `json:"pgn"`
	Description   string                 `json:"description"`
	Fields        map[string]interface{} `json:"fields"`
	Sequence      uint8                  `json:"-"` // 3 bits max, unvalidated
	CachedRawData []byte                 `json:"-"`
}

func findOccurrence(msg string, c rune, count int) int {
	if len(msg) == 0 || msg[0] == '\n' {
		return 0
	}

	pIdx := 0
	for i := 0; i < count && len(msg) != pIdx-1; i++ {
		nextIdx := strings.IndexByte(msg[pIdx:], byte(c))
		if nextIdx == -1 {
			return -1
		}
		pIdx += nextIdx
		if len(msg) != pIdx-1 {
			pIdx++
		}
	}
	return pIdx
}

func ParseTimestamp(from string) (time.Time, error) {
	tm, err1 := time.Parse(timestampFormat, from)
	if err1 == nil {
		return tm, nil
	}
	tm, err2 := time.Parse(timestampFormatAlt, from)
	if err2 == nil {
		return tm, nil
	}
	tm, err3 := time.Parse(timestampFormatAlt2, from)
	if err3 == nil {
		return tm, nil
	}
	var day, year, hour, minute, millis int
	var month string
	r, _ := fmt.Sscanf(from,
		"%d %s %d %d:%d +%d",
		&day,
		&month,
		&year,
		&hour,
		&minute,
		&millis)
	if r == 6 {
		var mMonth time.Month
		monthOk := true
		switch month {
		case "Jan":
			mMonth = time.January
		case "Feb":
			mMonth = time.February
		case "Mar":
			mMonth = time.March
		case "Apr":
			mMonth = time.April
		case "May":
			mMonth = time.May
		case "Jun":
			mMonth = time.June
		case "Jul":
			mMonth = time.July
		case "Aug":
			mMonth = time.August
		case "Sep":
			mMonth = time.September
		case "Oct":
			mMonth = time.October
		case "Nov":
			mMonth = time.November
		case "Dec":
			mMonth = time.December
		default:
			monthOk = false
		}
		if monthOk {
			secs := millis / 1000
			millis = millis % 1000
			nanos := millis * 1000000
			return time.Date(2000+year, mMonth, day, hour, minute, secs, nanos, time.Local), nil
		}
	}
	return time.Time{}, fmt.Errorf("error parsing time '%s': %w; %w; %w", from, err1, err2, err3)
}

func scanNibble(c byte) byte {
	if unicode.IsDigit(rune(c)) {
		return c - '0'
	}
	if c >= 'A' && c <= 'F' {
		return c - 'A' + 10
	}
	if c >= 'a' && c <= 'f' {
		return c - 'a' + 10
	}
	return 16
}

func scanHex(p string, m *byte) (int, bool) {
	var hi, lo byte

	if len(p) < 2 {
		return 0, false
	}

	hi = scanNibble(p[0])
	if hi > 15 {
		return 0, false
	}
	lo = scanNibble(p[1])
	if lo > 15 {
		return 0, false
	}
	*m = hi<<4 | lo
	return 2, true
}
