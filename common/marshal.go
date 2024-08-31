package common

import (
	"bytes"
	"errors"
	"fmt"
)

/*
MarshalRawMessageToPlainFormat marshals a RawMessage to the PLAIN packet format, described below.

1                        2 3     4 5   6 7
2022-09-10T12:10:16.614Z,6,60928,5,255,8,fb,9b,70,22,00,9b,50,c0

1. Timestamp
2. Priority
3. PGN
4. Source
5. Destination
6. Data Length
7. Data.
*/
func MarshalRawMessageToPlainFormat(rawMsg *RawMessage, multi MultiPackets) ([]byte, error) {
	totalRawSize := len(rawMsg.Data)
	if totalRawSize == 0 {
		return nil, errors.New("message has no data")
	}
	if multi == MultiPacketsSeparate && totalRawSize > 8 {
		return nil, fmt.Errorf("data (%d) cannot fit into max packet size %d", totalRawSize, 8)
	}

	commonPrefix := fmt.Sprintf(
		"%s,%d,%d,%d,%d,%d",
		rawMsg.Timestamp.Format(timestampFormat),
		rawMsg.Prio,
		rawMsg.PGN,
		rawMsg.Src,
		rawMsg.Dst,
		totalRawSize)

	var frameData bytes.Buffer
	if _, err := frameData.WriteString(commonPrefix); err != nil {
		return nil, err
	}
	for i := 0; i < len(rawMsg.Data); i++ {
		frameData.WriteString(fmt.Sprintf(",%02x", rawMsg.Data[i]))
	}
	frameData.WriteByte('\n')

	return frameData.Bytes(), nil
}

/*
MarshalRawMessageToFastFormat marshals a RawMessage to the FAST packet format, described below.
If the data is larger than 8 bytes, it will be split across multiple packets up to 223 bytes.

1                       2 3      4 5   6 7
2022-09-28-11:36:59.668,3,129029,0,255,8,00,2f,e7,95,3d,00,73,d6

1. Timestamp
2. Priority
3. PGN
4. Source
5. Destination
6. Data Length
7. Data.
*/
func MarshalRawMessageToFastFormat(rawMsg *RawMessage, multi MultiPackets) ([]byte, error) {
	if multi == MultiPacketsCoalesced {
		return MarshalRawMessageToPlainFormat(rawMsg, multi)
	}

	frameEnvelopeSize := FastPacketBucketNSize + 1
	commonPrefix := fmt.Sprintf(
		"%s,%d,%d,%d,%d,%d",
		rawMsg.Timestamp.Format(timestampFormat),
		rawMsg.Prio,
		rawMsg.PGN,
		rawMsg.Src,
		rawMsg.Dst,
		frameEnvelopeSize)

	var out []byte
	separate, err := rawMsg.SeparateFastPackets()
	if err != nil {
		return nil, err
	}
	for _, rm := range separate {
		var frameData bytes.Buffer
		if _, err := frameData.WriteString(commonPrefix); err != nil {
			return nil, err
		}
		for i := 0; i < len(rm.Data); i++ {
			frameData.WriteString(fmt.Sprintf(",%02x", rm.Data[i]))
		}
		out = append(out, frameData.Bytes()...)
		out = append(out, '\n')
	}

	return out, nil
}
