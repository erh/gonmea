package common

import (
	"bytes"
	"errors"
	"fmt"
	"math"
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
7. Data
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
7. Data
*/
func MarshalRawMessageToFastFormat(rawMsg *RawMessage, multi MultiPackets) ([]byte, error) {
	totalRawSize := len(rawMsg.Data)
	if totalRawSize == 0 {
		return nil, errors.New("message has no data")
	}
	if multi == MultiPacketsCoalesced {
		// it's really just plain based on implementation
		return MarshalRawMessageToPlainFormat(rawMsg, multi)
	}
	if totalRawSize > FastPacketMaxSize {
		return nil, fmt.Errorf("data (%d) cannot fit into max combined packet size %d", totalRawSize, FastPacketMaxSize)
	}

	numFrames := 1 + int(math.Ceil((float64(totalRawSize-FastPacketBucket0Size) / FastPacketBucketNSize)))

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
	remData := rawMsg.Data
	for frameIdx := 0; frameIdx < numFrames; frameIdx++ {
		frameBuf := make([]byte, frameEnvelopeSize)
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
		seqFrame |= byte(frameIdx) & 0x1f // frame, lower 5 bits
		// sequence will be zero since it seems unused/unspecified
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

		var frameData bytes.Buffer
		if _, err := frameData.WriteString(commonPrefix); err != nil {
			return nil, err
		}
		for i := 0; i < len(frameBuf); i++ {
			frameData.WriteString(fmt.Sprintf(",%02x", frameBuf[i]))
		}
		out = append(out, frameData.Bytes()...)
		out = append(out, '\n')
	}

	return out, nil
}
