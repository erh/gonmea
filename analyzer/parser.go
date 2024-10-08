package analyzer

import (
	"bufio"
	"errors"
	"io"
	"strings"

	"github.com/erh/gonmea/common"
)

// Simple helpers

// newOneOffAnalyzer returns a new analyzer ready to use for single use.
func newOneOffAnalyzer() (*analyzerImpl, error) {
	return newOneOffAnalyzerWithFormat(RawFormatUnknown)
}

// newOneOffAnalyzerWithFormat returns a new analyzer for single use
// that is expecting to read messages of the given format.
func newOneOffAnalyzerWithFormat(format RawFormat) (*analyzerImpl, error) {
	conf := NewConfig(common.NewLogger(io.Discard))
	conf.DesiredFormat = format
	ana, err := newAnalyzer(conf)
	if err != nil {
		return nil, err
	}
	return ana, nil
}

type analyzerStater interface {
	State() *AnalyzerState
}

var errExpectedOneMessage = errors.New("expected to parse a message but got nothing")

// ParseMessage parses the given data into a message. It will attempt
// to detect the format of the message.
func ParseMessage(msgData []byte) (*common.Message, RawFormat, error) {
	ana, err := newOneOffAnalyzer()
	if err != nil {
		return nil, RawFormatUnknown, err
	}
	msg, hasMsg, err := ana.ProcessMessage(msgData)
	if err != nil {
		return nil, RawFormatUnknown, err
	}
	if !hasMsg {
		return nil, RawFormatUnknown, errExpectedOneMessage
	}
	return msg, ana.State().SelectedFormat, nil
}

// ParseRawMessage parses the given data into a raw message. It will attempt
// to detect the format of the message.
func ParseRawMessage(msgData []byte) (*common.RawMessage, RawFormat, error) {
	ana, err := newOneOffAnalyzer()
	if err != nil {
		return nil, RawFormatUnknown, err
	}
	msg, hasMsg, err := ana.ProcessRawMessage(msgData)
	if err != nil {
		return nil, RawFormatUnknown, err
	}
	if !hasMsg {
		return nil, RawFormatUnknown, errExpectedOneMessage
	}
	return msg, ana.State().SelectedFormat, nil
}

// ParseMessageWithFormat parses the given data into a message in the provided format.
func ParseMessageWithFormat(msgData []byte, format RawFormat) (*common.Message, error) {
	ana, err := newOneOffAnalyzerWithFormat(format)
	if err != nil {
		return nil, err
	}
	ana.State().SelectedFormat = format
	msg, hasMsg, err := ana.ProcessMessage(msgData)
	if err != nil {
		return nil, err
	}
	if !hasMsg {
		return nil, errExpectedOneMessage
	}
	return msg, nil
}

// ParseRawMessageWithFormat parses the given data into a raw message in the provided format.
func ParseRawMessageWithFormat(msgData []byte, format RawFormat) (*common.RawMessage, error) {
	ana, err := newOneOffAnalyzerWithFormat(format)
	if err != nil {
		return nil, err
	}
	ana.State().SelectedFormat = format
	msg, hasMsg, err := ana.ProcessRawMessage(msgData)
	if err != nil {
		return nil, err
	}
	if !hasMsg {
		return nil, errExpectedOneMessage
	}
	return msg, nil
}

// ConvertRawMessage attempts to convert a raw message into a decode message. If it
// fails an error will be returned. If the data is insufficient, a false bool will
// be returned.
func ConvertRawMessage(rawMsg *common.RawMessage) (*common.Message, bool, error) {
	ana, err := newOneOffAnalyzer()
	if err != nil {
		return nil, false, err
	}
	// this is an optimistic assumption
	ana.State().MultiPackets = common.MultiPacketsCoalesced
	return ana.ConvertRawMessage(rawMsg)
}

type Reader interface {
	Read() (*common.Message, error)
}

type messageReader struct {
	ana    Analyzer
	reader *bufio.Reader
}

func (mr messageReader) Read() (*common.Message, error) {
	for {
		line, _, err := mr.reader.ReadLine()
		if err != nil {
			return nil, err
		}
		line = []byte(strings.TrimSpace(string(line)))
		if len(line) == 0 {
			continue
		}
		msg, hasMsg, err := mr.ana.ProcessMessage(line)
		if err != nil {
			return nil, err
		}
		if !hasMsg {
			continue
		}
		return msg, nil
	}
}

func NewMessageReader(reader io.Reader) (Reader, error) {
	ana, err := newOneOffAnalyzer()
	if err != nil {
		return nil, err
	}

	return messageReader{ana: ana, reader: bufio.NewReader(reader)}, nil
}
