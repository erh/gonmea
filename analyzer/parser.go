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
	return newOneOffAnalyzerWithFormat("")
}

// newOneOffAnalyzerWithFormat returns a new analyzer for single use
// that is expecting to read messages of the given format.
func newOneOffAnalyzerWithFormat(format string) (*analyzerImpl, error) {
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
func ParseTextMessage(msgData string) (*common.Message, common.TextLineParser, error) {
	ana, err := newOneOffAnalyzer()
	if err != nil {
		return nil, nil, err
	}
	msg, hasMsg, err := ana.ProcessMessage(msgData)
	if err != nil {
		return nil, nil, err
	}
	if !hasMsg {
		return nil, nil, errExpectedOneMessage
	}
	return msg, ana.State().parser, nil
}

// ParseRawMessage parses the given data into a raw message. It will attempt
// to detect the format of the message.
func ParseRawTextMessage(msgData string) (*common.RawMessage, common.TextLineParser, error) {
	ana, err := newOneOffAnalyzer()
	if err != nil {
		return nil, nil, err
	}
	msg, hasMsg, err := ana.ProcessRawMessage(msgData)
	if err != nil {
		return nil, nil, err
	}
	if !hasMsg {
		return nil, nil, errExpectedOneMessage
	}
	return msg, ana.State().parser, nil
}

// ParseMessageWithFormat parses the given data into a message in the provided format.
func ParseTextMessageWithFormat(msgData string, format string) (*common.Message, error) {
	ana, err := newOneOffAnalyzerWithFormat(format)
	if err != nil {
		return nil, err
	}
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
func ParseRawMessageWithFormat(msgData string, format string) (*common.RawMessage, error) {
	ana, err := newOneOffAnalyzerWithFormat(format)
	if err != nil {
		return nil, err
	}
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
		msgData := strings.TrimSpace(string(line))
		if len(line) == 0 {
			continue
		}
		msg, hasMsg, err := mr.ana.ProcessMessage(msgData)
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
