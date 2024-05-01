package analyzer

import (
	"bytes"
	"io"

	"github.com/erh/gonmea/common"
)

// A Parser is used to parse NMEA messages one by one.
type Parser struct {
	ana *Analyzer
	buf *bytes.Buffer
}

// NewParser returns a new parser ready for use.
func NewParser() (*Parser, error) {
	return NewParserWithFormat(RawFormatUnknown)
}

// NewParserWithFormat returns a new parser that is expecting to
// read messages of the given format.
func NewParserWithFormat(format RawFormat) (*Parser, error) {
	var buf bytes.Buffer
	conf := NewConfigForLibrary(common.NewLogger(io.Discard))
	conf.InFile = &buf
	conf.SelectedFormat = format
	ana, err := NewAnalyzer(conf)
	if err != nil {
		return nil, err
	}
	return &Parser{
		ana: ana,
		buf: &buf,
	}, nil
}

func (p *Parser) setNextData(msgData []byte) error {
	p.buf.Reset()
	_, err := p.buf.Write(msgData)
	return err
}

// ParseMessage parses the given data into a message.
func (p *Parser) ParseMessage(msgData []byte) (*common.Message, error) {
	if err := p.setNextData(msgData); err != nil {
		return nil, err
	}
	return p.ana.ReadMessage()
}

// ParseRawMessage parses the given data into a raw message.
func (p *Parser) ParseRawMessage(msgData []byte) (*common.RawMessage, error) {
	if err := p.setNextData(msgData); err != nil {
		return nil, err
	}
	return p.ana.ReadRawMessage()
}

// ParseMessage parses the given data into a message. It will attempt
// to detect the format of the message.
func ParseMessage(msgData []byte) (*common.Message, RawFormat, error) {
	p, err := NewParser()
	if err != nil {
		return nil, RawFormatUnknown, err
	}
	msg, err := p.ParseMessage(msgData)
	if err != nil {
		return nil, RawFormatUnknown, err
	}
	return msg, p.ana.SelectedFormat, nil
}

// ParseRawMessage parses the given data into a raw message. It will attempt
// to detect the format of the message.
func ParseRawMessage(msgData []byte) (*common.RawMessage, RawFormat, error) {
	p, err := NewParser()
	if err != nil {
		return nil, RawFormatUnknown, err
	}
	msg, err := p.ParseRawMessage(msgData)
	if err != nil {
		return nil, RawFormatUnknown, err
	}
	return msg, p.ana.SelectedFormat, nil
}

// ParseMessageWithFormat parses the given data into a message in the provided format.
func ParseMessageWithFormat(msgData []byte, format RawFormat) (*common.Message, error) {
	p, err := NewParser()
	if err != nil {
		return nil, err
	}
	p.ana.SelectedFormat = format
	return p.ParseMessage(msgData)
}

// ParseRawMessageWithFormat parses the given data into a raw message in the provided format.
func ParseRawMessageWithFormat(msgData []byte, format RawFormat) (*common.RawMessage, error) {
	p, err := NewParser()
	if err != nil {
		return nil, err
	}
	p.ana.SelectedFormat = format
	return p.ParseRawMessage(msgData)
}
