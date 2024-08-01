package cli

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
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"

	"github.com/erh/gonmea/analyzer"
	"github.com/erh/gonmea/common"
)

const bufMaxSize = 8192

type printBuffer struct {
	buf [bufMaxSize]byte
	p   int
}

func (pb *printBuffer) Print(msg string) {
	remain := bufMaxSize - pb.p
	if remain > 0 {
		if remain < len(msg) {
			msg = msg[:remain]
		}
		copy(pb.buf[pb.p:], msg)
		pb.p += len(msg)
	}
}

func (pb *printBuffer) Printf(format string, v ...any) {
	remain := bufMaxSize - pb.p
	if remain > 0 {
		str := fmt.Sprintf(format, v...)
		if remain < len(str) {
			str = str[:remain]
		}
		copy(pb.buf[pb.p:], str)
		pb.p += len(str)
	}
}

func (pb *printBuffer) Reset() {
	pb.p = 0
}

func (pb *printBuffer) Set(location int) {
	pb.p = location
}

func (pb *printBuffer) Chr(location int) rune {
	return rune(pb.buf[location])
}

func (pb *printBuffer) Insert(location int, str string) {
	strLen := len(str)
	if pb.p+strLen <= bufMaxSize {
		copy(pb.buf[location+strLen:], pb.buf[location:]) // right of
		copy(pb.buf[location:], str)
		pb.p += strLen
	}
}

func (pb *printBuffer) Write(stream io.Writer) {
	//nolint:errcheck
	stream.Write(pb.buf[:pb.p])
	if syncer, ok := stream.(interface {
		Sync() error
	}); ok {
		//nolint:errcheck
		syncer.Sync()
	}
	pb.Reset()
}

func (pb *printBuffer) Location() int {
	return pb.p
}

type geoFormat byte

const (
	geoFormatDD geoFormat = iota
	geoFormatDM
	geoFormatDMS
)

const (
	dataFieldUnknown   = 0
	dataFieldError     = -1
	dataFieldReserved1 = -2
	dataFieldReserved2 = -3
	dataFieldReserved3 = -4
)

func (c *CLI) printEmpty(exceptionValue int64) {
	if c.config.ShowJSON {
		if c.config.ShowJSONEmpty {
			c.pb.Print("null")
		} else {
			impl := c.ana.(analyzerImpl)
			impl.State().Skip = true
		}
	} else {
		switch exceptionValue {
		case dataFieldUnknown:
			c.pb.Print("Unknown")
		case dataFieldError:
			c.pb.Print("ERROR")
		case dataFieldReserved1:
			c.pb.Print("RESERVED1")
		case dataFieldReserved2:
			c.pb.Print("RESERVED2")
		case dataFieldReserved3:
			c.pb.Print("RESERVED3")
		default:
			c.pb.Printf("Unhandled value %d", exceptionValue)
		}
	}
}

func (c *CLI) printASCIIJSONEscaped(data []byte) {
	for _, char := range string(data) {
		switch char {
		case '\b':
			c.pb.Printf("%s", "\\b")

		case '\n':
			c.pb.Printf("%s", "\\n")

		case '\r':
			c.pb.Printf("%s", "\\r")

		case '\t':
			c.pb.Printf("%s", "\\t")

		case '\f':
			c.pb.Printf("%s", "\\f")

		case '"':
			c.pb.Printf("%s", "\\\"")

		case '\\':
			c.pb.Printf("%s", "\\\\")

		case '/':
			c.pb.Printf("%s", "\\/")

		case '\377':
			// 0xff has been seen on recent Simrad VHF systems, and it seems to indicate
			// end-of-field, with noise following. Assume this does not break other systems.
			return

		default:
			if char > 0x00 {
				c.pb.Printf("%c", char)
			}
		}
	}
}

func (c *CLI) printString(data []byte) (bool, error) {
	var lastbyte *byte

	dataLen := len(data)
	if dataLen > 0 {
		// rtrim funny stuff from end, we see all sorts
		lastbyte = &data[len(data)-1]
		lastbyteCount := 0
		for dataLen > 0 && (*lastbyte == 0xff || unicode.IsSpace(rune(*lastbyte)) || *lastbyte == 0 || *lastbyte == '@') {
			dataLen--
			lastbyteCount++
			if len(data)-1-lastbyteCount < 0 {
				break
			}
			lastbyte = &data[len(data)-1-lastbyteCount]
		}
	}

	if dataLen == 0 {
		c.printEmpty(dataFieldUnknown)
		return true, nil
	}

	if c.config.ShowJSON {
		c.pb.Print("\"")
		c.printASCIIJSONEscaped(data[:dataLen])
		c.pb.Print("\"")
	} else {
		c.printASCIIJSONEscaped(data[:dataLen])
	}

	return true, nil
}

func (c *CLI) PrintFieldNumber(
	field *analyzer.PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	var value int64
	var maxValue int64
	var a float64

	unit := field.Unit
	resolution := field.Resolution

	if resolution == 0.0 {
		resolution = 1.0
	}

	impl := c.ana.(analyzerImpl)
	if ok, exp := impl.ExtractNumberNotEmpty(field, data, startBit, *bits, &value, &maxValue); !ok {
		if exp <= 0 {
			c.printEmpty(exp)
		}
		return true, nil
	}

	logUnit := unit
	if logUnit == "" {
		logUnit = "None"
	}
	c.config.Logger.Debugf("fieldPrintNumber <%s> value=%x max=%x resolution=%g offset=%g unit='%s'",
		fieldName,
		value,
		maxValue,
		resolution,
		field.UnitOffset,
		logUnit)
	if resolution == 1.0 && field.UnitOffset == 0.0 {
		c.config.Logger.Debugf("fieldPrintNumber <%s> print as integer %d", fieldName, value)
		c.pb.Printf("%d", value)
		if !c.config.ShowJSON && unit != "" {
			c.pb.Printf(" %s", unit)
		}
	} else {
		var precision int

		a = float64(value)*field.Resolution + field.UnitOffset

		precision = field.Precision
		if precision == 0 {
			for r := field.Resolution; (r > 0.0) && (r < 1.0); r *= 10.0 {
				precision++
			}
		}

		//nolint:gocritic
		if c.config.ShowJSON {
			c.pb.Printf("%.*f", precision, a)
		} else if unit != "" && unit == "m" && a >= 1000.0 {
			c.pb.Printf("%.*f km", precision+3, a/1000)
		} else {
			c.pb.Printf("%.*f", precision, a)
			if unit != "" {
				c.pb.Printf(" %s", unit)
			}
		}
	}

	return true, nil
}

// Note(UNTESTED): See README.md.
func (c *CLI) PrintFieldFloat(
	field *analyzer.PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	data, adjusted := analyzer.AdjustDataLenStart(data, &startBit)
	if !adjusted {
		return false, nil
	}

	if *bits != 4 || startBit != 0 {
		c.config.Logger.Errorf("field '%s' FLOAT value unhandled bits=%d startBit=%d", fieldName, *bits, startBit)
		return false, nil
	}
	if len(data) < 4 {
		return false, nil
	}

	c.pb.Printf("%g", math.Float32frombits(binary.BigEndian.Uint32(data)))
	if !c.config.ShowJSON && field.Unit != "" {
		c.pb.Printf(" %s", field.Unit)
	}

	return true, nil
}

// Note(UNTESTED): See README.md.
func (c *CLI) PrintFieldDecimal(
	_ *analyzer.PGNField,
	_ string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	bitMagnitude := uint8(1)

	data, adjusted := analyzer.AdjustDataLenStart(data, &startBit)
	if !adjusted {
		return false, nil
	}

	bitMask := byte(1 << startBit)

	if startBit+*bits > len(data)*8 {
		*bits = len(data)*8 - startBit
	}

	var value uint8
	for bit := 0; bit < *bits && bit < 128*8; bit++ {
		/* Act on the current bit */
		bitIsSet := (data[0] & bitMask) > 0
		if bitIsSet {
			value |= bitMagnitude
		}

		/* Find the next bit */
		if bitMask == 128 {
			bitMask = 1
			data = data[1:]
		} else {
			bitMask <<= 1
		}
		bitMagnitude <<= 1

		if bit%8 == 7 {
			if value < 100 {
				c.pb.Printf("%02d", value)
			}
			value = 0
			bitMagnitude = 1
		}
	}
	return true, nil
}

func (c *CLI) PrintFieldLookup(
	field *analyzer.PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	var s string

	var value int64
	var maxValue int64

	// Can't use ExtractNumberNotEmpty when the lookup key might use the 'error/unknown' values.
	if !analyzer.ExtractNumber(field, data, startBit, *bits, &value, &maxValue, c.config.Logger) {
		return true, nil
	}

	impl := c.ana.(analyzerImpl)
	state := impl.State()
	if field.Unit != "" && field.Unit[0] == '=' && unicode.IsDigit(rune(field.Unit[1])) {
		lookfor := fmt.Sprintf("=%d", value)
		if lookfor != field.Unit {
			c.config.Logger.Debugf("Field %s value %d does not match %s", fieldName, value, field.Unit[1:])
			state.Skip = true
			return false, nil
		}
		s = field.Description
		if s == "" && field.Lookup.LookupType == analyzer.LookupTypeNone {
			s = lookfor[1:]
		}
	}

	if s == "" && field.Lookup.LookupType != analyzer.LookupTypeNone && value >= 0 {
		if field.Lookup.LookupType == analyzer.LookupTypePair || field.Lookup.LookupType == analyzer.LookupTypeFieldType {
			s = field.Lookup.FunctionPair(int(value))
		} else if field.Lookup.LookupType == analyzer.LookupTypeTriplet {
			var val1 int64

			c.config.Logger.Debugf("Triplet extraction for field '%s'", field.Name)

			if field.PGN != nil && analyzer.ExtractNumberByOrder(field.PGN, int(field.Lookup.Val1Order), data, &val1, c.config.Logger) {
				s = field.Lookup.FunctionTriplet(int(val1), int(value))
			}
		}
		// BIT is handled in fieldPrintBitLookup
	}

	if s != "" {
		//nolint:gocritic
		if c.config.ShowJSONValue {
			c.pb.Printf("%d,\"name\":\"%s\"}", value, s)
		} else if c.config.ShowJSON {
			c.pb.Printf("\"%s\"", s)
		} else {
			c.pb.Printf("%s", s)
		}
	} else {
		maxValueBitCheck := int64(1)
		if *bits > 2 {
			maxValueBitCheck = 2
		}
		//nolint:gocritic
		if *bits > 1 && (value >= maxValue-maxValueBitCheck) {
			c.printEmpty(value - maxValue)
		} else if c.config.ShowJSONValue {
			c.pb.Printf("%d", value)
			if c.config.ShowJSONEmpty {
				c.pb.Print(",\"name\":null")
			}
			c.pb.Print("}")
		} else {
			c.pb.Printf("%d", value)
		}
	}

	return true, nil
}

func (c *CLI) PrintFieldBitLookup(
	field *analyzer.PGNField,
	_ string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	var value int64
	var maxValue int64
	var sep string

	if !analyzer.ExtractNumber(field, data, startBit, *bits, &value, &maxValue, c.config.Logger) {
		return true, nil
	}
	if value == 0 {
		if c.config.ShowJSON {
			c.printEmpty(value - maxValue)
		} else {
			c.pb.Print("None")
		}
		return true, nil
	}

	c.config.Logger.Debugf("RES_BITFIELD length %d value %d", *bits, value)

	//nolint:gocritic
	if c.config.ShowJSONValue {
		sep = "["
	} else if c.config.ShowJSON {
		sep = "["
	} else {
		sep = ""
	}

	bit := 0
	for bitValue := int64(1); bit < *bits; bit++ {
		isSet := (value & bitValue) != 0
		c.config.Logger.Debugf("RES_BITFIELD is bit %d value %d set? = %t", bit, bitValue, isSet)
		if isSet {
			s := field.Lookup.FunctionPair(bit)

			if s != "" {
				//nolint:gocritic
				if c.config.ShowJSONValue {
					c.pb.Printf("%s{\"value\":%d,\"name\":\"%s\"}", sep, bitValue, s)
				} else if c.config.ShowJSON {
					c.pb.Printf("%s\"%s\"", sep, s)
				} else {
					c.pb.Printf("%s%s", sep, s)
				}
			} else {
				if c.config.ShowJSONValue {
					c.pb.Printf("%s{\"value\":%d,\"name\":null}", sep, bitValue)
				} else {
					c.pb.Printf("%s%d", sep, bitValue)
				}
			}
			sep = ","
		}
		bitValue <<= 1
	}
	if c.config.ShowJSON {
		if sep[0] != '[' {
			c.pb.Print("]")
		} else {
			c.pb.Print("[]")
		}
	}
	return true, nil
}

func (c *CLI) PrintFieldBinary(
	field *analyzer.PGNField,
	_ string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	var remainingBits int
	var s string

	data, adjusted := analyzer.AdjustDataLenStart(data, &startBit)
	if !adjusted {
		return false, nil
	}

	if *bits == 0 && field.FieldType == "BINARY" {
		// The length is in the previous field. This is heuristically defined right now, it might change.
		// The only PGNs where this happens are AIS PGNs 129792, 129795 and 129797.
		impl := c.ana.(analyzerImpl)
		*bits = int(impl.State().PreviousFieldValue)
	}

	if startBit+*bits > len(data)*8 {
		*bits = len(data)*8 - startBit
	}

	if c.config.ShowJSON {
		c.pb.Print("\"")
	}
	remainingBits = *bits
	s = ""
	for i := 0; i < (*bits+7)>>3; i++ {
		dataByte := data[i]

		if i == 0 && startBit != 0 {
			dataByte >>= startBit // Shift off older bits
			if remainingBits+startBit < 8 {
				dataByte &= ((1 << remainingBits) - 1)
			} else {
				dataByte <<= startBit // Shift zeros back in
			}
			remainingBits -= (8 - startBit)
		} else {
			if remainingBits < 8 {
				// only the lower remainingBits should be used
				dataByte &= ((1 << remainingBits) - 1)
			}
			remainingBits -= 8
		}
		c.pb.Printf("%s%2.02X", s, dataByte)
		s = " "
	}
	if c.config.ShowJSON {
		c.pb.Print("\"")
	}
	return true, nil
}

/*
 * Only print reserved fields if they are NOT all ones, in that case we have an incorrect
 * PGN definition.
 */
func (c *CLI) PrintFieldReserved(
	field *analyzer.PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	var value int64
	var maxValue int64

	if !analyzer.ExtractNumber(field, data, startBit, *bits, &value, &maxValue, c.config.Logger) {
		return true, nil
	}
	if value == maxValue {
		impl := c.ana.(analyzerImpl)
		impl.State().Skip = true
		return true, nil
	}

	return c.PrintFieldBinary(field, fieldName, data, startBit, bits)
}

/*
 * Only print spare fields if they are NOT all zeroes, in that case we have an incorrect
 * PGN definition.
 */
func (c *CLI) PrintFieldSpare(
	field *analyzer.PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	var value int64
	var maxValue int64

	if !analyzer.ExtractNumber(field, data, startBit, *bits, &value, &maxValue, c.config.Logger) {
		return true, nil
	}
	if value == 0 {
		impl := c.ana.(analyzerImpl)
		impl.State().Skip = true
		return true, nil
	}

	return c.PrintFieldBinary(field, fieldName, data, startBit, bits)
}

// This is only a different printer than fieldPrintNumber so the JSON can contain a string value.
func (c *CLI) PrintFieldMMSI(
	field *analyzer.PGNField,
	_ string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	var value int64
	var maxValue int64

	impl := c.ana.(analyzerImpl)
	if ok, exp := impl.ExtractNumberNotEmpty(field, data, startBit, *bits, &value, &maxValue); !ok {
		if exp <= 0 {
			c.printEmpty(exp)
		}
		return true, nil
	}

	c.pb.Printf("\"%09d\"", uint32(value))
	return true, nil
}

// Note(UNTESTED): See README.md.
func (c *CLI) PrintFieldKeyValue(
	field *analyzer.PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	var r bool

	impl := c.ana.(analyzerImpl)
	state := impl.State()
	if state.Length != 0 {
		*bits = int(state.Length * 8)
	} else {
		*bits = int(field.Size)
	}
	c.config.Logger.Debugf("fieldPrintKeyValue('%s') bits=%d", fieldName, *bits)

	if len(data) >= ((startBit + *bits) >> 3) {
		if state.FTF != nil {
			f := state.FTF

			c.config.Logger.Debugf("fieldPrintKeyValue('%s') is actually a '%s' field bits=%d", fieldName, f.FT.Name, f.Size)

			if *bits == 0 {
				*bits = int(f.Size)
			}
			if *bits == 0 && f.FT != nil && f.FT.Name != "" && f.FT.Name == "LOOKUP" {
				*bits = f.Lookup.Size
			}

			var err error
			r, err = f.FT.PF(c, f, fieldName, data, startBit, bits)
			if err != nil {
				return false, err
			}
		} else {
			var err error
			r, err = c.PrintFieldBinary(field, fieldName, data, startBit, bits)
			if err != nil {
				return false, err
			}
		}
	} else {
		var pgn uint32
		if field.PGN != nil {
			pgn = field.PGN.PGN
		}
		c.config.Logger.Errorf("PGN %d key-value has insufficient bytes for field %s", pgn, fieldName)
	}

	state.FTF = nil
	state.Length = 0

	return r, nil
}

func (c *CLI) PrintFieldLatLon(
	field *analyzer.PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	var absVal uint64
	var value int64
	var maxValue int64
	isLongitude := strings.Contains(fieldName, "ongit")
	var dd float64
	var degrees float64
	var remainder float64
	var minutes float64
	var seconds float64

	c.config.Logger.Debugf("fieldPrintLatLon for '%s' startbit=%d bits=%d", fieldName, startBit, *bits)

	impl := c.ana.(analyzerImpl)
	if ok, exp := impl.ExtractNumberNotEmpty(field, data, startBit, *bits, &value, &maxValue); !ok {
		if exp <= 0 {
			c.printEmpty(exp)
		}
		return true, nil
	}

	if value < 0 {
		absVal = uint64(-value)
	} else {
		absVal = uint64(value)
	}
	dd = float64(value) * field.Resolution

	if c.config.ShowGeo == geoFormatDD {
		c.pb.Printf("%10.7f", dd)
	} else {
		if c.config.ShowJSONValue {
			c.pb.Printf("%d,\"name\":", value)
		}
		if c.config.ShowGeo == geoFormatDM {
			dd = float64(absVal) * field.Resolution
			degrees = math.Floor(dd)
			remainder = dd - degrees
			minutes = remainder * 60.

			fmtStr := "%02dd %6.3f %c"
			if c.config.ShowJSON {
				fmtStr = "\"%02d&deg; %6.3f %c\""
			}
			var dir rune
			if isLongitude {
				if value >= 0 {
					dir = 'E'
				} else {
					dir = 'W'
				}
			} else {
				if value >= 0 {
					dir = 'N'
				} else {
					dir = 'S'
				}
			}
			c.pb.Printf(fmtStr,
				uint32(degrees),
				minutes,
				dir)
		} else {
			dd = float64(absVal) * field.Resolution
			degrees = math.Floor(dd)
			remainder = dd - degrees
			minutes = math.Floor(remainder * 60.)
			seconds = math.Floor(remainder*3600.) - 60.*minutes

			fmtStr := "%02dd %02d' %06.3f\"%c"
			if c.config.ShowJSON {
				fmtStr = "\"%02d&deg;%02d&rsquo;%06.3f&rdquo;%c\""
			}

			var dir rune
			if isLongitude {
				if value >= 0 {
					dir = 'E'
				} else {
					dir = 'W'
				}
			} else {
				if value >= 0 {
					dir = 'N'
				} else {
					dir = 'S'
				}
			}
			c.pb.Printf(fmtStr,
				int(degrees),
				int(minutes),
				seconds,
				dir)
		}
		if c.config.ShowJSONValue {
			c.pb.Print("}")
		}
	}
	return true, nil
}

func (c *CLI) PrintFieldDate(
	_ *analyzer.PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	var d uint16

	data, adjusted := analyzer.AdjustDataLenStart(data, &startBit)
	if !adjusted {
		return false, nil
	}

	if startBit != 0 {
		return analyzer.UnhandledStartOffset(fieldName, startBit, c.config.Logger), nil
	}
	if *bits != 16 {
		return analyzer.UnhandledBitLength(fieldName, *bits, c.config.Logger), nil
	}
	if len(data) < *bits/8 {
		return true, nil
	}

	d = uint16(data[0]) + (uint16(data[1]) << 8)

	if d >= 0xfffd {
		c.printEmpty(int64(d) - int64(0xffff))
		return true, nil
	}

	tm := time.Unix(int64(d)*86400, 0).UTC()
	formatted := tm.Format("2006.01.02")
	if c.config.ShowJSON {
		if c.config.ShowJSONValue {
			c.pb.Printf("%d,\"name\":\"%s\"}", d, formatted)
		} else {
			c.pb.Printf("\"%s\"", formatted)
		}
	} else {
		c.pb.Printf("%s", formatted)
	}
	return true, nil
}

/**
 * Fixed length string where the length is defined by the field definition.
 */
func (c *CLI) PrintFieldStringFix(
	field *analyzer.PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	dataLen := int(field.Size) / 8

	data, adjusted := analyzer.AdjustDataLenStart(data, &startBit)
	if !adjusted {
		return false, nil
	}

	c.config.Logger.Debugf("fieldPrintStringFix('%s',%d) size=%d", fieldName, len(data), dataLen)

	dataLen = common.Min(dataLen, len(data)) // Cap length to remaining bytes in message
	*bits = 8 * dataLen
	return c.printString(data[:dataLen])
}

// Note(UNTESTED): See README.md.
func (c *CLI) PrintFieldStringLZ(
	_ *analyzer.PGNField,
	_ string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	// STRINGLZ format is <specifiedDataLen> [ <data> ... ]
	var dataLen int

	data, adjusted := analyzer.AdjustDataLenStart(data, &startBit)
	if !adjusted {
		return false, nil
	}
	dataLen = len(data)

	// Cap to dataLen
	specifiedDataLen := data[0]
	data = data[1:]
	specifiedDataLen = common.Min(specifiedDataLen, byte(dataLen-1))
	*bits = int(8 * (specifiedDataLen + 1))

	return c.printString(data[:specifiedDataLen])
}

func (c *CLI) PrintFieldStringLAU(
	_ *analyzer.PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	// STRINGLAU format is <len> <control> [ <data> ... ]
	// where <control> == 0 = UTF16
	//       <control> == 1 = ASCII(?) or maybe UTF8?
	var control int
	var specifiedDataLen int

	data, adjusted := analyzer.AdjustDataLenStart(data, &startBit)
	if !adjusted {
		return false, nil
	}
	dataLen := len(data)
	c.config.Logger.Debugf("fieldPrintStringLAU: <%s> data=%p len=%d startBit=%d bits=%d", fieldName, data, len(data), startBit, *bits)

	specifiedDataLen = int(data[0])
	control = int(data[1])
	data = data[2:]
	if specifiedDataLen < 2 || dataLen < 2 {
		c.config.Logger.Errorf("field '%s': Invalid string length %d in STRINana.LAU field", fieldName, specifiedDataLen)
		return false, nil
	}
	specifiedDataLen = common.Min(specifiedDataLen, dataLen) - 2

	*bits = 8 * (specifiedDataLen + 2)

	if control == 0 {
		utf16Data := make([]uint16, specifiedDataLen/2)
		//nolint:errcheck
		_ = binary.Read(bytes.NewReader(data), binary.LittleEndian, &utf16Data)
		utf16Str := utf16.Decode(utf16Data)
		utf8Str := string(utf16Str)
		c.config.Logger.Debugf("fieldprintStringLAU: UTF16 len %d requires %d utf8 bytes", specifiedDataLen/2, len(utf8Str))
		data = []byte(utf8Str)
		specifiedDataLen = len(data)
	} else if control > 1 {
		c.config.Logger.Errorf("Unhandled string type %d in PGN", control)
		return false, nil
	}

	return c.printString(data[:specifiedDataLen])
}

func (c *CLI) PrintFieldTime(
	field *analyzer.PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	var unitspersecond uint64
	var hours uint32
	var minutes uint32
	var seconds uint32
	var units uint32
	var value int64
	var maxValue int64
	var t uint64
	var digits int

	sign := ""

	impl := c.ana.(analyzerImpl)
	if ok, exp := impl.ExtractNumberNotEmpty(field, data, startBit, *bits, &value, &maxValue); !ok {
		if exp <= 0 {
			c.printEmpty(exp)
		}
		return true, nil
	}

	c.config.Logger.Debugf("fieldPrintTime(<%s>, \"%s\") v=%d res=%g max=0x%d",
		field.Name,
		fieldName,
		value,
		field.Resolution,
		maxValue)

	if value < 0 {
		value = -value
		sign = "-"
	}

	if field.Resolution < 1.0 {
		unitspersecond = uint64(1.0 / field.Resolution)
	} else {
		unitspersecond = 1
		value *= int64(field.Resolution)
	}

	t = uint64(value)
	seconds = uint32(t / unitspersecond)
	units = uint32(t % unitspersecond)
	minutes = seconds / 60
	seconds %= 60
	hours = minutes / 60
	minutes %= 60

	digits = int(math.Log10(float64(unitspersecond)))

	if c.config.ShowJSON {
		if c.config.ShowJSONValue {
			c.pb.Printf("%s%d,\"name\":", sign, value)
		}
		if units != 0 {
			c.pb.Printf("\"%s%02d:%02d:%02d.%0*d\"", sign, hours, minutes, seconds, digits, units)
		} else {
			c.pb.Printf("\"%s%02d:%02d:%02d\"", sign, hours, minutes, seconds)
		}
		if c.config.ShowJSONValue {
			c.pb.Print("}")
		}
	} else {
		if units != 0 {
			c.pb.Printf("%s%02d:%02d:%02d.%0*d", sign, hours, minutes, seconds, digits, units)
		} else {
			c.pb.Printf("%s%02d:%02d:%02d", sign, hours, minutes, seconds)
		}
	}
	return true, nil
}
