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
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"runtime/debug"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"

	"github.com/erh/gonmea/common"
	"go.viam.com/rdk/logging"
)

const bufMaxSize = 8192

type printBuffer struct {
	buf [bufMaxSize]byte
	p   int
}

func (pb *printBuffer) Printf(format string, v ...any) {
	if fmt.Sprintf(format, v...) == " None" {
		debug.PrintStack()
	}
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

/*
 * Find a field by Order. This will only work for a field that
 * is at a predefined bit offset, so no variable fields before
 * it.
 *
 * It is currently only used for LOOKUP_TYPE_TRIPLET.
 */
func getFieldOffsetByOrder(pgn *pgnInfo, order int) int {
	bitOffset := 0

	for i := 0; i < order; i++ {
		field := &pgn.fieldList[i]

		if i+1 == order {
			return bitOffset
		}
		bitOffset += int(field.size)
	}
	return 0
}

func adjustDataLenStart(data []byte, startBit *int) ([]byte, bool) {
	bytes := *startBit >> 3

	if bytes < len(data) {
		*startBit &= 7
		return data[bytes:], true
	}

	return nil, false
}

func extractNumberByOrder(pgn *pgnInfo, order int, data []byte, value *int64, logger logging.Logger) bool {
	field := &pgn.fieldList[order-1]
	bitOffset := getFieldOffsetByOrder(pgn, order)

	var startBit int
	var maxValue int64

	startBit = bitOffset & 7
	data = data[bitOffset>>3:]

	return extractNumber(field, data, startBit, int(field.size), value, &maxValue, logger)
}

func extractNumber(
	field *pgnField,
	data []byte,
	startBit int,
	bits int,
	value *int64,
	maxValue *int64,
	logger logging.Logger,
) bool {
	var hasSign bool
	if field == nil {
		hasSign = false
	} else {
		hasSign = field.hasSign
	}
	var name string
	if field == nil {
		name = "<bits>"
	} else {
		name = field.name
	}

	bitsRemaining := bits
	magnitude := 0
	var bitsInThisByte int
	var bitMask uint64
	var allOnes uint64
	var valueInThisByte uint64
	var maxv uint64

	logger.Debugf("extractNumber <%s> startBit=%d bits=%d", name, startBit, bits)

	data, adjusted := adjustDataLenStart(data, &startBit)
	if !adjusted {
		return false
	}

	firstBit := startBit
	*value = 0
	maxv = 0

	for bitsRemaining > 0 && len(data) > 0 {
		bitsInThisByte = common.Min(8-firstBit, bitsRemaining)
		allOnes = ((uint64(1)) << bitsInThisByte) - 1

		// How are bits ordered in bytes for bit fields? There are two ways, first field at LSB or first
		// field as MSB.
		// Experimentation, using the 129026 PGN, has shown that the most likely candidate is LSB.
		bitMask = allOnes << firstBit
		valueInThisByte = (uint64(data[0]) & bitMask) >> firstBit

		*value |= int64(valueInThisByte << magnitude)
		maxv |= allOnes << magnitude

		magnitude += bitsInThisByte
		bitsRemaining -= bitsInThisByte
		firstBit += bitsInThisByte
		if firstBit >= 8 {
			firstBit -= 8
			data = data[1:]
		}
	}
	if bitsRemaining > 0 {
		logger.Debugf("Insufficient length in PGN to fill field '%s'", name)
		return false
	}

	if hasSign {
		maxv >>= 1

		if field != nil && field.offset != 0 /* J1939 Excess-K notation */ {
			*value += int64(field.offset)
			maxv += uint64(field.offset)
		} else {
			negative := (*value & int64(((uint64(1)) << (bits - 1)))) > 0

			if negative {
				/* Sign extend value for cases where bits < 64 */
				/* Assume we have bits = 16 and value = -2 then we do: */
				/* 0000.0000.0000.0000.0111.1111.1111.1101 value    */
				/* 0000.0000.0000.0000.0111.1111.1111.1111 maxvalue */
				/* 1111.1111.1111.1111.1000.0000.0000.0000 ~maxvalue */
				*value |= int64(^maxv)
			}
		}
	} else if field != nil && field.offset != 0 /* J1939 Excess-K notation */ {
		*value += int64(field.offset)
		maxv += uint64(field.offset)
	}

	*maxValue = int64(maxv)

	logger.Debugf("extractNumber <%s> startBit=%d bits=%d value=%d max=%d", name, startBit, bits, *value, *maxValue)

	return true
}

func (ana *Analyzer) extractNumberNotEmpty(
	field *pgnField,
	data []byte,
	startBit int,
	bits int,
	value *int64,
	maxValue *int64,
) bool {
	var reserved int64

	if !extractNumber(field, data, startBit, bits, value, maxValue, ana.Logger) {
		return false
	}

	//nolint:gocritic
	if *maxValue >= 7 {
		reserved = 2 /* dataFieldError and dataFieldUnknown */
	} else if *maxValue > 1 {
		reserved = 1 /* dataFieldUnknown */
	} else {
		reserved = 0
	}

	if field.pgn != nil && field.pgn.repeatingField1 == field.order {
		ana.Logger.Debugf("The first repeating fieldset repeats %d times", *value)
		ana.variableFieldRepeat[0] = *value
	}

	if field.pgn != nil && field.pgn.repeatingField2 == field.order {
		ana.Logger.Debugf("The second repeating fieldset repeats %d times", *value)
		ana.variableFieldRepeat[1] = *value
	}

	ana.previousFieldValue = *value

	if *value > *maxValue-reserved {
		ana.printEmpty(*value - *maxValue)
		return false
	}

	return true
}

const (
	dataFieldUnknown   = 0
	dataFieldError     = -1
	dataFieldReserved1 = -2
	dataFieldReserved2 = -3
	dataFieldReserved3 = -4
)

func (ana *Analyzer) printEmpty(exceptionValue int64) {
	if ana.ShowJSON {
		if ana.ShowJSONEmpty {
			ana.pb.Printf("null")
		} else {
			ana.skip = true
		}
	} else {
		switch exceptionValue {
		case dataFieldUnknown:
			ana.pb.Printf("Unknown")
		case dataFieldError:
			ana.pb.Printf("ERROR")
		case dataFieldReserved1:
			ana.pb.Printf("RESERVED1")
		case dataFieldReserved2:
			ana.pb.Printf("RESERVED2")
		case dataFieldReserved3:
			ana.pb.Printf("RESERVED3")
		default:
			ana.pb.Printf("Unhandled value %d", exceptionValue)
		}
	}
}

func fieldPrintNumber(
	ana *Analyzer,
	field *pgnField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	var value int64
	var maxValue int64
	var a float64

	unit := field.unit
	resolution := field.resolution

	if resolution == 0.0 {
		resolution = 1.0
	}

	if !ana.extractNumberNotEmpty(field, data, startBit, *bits, &value, &maxValue) {
		return true, nil
	}

	logUnit := unit
	if logUnit == "" {
		logUnit = "None"
	}
	ana.Logger.Debugf("fieldPrintNumber <%s> value=%x max=%x resolution=%g offset=%g unit='%s'",
		fieldName,
		value,
		maxValue,
		resolution,
		field.unitOffset,
		logUnit)
	if resolution == 1.0 && field.unitOffset == 0.0 {
		ana.Logger.Debugf("fieldPrintNumber <%s> print as integer %d", fieldName, value)
		ana.pb.Printf("%d", value)
		if !ana.ShowJSON && unit != "" {
			ana.pb.Printf(" %s", unit)
		}
	} else {
		var precision int

		a = float64(value)*field.resolution + field.unitOffset

		precision = field.precision
		if precision == 0 {
			for r := field.resolution; (r > 0.0) && (r < 1.0); r *= 10.0 {
				precision++
			}
		}

		//nolint:gocritic
		if ana.ShowJSON {
			ana.pb.Printf("%.*f", precision, a)
		} else if unit != "" && unit == "m" && a >= 1000.0 {
			ana.pb.Printf("%.*f km", precision+3, a/1000)
		} else {
			ana.pb.Printf("%.*f", precision, a)
			if unit != "" {
				ana.pb.Printf(" %s", unit)
			}
		}
	}

	return true, nil
}

// Note(UNTESTED): See README.md.
func fieldPrintFloat(
	ana *Analyzer,
	field *pgnField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	data, adjusted := adjustDataLenStart(data, &startBit)
	if !adjusted {
		return false, nil
	}

	if *bits != 4 || startBit != 0 {
		ana.Logger.Errorf("field '%s' FLOAT value unhandled bits=%d startBit=%d", fieldName, *bits, startBit)
		return false, nil
	}
	if len(data) < 4 {
		return false, nil
	}

	ana.pb.Printf("%g", math.Float32frombits(binary.BigEndian.Uint32(data)))
	if !ana.ShowJSON && field.unit != "" {
		ana.pb.Printf(" %s", field.unit)
	}

	return true, nil
}

// Note(UNTESTED): See README.md.
func fieldPrintDecimal(
	ana *Analyzer,
	_ *pgnField,
	_ string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	bitMagnitude := uint8(1)

	data, adjusted := adjustDataLenStart(data, &startBit)
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
				ana.pb.Printf("%02d", value)
			}
			value = 0
			bitMagnitude = 1
		}
	}
	return true, nil
}

func fieldPrintLookup(
	ana *Analyzer,
	field *pgnField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	var s string

	var value int64
	var maxValue int64

	// Can't use extractNumberNotEmpty when the lookup key might use the 'error/unknown' values.
	if !extractNumber(field, data, startBit, *bits, &value, &maxValue, ana.Logger) {
		return true, nil
	}

	if field.unit != "" && field.unit[0] == '=' && unicode.IsDigit(rune(field.unit[1])) {
		lookfor := fmt.Sprintf("=%d", value)
		if lookfor != field.unit {
			ana.Logger.Debugf("Field %s value %d does not match %s", fieldName, value, field.unit[1:])
			ana.skip = true
			return false, nil
		}
		s = field.description
		if s == "" && field.lookup.lookupType == lookupTypeNone {
			s = lookfor[1:]
		}
	}

	if s == "" && field.lookup.lookupType != lookupTypeNone && value >= 0 {
		if field.lookup.lookupType == lookupTypePair || field.lookup.lookupType == lookupTypeFieldType {
			s = field.lookup.functionPair(int(value))
		} else if field.lookup.lookupType == lookupTypeTriplet {
			var val1 int64

			ana.Logger.Debugf("Triplet extraction for field '%s'", field.name)

			if field.pgn != nil && extractNumberByOrder(field.pgn, int(field.lookup.val1Order), data, &val1, ana.Logger) {
				s = field.lookup.functionTriplet(int(val1), int(value))
			}
		}
		// BIT is handled in fieldPrintBitLookup
	}

	if s != "" {
		//nolint:gocritic
		if ana.ShowJSONValue {
			ana.pb.Printf("%d,\"name\":\"%s\"}", value, s)
		} else if ana.ShowJSON {
			ana.pb.Printf("\"%s\"", s)
		} else {
			ana.pb.Printf("%s", s)
		}
	} else {
		maxValueBitCheck := int64(1)
		if *bits > 2 {
			maxValueBitCheck = 2
		}
		//nolint:gocritic
		if *bits > 1 && (value >= maxValue-maxValueBitCheck) {
			ana.printEmpty(value - maxValue)
		} else if ana.ShowJSONValue {
			ana.pb.Printf("%d", value)
			if ana.ShowJSONEmpty {
				ana.pb.Printf(",\"name\":null")
			}
			ana.pb.Printf("}")
		} else {
			ana.pb.Printf("%d", value)
		}
	}

	return true, nil
}

func fieldPrintBitLookup(
	ana *Analyzer,
	field *pgnField,
	_ string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	var value int64
	var maxValue int64
	var sep string

	if !extractNumber(field, data, startBit, *bits, &value, &maxValue, ana.Logger) {
		return true, nil
	}
	if value == 0 {
		if ana.ShowJSON {
			ana.printEmpty(value - maxValue)
		} else {
			ana.pb.Printf("None")
		}
		return true, nil
	}

	ana.Logger.Debugf("RES_BITFIELD length %d value %d", *bits, value)

	//nolint:gocritic
	if ana.ShowJSONValue {
		sep = "["
	} else if ana.ShowJSON {
		sep = "["
	} else {
		sep = ""
	}

	bit := 0
	for bitValue := int64(1); bit < *bits; bit++ {
		isSet := (value & bitValue) != 0
		ana.Logger.Debugf("RES_BITFIELD is bit %d value %d set? = %t", bit, bitValue, isSet)
		if isSet {
			s := field.lookup.functionPair(bit)

			if s != "" {
				//nolint:gocritic
				if ana.ShowJSONValue {
					ana.pb.Printf("%s{\"value\":%d,\"name\":\"%s\"}", sep, bitValue, s)
				} else if ana.ShowJSON {
					ana.pb.Printf("%s\"%s\"", sep, s)
				} else {
					ana.pb.Printf("%s%s", sep, s)
				}
			} else {
				if ana.ShowJSONValue {
					ana.pb.Printf("%s{\"value\":%d,\"name\":null}", sep, bitValue)
				} else {
					ana.pb.Printf("%s%d", sep, bitValue)
				}
			}
			sep = ","
		}
		bitValue <<= 1
	}
	if ana.ShowJSON {
		if sep[0] != '[' {
			ana.pb.Printf("]")
		} else {
			ana.pb.Printf("[]")
		}
	}
	return true, nil
}

func fieldPrintBinary(
	ana *Analyzer,
	field *pgnField,
	_ string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	var remainingBits int
	var s string

	data, adjusted := adjustDataLenStart(data, &startBit)
	if !adjusted {
		return false, nil
	}

	if *bits == 0 && field.fieldType == "BINARY" {
		// The length is in the previous field. This is heuristically defined right now, it might change.
		// The only PGNs where this happens are AIS PGNs 129792, 129795 and 129797.
		*bits = int(ana.previousFieldValue)
	}

	if startBit+*bits > len(data)*8 {
		*bits = len(data)*8 - startBit
	}

	if ana.ShowJSON {
		ana.pb.Printf("\"")
	}
	remainingBits = *bits
	s = ""
	for i := 0; i < (*bits+7)>>3; i++ {
		dataByte := data[i]

		if i == 0 && startBit != 0 {
			dataByte >>= startBit // Shift off older bits
			if remainingBits+startBit < 8 {
				dataByte &= ((1 << remainingBits) - 1)
			}
			dataByte <<= startBit // Shift zeros back in
			remainingBits -= (8 - startBit)
		} else {
			if remainingBits < 8 {
				// only the lower remainingBits should be used
				dataByte &= ((1 << remainingBits) - 1)
			}
			remainingBits -= 8
		}
		ana.pb.Printf("%s%2.02X", s, dataByte)
		s = " "
	}
	if ana.ShowJSON {
		ana.pb.Printf("\"")
	}
	return true, nil
}

/*
 * Only print reserved fields if they are NOT all ones, in that case we have an incorrect
 * PGN definition.
 */
func fieldPrintReserved(
	ana *Analyzer,
	field *pgnField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	var value int64
	var maxValue int64

	if !extractNumber(field, data, startBit, *bits, &value, &maxValue, ana.Logger) {
		return true, nil
	}
	if value == maxValue {
		ana.skip = true
		return true, nil
	}

	return fieldPrintBinary(ana, field, fieldName, data, startBit, bits)
}

/*
 * Only print spare fields if they are NOT all zeroes, in that case we have an incorrect
 * PGN definition.
 */
func fieldPrintSpare(
	ana *Analyzer,
	field *pgnField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	var value int64
	var maxValue int64

	if !extractNumber(field, data, startBit, *bits, &value, &maxValue, ana.Logger) {
		return true, nil
	}
	if value == 0 {
		ana.skip = true
		return true, nil
	}

	return fieldPrintBinary(ana, field, fieldName, data, startBit, bits)
}

// This is only a different printer than fieldPrintNumber so the JSON can contain a string value.
func fieldPrintMMSI(
	ana *Analyzer,
	field *pgnField,
	_ string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	var value int64
	var maxValue int64

	if !ana.extractNumberNotEmpty(field, data, startBit, *bits, &value, &maxValue) {
		return true, nil
	}

	ana.pb.Printf("\"%09d\"", uint32(value))
	return true, nil
}

// Note(UNTESTED): See README.md.
func fieldPrintKeyValue(
	ana *Analyzer,
	field *pgnField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	var r bool

	if ana.length != 0 {
		*bits = int(ana.length * 8)
	} else {
		*bits = int(field.size)
	}
	ana.Logger.Debugf("fieldPrintKeyValue('%s') bits=%d", fieldName, *bits)

	if len(data) >= ((startBit + *bits) >> 3) {
		if ana.ftf != nil {
			f := ana.ftf

			ana.Logger.Debugf("fieldPrintKeyValue('%s') is actually a '%s' field bits=%d", fieldName, f.ft.name, f.size)

			if *bits == 0 {
				*bits = int(f.size)
			}
			if *bits == 0 && f.ft != nil && f.ft.name != "" && f.ft.name == "LOOKUP" {
				*bits = f.lookup.size
			}

			var err error
			r, err = f.ft.pf(ana, f, fieldName, data, startBit, bits)
			if err != nil {
				return false, err
			}
		} else {
			var err error
			r, err = fieldPrintBinary(ana, field, fieldName, data, startBit, bits)
			if err != nil {
				return false, err
			}
		}
	} else {
		var pgn uint32
		if field.pgn != nil {
			pgn = field.pgn.pgn
		}
		ana.Logger.Errorf("PGN %d key-value has insufficient bytes for field %s", pgn, fieldName)
	}

	ana.ftf = nil
	ana.length = 0

	return r, nil
}

func fieldPrintLatLon(
	ana *Analyzer,
	field *pgnField,
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

	ana.Logger.Debugf("fieldPrintLatLon for '%s' startbit=%d bits=%d", fieldName, startBit, *bits)

	if !ana.extractNumberNotEmpty(field, data, startBit, *bits, &value, &maxValue) {
		return true, nil
	}

	if value < 0 {
		absVal = uint64(-value)
	} else {
		absVal = uint64(value)
	}
	dd = float64(value) * field.resolution

	if ana.ShowGeo == geoFormatDD {
		ana.pb.Printf("%10.7f", dd)
	} else {
		if ana.ShowJSONValue {
			ana.pb.Printf("%d,\"name\":", value)
		}
		if ana.ShowGeo == geoFormatDM {
			dd = float64(absVal) * field.resolution
			degrees = math.Floor(dd)
			remainder = dd - degrees
			minutes = remainder * 60.

			fmtStr := "%02dd %6.3f %c"
			if ana.ShowJSON {
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
			ana.pb.Printf(fmtStr,
				uint32(degrees),
				minutes,
				dir)
		} else {
			dd = float64(absVal) * field.resolution
			degrees = math.Floor(dd)
			remainder = dd - degrees
			minutes = math.Floor(remainder * 60.)
			seconds = math.Floor(remainder*3600.) - 60.*minutes

			fmtStr := "%02dd %02d' %06.3f\"%c"
			if ana.ShowJSON {
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
			ana.pb.Printf(fmtStr,
				int(degrees),
				int(minutes),
				seconds,
				dir)
		}
		if ana.ShowJSONValue {
			ana.pb.Printf("}")
		}
	}
	return true, nil
}

func fieldPrintDate(
	ana *Analyzer,
	_ *pgnField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	var d uint16

	data, adjusted := adjustDataLenStart(data, &startBit)
	if !adjusted {
		return false, nil
	}

	if startBit != 0 {
		return unhandledStartOffset(fieldName, startBit, ana.Logger), nil
	}
	if *bits != 16 {
		return unhandledBitLength(fieldName, *bits, ana.Logger), nil
	}
	if len(data) < *bits/8 {
		return true, nil
	}

	d = uint16(data[0]) + (uint16(data[1]) << 8)

	if d >= 0xfffd {
		ana.printEmpty(int64(d) - int64(0xffff))
		return true, nil
	}

	tm := time.Unix(int64(d)*86400, 0).UTC()
	formatted := tm.Format("2006.01.02")
	if ana.ShowJSON {
		if ana.ShowJSONValue {
			ana.pb.Printf("%d,\"name\":\"%s\"}", d, formatted)
		} else {
			ana.pb.Printf("\"%s\"", formatted)
		}
	} else {
		ana.pb.Printf("%s", formatted)
	}
	return true, nil
}

/**
 * Fixed length string where the length is defined by the field definition.
 */
func fieldPrintStringFix(
	ana *Analyzer,
	field *pgnField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	dataLen := int(field.size) / 8

	data, adjusted := adjustDataLenStart(data, &startBit)
	if !adjusted {
		return false, nil
	}

	ana.Logger.Debugf("fieldPrintStringFix('%s',%d) size=%d", fieldName, len(data), dataLen)

	dataLen = common.Min(dataLen, len(data)) // Cap length to remaining bytes in message
	*bits = 8 * dataLen
	return ana.printString(data[:dataLen])
}

// Note(UNTESTED): See README.md.
func fieldPrintStringLZ(
	ana *Analyzer,
	_ *pgnField,
	_ string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	// STRINGLZ format is <specifiedDataLen> [ <data> ... ]
	var dataLen int

	data, adjusted := adjustDataLenStart(data, &startBit)
	if !adjusted {
		return false, nil
	}
	dataLen = len(data)

	// Cap to dataLen
	specifiedDataLen := data[0]
	data = data[1:]
	specifiedDataLen = common.Min(specifiedDataLen, byte(dataLen-1))
	*bits = int(8 * (specifiedDataLen + 1))

	return ana.printString(data[:specifiedDataLen])
}

func fieldPrintStringLAU(
	ana *Analyzer,
	_ *pgnField,
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

	data, adjusted := adjustDataLenStart(data, &startBit)
	if !adjusted {
		return false, nil
	}
	dataLen := len(data)
	ana.Logger.Debugf("fieldPrintStringLAU: <%s> data=%p len=%d startBit=%d bits=%d", fieldName, data, len(data), startBit, *bits)

	specifiedDataLen = int(data[0])
	control = int(data[1])
	data = data[2:]
	if specifiedDataLen < 2 || dataLen < 2 {
		ana.Logger.Errorf("field '%s': Invalid string length %d in STRINana.LAU field", fieldName, specifiedDataLen)
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
		ana.Logger.Debugf("fieldprintStringLAU: UTF16 len %d requires %d utf8 bytes", specifiedDataLen/2, len(utf8Str))
		data = []byte(utf8Str)
		specifiedDataLen = len(data)
	} else if control > 1 {
		ana.Logger.Errorf("Unhandled string type %d in PGN", control)
		return false, nil
	}

	return ana.printString(data[:specifiedDataLen])
}

func fieldPrintTime(
	ana *Analyzer,
	field *pgnField,
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

	if !ana.extractNumberNotEmpty(field, data, startBit, *bits, &value, &maxValue) {
		return true, nil
	}

	ana.Logger.Debugf("fieldPrintTime(<%s>, \"%s\") v=%d res=%g max=0x%d",
		field.name,
		fieldName,
		value,
		field.resolution,
		maxValue)

	if value < 0 {
		value = -value
		sign = "-"
	}

	if field.resolution < 1.0 {
		unitspersecond = uint64(1.0 / field.resolution)
	} else {
		unitspersecond = 1
		value *= int64(field.resolution)
	}

	t = uint64(value)
	seconds = uint32(t / unitspersecond)
	units = uint32(t % unitspersecond)
	minutes = seconds / 60
	seconds %= 60
	hours = minutes / 60
	minutes %= 60

	digits = int(math.Log10(float64(unitspersecond)))

	if ana.ShowJSON {
		if ana.ShowJSONValue {
			ana.pb.Printf("%s%d,\"name\":", sign, value)
		}
		if units != 0 {
			ana.pb.Printf("\"%s%02d:%02d:%02d.%0*d\"", sign, hours, minutes, seconds, digits, units)
		} else {
			ana.pb.Printf("\"%s%02d:%02d:%02d\"", sign, hours, minutes, seconds)
		}
		if ana.ShowJSONValue {
			ana.pb.Printf("}")
		}
	} else {
		if units != 0 {
			ana.pb.Printf("%s%02d:%02d:%02d.%0*d", sign, hours, minutes, seconds, digits, units)
		} else {
			ana.pb.Printf("%s%02d:%02d:%02d", sign, hours, minutes, seconds)
		}
	}
	return true, nil
}

func unhandledStartOffset(fieldName string, startBit int, logger logging.Logger) bool {
	//nolint:errcheck
	logger.Error("Field '%s' cannot start on bit %d", fieldName, startBit)
	return false
}

func unhandledBitLength(fieldName string, length int, logger logging.Logger) bool {
	//nolint:errcheck
	logger.Error("Field '%s' cannot have size %d", fieldName, length)
	return false
}

func (ana *Analyzer) printASCIIJSONEscaped(data []byte) {
	for _, c := range string(data) {
		switch c {
		case '\b':
			ana.pb.Printf("%s", "\\b")

		case '\n':
			ana.pb.Printf("%s", "\\n")

		case '\r':
			ana.pb.Printf("%s", "\\r")

		case '\t':
			ana.pb.Printf("%s", "\\t")

		case '\f':
			ana.pb.Printf("%s", "\\f")

		case '"':
			ana.pb.Printf("%s", "\\\"")

		case '\\':
			ana.pb.Printf("%s", "\\\\")

		case '/':
			ana.pb.Printf("%s", "\\/")

		case '\377':
			// 0xff has been seen on recent Simrad VHF systems, and it seems to indicate
			// end-of-field, with noise following. Assume this does not break other systems.
			return

		default:
			if c > 0x00 {
				ana.pb.Printf("%c", c)
			}
		}
	}
}

func (ana *Analyzer) printString(data []byte) (bool, error) {
	var lastbyte *byte

	dataLen := len(data)
	if dataLen > 0 {
		// rtrim funny stuff from end, we see all sorts
		lastbyte = &data[len(data)-1]
		lastbyteCount := 0
		for dataLen > 0 && (*lastbyte == 0xff || unicode.IsSpace(rune(*lastbyte)) || *lastbyte == 0 || *lastbyte == '@') {
			dataLen--
			lastbyteCount++
			lastbyte = &data[len(data)-1-lastbyteCount]
		}
	}

	if dataLen == 0 {
		ana.printEmpty(dataFieldUnknown)
		return true, nil
	}

	if ana.ShowJSON {
		ana.pb.Printf("\"")
		ana.printASCIIJSONEscaped(data[:dataLen])
		ana.pb.Printf("\"")
	} else {
		ana.printASCIIJSONEscaped(data[:dataLen])
	}

	return true, nil
}
