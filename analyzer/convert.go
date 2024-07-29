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
	"math"
	"time"
	"unicode"
	"unicode/utf16"

	"go.viam.com/rdk/logging"

	"github.com/erh/gonmea/common"
)

func convertFieldNumber(
	ana *analyzerImpl,
	field *PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (interface{}, bool, error) {
	var value int64
	var maxValue int64

	unit := field.Unit
	resolution := field.Resolution

	if resolution == 0.0 {
		resolution = 1.0
	}

	if ok, _ := ana.ExtractNumberNotEmpty(field, data, startBit, *bits, &value, &maxValue); !ok {
		return nil, false, nil
	}

	logUnit := unit
	if logUnit == "" {
		logUnit = "None"
	}
	ana.Logger.Debugf("convertFieldNumber <%s> value=%x max=%x resolution=%g offset=%g unit='%s'",
		fieldName,
		value,
		maxValue,
		resolution,
		field.UnitOffset,
		logUnit)
	if resolution == 1.0 && field.UnitOffset == 0.0 {
		ana.Logger.Debugf("convertFieldNumber <%s> print as integer %d", fieldName, value)
		return int(value), true, nil
	}
	return float64(value)*field.Resolution + field.UnitOffset, true, nil
}

// Note(UNTESTED): See README.md.
func convertFieldFloat(
	ana *analyzerImpl,
	field *PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (interface{}, bool, error) {
	data, adjusted := AdjustDataLenStart(data, &startBit)
	if !adjusted {
		return nil, false, nil
	}

	if *bits != 4 || startBit != 0 {
		ana.Logger.Errorf("field '%s' FLOAT value unhandled bits=%d startBit=%d", fieldName, *bits, startBit)
		return nil, false, nil
	}
	if len(data) < 4 {
		return nil, false, nil
	}

	return float64(math.Float32frombits(binary.BigEndian.Uint32(data))), true, nil
}

// Note(UNTESTED): See README.md.
func convertFieldDecimal(
	ana *analyzerImpl,
	_ *PGNField,
	_ string,
	data []byte,
	startBit int,
	bits *int,
) (interface{}, bool, error) {
	bitMagnitude := uint8(1)

	data, adjusted := AdjustDataLenStart(data, &startBit)
	if !adjusted {
		return nil, false, nil
	}

	bitMask := byte(1 << startBit)

	if startBit+*bits > len(data)*8 {
		*bits = len(data)*8 - startBit
	}

	var totalValue int
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
				totalValue = (totalValue * 10) + int(value)
			}
			value = 0
			bitMagnitude = 1
		}
	}
	return totalValue, true, nil
}

func convertFieldLookup(
	ana *analyzerImpl,
	field *PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (interface{}, bool, error) {
	var s string

	var value int64
	var maxValue int64

	// Can't use ExtractNumberNotEmpty when the lookup key might use the 'error/unknown' values.
	if !ExtractNumber(field, data, startBit, *bits, &value, &maxValue, ana.Logger) {
		return nil, false, nil
	}

	if field.Unit != "" && field.Unit[0] == '=' && unicode.IsDigit(rune(field.Unit[1])) {
		lookfor := fmt.Sprintf("=%d", value)
		if lookfor != field.Unit {
			ana.Logger.Debugf("Field %s value %d does not match %s", fieldName, value, field.Unit[1:])
			ana.state.Skip = true
			return nil, false, nil
		}
		s = field.Description
		if s == "" && field.Lookup.LookupType == LookupTypeNone {
			s = lookfor[1:]
		}
	}

	if s == "" && field.Lookup.LookupType != LookupTypeNone && value >= 0 {
		if field.Lookup.LookupType == LookupTypePair || field.Lookup.LookupType == LookupTypeFieldType {
			s = field.Lookup.FunctionPair(int(value))
		} else if field.Lookup.LookupType == LookupTypeTriplet {
			var val1 int64

			ana.Logger.Debugf("Triplet extraction for field '%s'", field.Name)

			if field.PGN != nil && ExtractNumberByOrder(field.PGN, int(field.Lookup.Val1Order), data, &val1, ana.Logger) {
				s = field.Lookup.FunctionTriplet(int(val1), int(value))
			}
		}
		// BIT is handled in convertFieldBitLookup
	}

	if s != "" {
		return s, true, nil
	}
	maxValueBitCheck := int64(1)
	if *bits > 2 {
		maxValueBitCheck = 2
	}

	if *bits > 1 && (value >= maxValue-maxValueBitCheck) {
		return nil, false, nil
	}

	return int(value), true, nil
}

func convertFieldBitLookup(
	ana *analyzerImpl,
	field *PGNField,
	_ string,
	data []byte,
	startBit int,
	bits *int,
) (interface{}, bool, error) {
	var value int64
	var maxValue int64

	if !ExtractNumber(field, data, startBit, *bits, &value, &maxValue, ana.Logger) {
		return nil, false, nil
	}
	if value == 0 {
		return nil, false, nil
	}

	ana.Logger.Debugf("RES_BITFIELD length %d value %d", *bits, value)

	values := make([]interface{}, 0, *bits)
	bit := 0
	for bitValue := int64(1); bit < *bits; bit++ {
		isSet := (value & bitValue) != 0
		ana.Logger.Debugf("RES_BITFIELD is bit %d value %d set? = %t", bit, bitValue, isSet)
		if isSet {
			s := field.Lookup.FunctionPair(bit)

			if s != "" {
				values = append(values, s)
			} else {
				values = append(values, bitValue)
			}
		}
		bitValue <<= 1
	}
	return values, true, nil
}

func convertFieldBinary(
	ana *analyzerImpl,
	field *PGNField,
	_ string,
	data []byte,
	startBit int,
	bits *int,
) (interface{}, bool, error) {
	var remainingBits int

	data, adjusted := AdjustDataLenStart(data, &startBit)
	if !adjusted {
		return nil, false, nil
	}

	if *bits == 0 && field.FieldType == "BINARY" {
		// The length is in the previous field. This is heuristically defined right now, it might change.
		// The only PGNs where this happens are AIS PGNs 129792, 129795 and 129797.
		*bits = int(ana.state.PreviousFieldValue)
	}

	if startBit+*bits > len(data)*8 {
		*bits = len(data)*8 - startBit
	}

	remainingBits = *bits
	convertedData := make([]byte, 0, (*bits+7)>>3)
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
		convertedData = append(convertedData, dataByte)
	}
	return convertedData, true, nil
}

/*
 * Only print reserved fields if they are NOT all ones, in that case we have an incorrect
 * PGN definition.
 */
func convertFieldReserved(
	ana *analyzerImpl,
	field *PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (interface{}, bool, error) {
	var value int64
	var maxValue int64

	if !ExtractNumber(field, data, startBit, *bits, &value, &maxValue, ana.Logger) {
		return nil, false, nil
	}
	if value == maxValue {
		ana.state.Skip = true
		return nil, false, nil
	}

	return convertFieldBinary(ana, field, fieldName, data, startBit, bits)
}

/*
 * Only print spare fields if they are NOT all zeroes, in that case we have an incorrect
 * PGN definition.
 */
func convertFieldSpare(
	ana *analyzerImpl,
	field *PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (interface{}, bool, error) {
	var value int64
	var maxValue int64

	if !ExtractNumber(field, data, startBit, *bits, &value, &maxValue, ana.Logger) {
		return nil, false, nil
	}
	if value == 0 {
		ana.state.Skip = true
		return nil, false, nil
	}

	return convertFieldBinary(ana, field, fieldName, data, startBit, bits)
}

// This is only a different printer than convertFieldNumber so the JSON can contain a string value.
func convertFieldMMSI(
	ana *analyzerImpl,
	field *PGNField,
	_ string,
	data []byte,
	startBit int,
	bits *int,
) (interface{}, bool, error) {
	var value int64
	var maxValue int64

	if ok, _ := ana.ExtractNumberNotEmpty(field, data, startBit, *bits, &value, &maxValue); !ok {
		return nil, false, nil
	}

	return int(value), true, nil
}

// Note(UNTESTED): See README.md.
func convertFieldKeyValue(
	ana *analyzerImpl,
	field *PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (interface{}, bool, error) {
	if ana.state.Length != 0 {
		*bits = int(ana.state.Length * 8)
	} else {
		*bits = int(field.Size)
	}
	ana.Logger.Debugf("convertFieldKeyValue('%s') bits=%d", fieldName, *bits)

	var val interface{}
	var ok bool
	if len(data) >= ((startBit + *bits) >> 3) {
		if ana.state.FTF != nil {
			f := ana.state.FTF

			ana.Logger.Debugf("convertFieldKeyValue('%s') is actually a '%s' field bits=%d", fieldName, f.FT.Name, f.Size)

			if *bits == 0 {
				*bits = int(f.Size)
			}
			if *bits == 0 && f.FT != nil && f.FT.Name != "" && f.FT.Name == "LOOKUP" {
				*bits = f.Lookup.Size
			}

			var err error
			val, ok, err = f.FT.CF(ana, f, fieldName, data, startBit, bits)
			if err != nil {
				return nil, false, err
			}
		} else {
			var err error
			val, ok, err = convertFieldBinary(ana, field, fieldName, data, startBit, bits)
			if err != nil {
				return nil, false, err
			}
		}
	} else {
		var pgn uint32
		if field.PGN != nil {
			pgn = field.PGN.PGN
		}
		ana.Logger.Errorf("PGN %d key-value has insufficient bytes for field %s", pgn, fieldName)
	}

	ana.state.FTF = nil
	ana.state.Length = 0

	if !ok {
		return nil, false, nil
	}
	return val, true, nil
}

func convertFieldLatLon(
	ana *analyzerImpl,
	field *PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (interface{}, bool, error) {
	var value int64
	var maxValue int64
	var dd float64

	ana.Logger.Debugf("convertFieldLatLon for '%s' startbit=%d bits=%d", fieldName, startBit, *bits)

	if ok, _ := ana.ExtractNumberNotEmpty(field, data, startBit, *bits, &value, &maxValue); !ok {
		return nil, false, nil
	}

	dd = float64(value) * field.Resolution

	return dd, true, nil
}

func UnhandledStartOffset(fieldName string, startBit int, logger logging.Logger) bool {
	logger.Error("Field '%s' cannot start on bit %d", fieldName, startBit)
	return false
}

func UnhandledBitLength(fieldName string, length int, logger logging.Logger) bool {
	logger.Error("Field '%s' cannot have size %d", fieldName, length)
	return false
}

func convertFieldDate(
	ana *analyzerImpl,
	_ *PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (interface{}, bool, error) {
	var d uint16

	data, adjusted := AdjustDataLenStart(data, &startBit)
	if !adjusted {
		return nil, false, nil
	}

	if startBit != 0 {
		UnhandledStartOffset(fieldName, startBit, ana.Logger)
		return nil, false, nil
	}
	if *bits != 16 {
		UnhandledBitLength(fieldName, *bits, ana.Logger)
		return nil, false, nil
	}
	if len(data) < *bits/8 {
		return nil, false, nil
	}

	d = uint16(data[0]) + (uint16(data[1]) << 8)

	if d >= 0xfffd {
		return nil, false, nil
	}

	return time.Unix(int64(d)*86400, 0).UTC(), true, nil
}

func convertString(data []byte) (string, bool) {
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
		return "", false
	}

	return string(data[:dataLen]), true
}

/**
 * Fixed length string where the length is defined by the field definition.
 */
func convertFieldStringFix(
	ana *analyzerImpl,
	field *PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (interface{}, bool, error) {
	dataLen := int(field.Size) / 8

	data, adjusted := AdjustDataLenStart(data, &startBit)
	if !adjusted {
		return nil, false, nil
	}

	ana.Logger.Debugf("convertFieldStringFix('%s',%d) size=%d", fieldName, len(data), dataLen)

	dataLen = common.Min(dataLen, len(data)) // Cap length to remaining bytes in message
	*bits = 8 * dataLen
	val, ok := convertString(data[:dataLen])
	if !ok {
		return nil, false, nil
	}
	return val, true, nil
}

// Note(UNTESTED): See README.md.
func convertFieldStringLZ(
	ana *analyzerImpl,
	_ *PGNField,
	_ string,
	data []byte,
	startBit int,
	bits *int,
) (interface{}, bool, error) {
	// STRINGLZ format is <specifiedDataLen> [ <data> ... ]
	var dataLen int

	data, adjusted := AdjustDataLenStart(data, &startBit)
	if !adjusted {
		return nil, false, nil
	}
	dataLen = len(data)

	// Cap to dataLen
	specifiedDataLen := data[0]
	data = data[1:]
	specifiedDataLen = common.Min(specifiedDataLen, byte(dataLen-1))
	*bits = int(8 * (specifiedDataLen + 1))

	val, ok := convertString(data[:specifiedDataLen])
	if !ok {
		return nil, false, nil
	}
	return val, true, nil
}

func convertFieldStringLAU(
	ana *analyzerImpl,
	_ *PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (interface{}, bool, error) {
	// STRINGLAU format is <len> <control> [ <data> ... ]
	// where <control> == 0 = UTF16
	//       <control> == 1 = ASCII(?) or maybe UTF8?
	var control int
	var specifiedDataLen int

	data, adjusted := AdjustDataLenStart(data, &startBit)
	if !adjusted {
		return nil, false, nil
	}
	dataLen := len(data)
	ana.Logger.Debugf("convertFieldStringLAU: <%s> data=%p len=%d startBit=%d bits=%d", fieldName, data, len(data), startBit, *bits)

	specifiedDataLen = int(data[0])
	control = int(data[1])
	data = data[2:]
	if specifiedDataLen < 2 || dataLen < 2 {
		ana.Logger.Errorf("field '%s': Invalid string length %d in STRINana.LAU field", fieldName, specifiedDataLen)
		return nil, false, nil
	}
	specifiedDataLen = common.Min(specifiedDataLen, dataLen) - 2

	*bits = 8 * (specifiedDataLen + 2)

	if control == 0 {
		utf16Data := make([]uint16, specifiedDataLen/2)
		//nolint:errcheck
		_ = binary.Read(bytes.NewReader(data), binary.LittleEndian, &utf16Data)
		utf16Str := utf16.Decode(utf16Data)
		utf8Str := string(utf16Str)
		ana.Logger.Debugf("convertFieldStringLAU: UTF16 len %d requires %d utf8 bytes", specifiedDataLen/2, len(utf8Str))
		data = []byte(utf8Str)
		specifiedDataLen = len(data)
	} else if control > 1 {
		ana.Logger.Errorf("Unhandled string type %d in PGN", control)
		return nil, false, nil
	}

	val, ok := convertString(data[:specifiedDataLen])
	if !ok {
		return nil, false, nil
	}
	return val, true, nil
}

func convertFieldTime(
	ana *analyzerImpl,
	field *PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (interface{}, bool, error) {
	var unitspersecond uint64
	var hours uint32
	var minutes uint32
	var seconds uint32
	var value int64
	var maxValue int64
	var t uint64

	positive := true

	if ok, _ := ana.ExtractNumberNotEmpty(field, data, startBit, *bits, &value, &maxValue); !ok {
		return nil, false, nil
	}

	ana.Logger.Debugf("convertFieldTime(<%s>, \"%s\") v=%d res=%g max=0x%d",
		field.Name,
		fieldName,
		value,
		field.Resolution,
		maxValue)

	if value < 0 {
		value = -value
		positive = false
	}

	if field.Resolution < 1.0 {
		unitspersecond = uint64(1.0 / field.Resolution)
	} else {
		unitspersecond = 1
		value *= int64(field.Resolution)
	}

	t = uint64(value)
	seconds = uint32(t / unitspersecond)
	minutes = seconds / 60
	seconds %= 60
	hours = minutes / 60
	minutes %= 60

	// Note(erd): this loses the units remainder
	dur := time.Hour*time.Duration(hours) +
		time.Minute*time.Duration(minutes) +
		time.Second*time.Duration(seconds)
	if !positive {
		dur *= -1
	}
	return dur, true, nil
}

func convertFieldVariable(
	ana *analyzerImpl,
	_ *PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (interface{}, bool, error) {
	refField := ana.GetField(uint32(ana.state.RefPgn), uint32(data[startBit/8-1]-1))
	if refField != nil {
		ana.Logger.Debugf("Field %s: found variable field %d '%s'", fieldName, ana.state.RefPgn, refField.Name)
		val, ok, err := ana.convertField(refField, fieldName, data, startBit, bits)
		if err != nil {
			return nil, false, err
		}
		*bits = (*bits + 7) & ^0x07 // round to bytes
		if !ok {
			return nil, false, nil
		}
		return val, true, nil
	}

	ana.Logger.Errorf("Field %s: cannot derive variable length for PGN %d field # %d", fieldName, ana.state.RefPgn, data[len(data)-1])
	*bits = 8 /* Gotta assume something */
	return nil, false, nil
}
