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
	"math"
	"strconv"
	"unicode"

	"github.com/erh/gonmea/common"
)

const (
	lenVariable         = 0
	resLatLongPrecision = 10000000 /* 1e7 */
	resLatLong          = 1.0e-7
	resLatLong64        = 1.0e-16
	resPercentage       = 100.0 / 25000.0
	resRadians          = 1e-4
	resRotation         = 1e-3 / 32.0
	resHiresRotation    = 1e-6 / 32.0
)

type packetStatus byte

const (
	packetStatusComplete             packetStatus = 0
	packetStatusFieldsUnknown        packetStatus = 1
	packetStatusFieldLengthsUnknown  packetStatus = 2
	packetStatusResolutionUnknown    packetStatus = 4
	packetStatusLookupsUnknown       packetStatus = 8
	packetStatusNotSeen              packetStatus = 16
	packetStatusIntervalUnknown      packetStatus = 32
	packetStatusMissingcompanyFields packetStatus = 64
)

const (
	packetStatusIncomplete       = (packetStatusFieldsUnknown | packetStatusFieldLengthsUnknown | packetStatusResolutionUnknown)
	packetStatusIncompleteLookup = (packetStatusIncomplete | packetStatusLookupsUnknown)
	packetStatusPDFOnly          = (packetStatusFieldLengthsUnknown |
		packetStatusResolutionUnknown |
		packetStatusLookupsUnknown |
		packetStatusNotSeen)
)

type packetType byte

const (
	packetTypeSingle packetType = iota
	packetTypeFast
	packetTypeISOTP
	packetTypeMixed
)

func (pt packetType) String() string {
	switch pt {
	case packetTypeSingle:
		return "Single"
	case packetTypeFast:
		return "Fast"
	case packetTypeISOTP:
		return "ISO"
	case packetTypeMixed:
		return "Mixed"
	default:
		return "UNKNOWN"
	}
}

type pgnField struct {
	name      string
	fieldType string

	size        uint32 /* Size in bits. All fields are contiguous in message; use 'reserved' fields to fill in empty bits. */
	unit        string /* String containing the 'Dimension' (e.g. s, h, m/s, etc.) */
	description string

	offset int32 /* Only used for SAE J1939 values with sign; these are in Offset/Excess-K notation instead
	 *    of two's complement as used by NMEA 2000.
	 *    See http://en.wikipedia.org/wiki/Offset_binary
	 */
	resolution  float64 /* Either a positive real value or zero */
	precision   int     /* How many decimal digits after the decimal point to print; usually 0 = automatic */
	unitOffset  float64 /* Only used for K.C conversion in non-SI print */
	proprietary bool    /* Field is only present if earlier PGN field is in proprietary range */
	hasSign     bool    /* Is the value signed, e.g. has both positive and negative values? */

	/* The following fields are filled by C, no need to set in initializers */
	order uint8
	//nolint:unused
	bitOffset int // Bit offset from start of data, e.g. lower 3 bits = bit#, bit 4.. is byte offset
	camelName string
	lookup    lookupInfo
	ft        *fieldType
	pgn       *pgnInfo
	rangeMin  float64
	rangeMax  float64
}

type pgnInfo struct {
	description      string
	pgn              uint32
	complete         packetStatus /* Either packetStatusComplete or bit values set for various unknown items */
	packetType       packetType   /* Single, Fast or ISO_TP */
	fieldList        [33]pgnField /* Note fixed # of fields; increase if needed. RepeatingFields support means this is enough for now. */
	fieldCount       uint32       /* Filled by C, no need to set in initializers. */
	camelDescription string       /* Filled by C, no need to set in initializers. */
	fallback         bool         /* true = this is a catch-all for unknown PGNs */
	hasMatchFields   bool         /* true = there are multiple PGNs with same PRN */
	explanation      string       /* Preferably the NMEA 2000 explanation from the NMEA PGN field list */
	url              string       /* External URL */
	interval         uint16       /* Milliseconds between transmissions, standard. 0 is: not known, math.MaxUint16 = never */
	repeatingCount1  uint8        /* How many fields repeat in set 1? */
	repeatingCount2  uint8        /* How many fields repeat in set 2? */
	repeatingStart1  uint8        /* At which field does the first set start? */
	repeatingStart2  uint8        /* At which field does the second set start? */
	repeatingField1  uint8        /* Which field explains how often the repeating fields set #1 repeats? 255 = there is no field */
	repeatingField2  uint8        /* Which field explains how often the repeating fields set #2 repeats? 255 = there is no field */
}

func lookupField(nam string, dataLen uint32, typ string) pgnField {
	return pgnField{
		name:       nam,
		size:       dataLen,
		resolution: 1,
		hasSign:    false,
		lookup: lookupInfo{
			lookupType:   lookupTypePair,
			functionPair: lookupFunctionPairForTyp[typ],
			name:         typ,
		},
		fieldType: "LOOKUP",
	}
}

func lookupFieldtypeField(nam string, dataLen uint32, typ string) pgnField {
	return pgnField{
		name:       nam,
		size:       dataLen,
		resolution: 1,
		hasSign:    false,
		lookup: lookupInfo{
			lookupType:   lookupTypeFieldType,
			functionPair: lookupFunctionPairForTyp[typ],
			name:         typ,
		},
		fieldType: "FIELDTYPE_LOOKUP",
	}
}

func lookupTripletField(nam string, dataLen uint32, typ, desc string, order uint8) pgnField {
	return pgnField{
		name:       nam,
		size:       dataLen,
		resolution: 1,
		hasSign:    false,
		lookup: lookupInfo{
			lookupType:      lookupTypeTriplet,
			functionTriplet: lookupFunctionTripletForTyp[typ],
			name:            typ,
			val1Order:       order,
		},
		fieldType:   "INDIRECT_LOOKUP",
		description: desc,
	}
}

func lookupFieldDesc(nam string, dataLen uint32, typ, desc string) pgnField {
	return pgnField{
		name:       nam,
		size:       dataLen,
		resolution: 1,
		hasSign:    false,
		lookup: lookupInfo{
			lookupType:   lookupTypePair,
			functionPair: lookupFunctionPairForTyp[typ],
			name:         typ,
		},
		fieldType:   "LOOKUP",
		description: desc,
	}
}

func bitlookupField(nam string, dataLen uint32, typ string) pgnField {
	return pgnField{
		name:       nam,
		size:       dataLen,
		resolution: 1,
		hasSign:    false,
		lookup: lookupInfo{
			lookupType:   lookupTypeBit,
			functionPair: lookupFunctionPairForTyp[typ],
			name:         typ,
		},
		fieldType: "BITLOOKUP",
	}
}

//nolint:unused
func fieldtypeLookup(nam string, dataLen uint32, typ string) pgnField {
	return pgnField{
		name:       nam,
		size:       dataLen,
		resolution: 1,
		hasSign:    false,
		lookup: lookupInfo{
			lookupType:   lookupTypeFieldType,
			functionPair: lookupFunctionPairForTyp[typ],
			name:         typ,
		},
		fieldType: "LOOKUP_TYPE_FIELDTYPE",
	}
}

//nolint:unused
func unknownLookupField(nam string, dataLen uint32) pgnField {
	return pgnField{
		name:       nam,
		size:       dataLen,
		resolution: 1,
		hasSign:    false,
		lookup: lookupInfo{
			lookupType: lookupTypePair,
		},
		fieldType: "LOOKUP",
	}
}

func spareNamedField(nam string, dataLen uint32) pgnField {
	return pgnField{
		name: nam, size: dataLen, resolution: 1, fieldType: "SPARE",
	}
}

func spareField(dataLen uint32) pgnField {
	return spareNamedField("Spare", dataLen)
}

func reservedField(dataLen uint32) pgnField {
	return pgnField{
		name: "Reserved", size: dataLen, resolution: 1, fieldType: "RESERVED",
	}
}

func reservedPropField(dataLen uint32, desc string) pgnField {
	return pgnField{
		name: "Reserved", size: dataLen, resolution: 1, description: desc, fieldType: "RESERVED", proprietary: true,
	}
}

func binaryField(nam string, dataLen uint32, desc string) pgnField {
	return pgnField{
		name: nam, size: dataLen, resolution: 1, description: desc, fieldType: "BINARY",
	}
}

//nolint:unused
func binaryUnitField(nam string, dataLen uint32, unt, desc string, prop bool) pgnField {
	return pgnField{
		name: nam, size: dataLen, resolution: 1, unit: unt, description: desc, proprietary: prop, fieldType: "BINARY",
	}
}

func latitudeI32Field(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 4, resolution: 1e-7, hasSign: true, unit: "deg", fieldType: "GEO_FIX32",
	}
}

func latitudeI64Field(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 8, resolution: 1e-16, hasSign: true, unit: "deg", fieldType: "GEO_FIX64",
	}
}

func longitudeI32Field(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 4, resolution: 1e-7, hasSign: true, unit: "deg", fieldType: "GEO_FIX32",
	}
}

func longitudeI64Field(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 8, resolution: 1e-16, hasSign: true, unit: "deg", fieldType: "GEO_FIX64",
	}
}

func angleU16Field(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: resRadians, hasSign: false, unit: "rad", description: desc,
		fieldType: "ANGLE_UFIX16",
	}
}

func angleI16Field(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: resRadians, hasSign: true, unit: "rad", description: desc,
		fieldType: "ANGLE_FIX16",
	}
}

func int32Field(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 4, resolution: 1, hasSign: true, fieldType: "INT32", description: desc,
	}
}

// A whole bunch of different NUMBER fields, with variing resolutions

func unsignedAlmanacParameterField(nam string, dataLen uint32, res float64, unt, desc string) pgnField {
	return pgnField{
		name: nam, size: dataLen, resolution: res, hasSign: false, unit: unt, description: desc, fieldType: "UNSIGNED_ALMANAC_PARAMETER",
	}
}

func signedAlmanacParameterField(nam string, dataLen uint32, res float64, unt, desc string) pgnField {
	return pgnField{
		name: nam, size: dataLen, resolution: res, hasSign: true, unit: unt, description: desc, fieldType: "SIGNED_ALMANAC_PARAMETER",
	}
}

func dilutionOfPrecisionUfix16Field(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.01, fieldType: "DILUTION_OF_PRECISION_UFIX16", description: desc,
	}
}

func dilutionOfPrecisionFix16Field(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.01, hasSign: true, fieldType: "DILUTION_OF_PRECISION_FIX16", description: desc,
	}
}

func signaltonoiseratioUfix16Field(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.01, fieldType: "SIGNALTONOISERATIO_UFIX16", description: desc,
	}
}

func signaltonoiseratioFix16Field(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.01, hasSign: true, fieldType: "SIGNALTONOISERATIO_FIX16", description: desc,
	}
}

func versionField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.001, fieldType: "VERSION",
	}
}

func voltageU16VField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 1.0, unit: "V", fieldType: "VOLTAGE_UFIX16_V",
	}
}

func voltageU1610mvField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.01, unit: "V", fieldType: "VOLTAGE_UFIX16_10MV",
	}
}

//nolint:unused
func voltageU1650mvField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.05, unit: "V", fieldType: "VOLTAGE_UFIX16_50MV",
	}
}

func voltageU16100mvField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.1, unit: "V", fieldType: "VOLTAGE_UFIX16_100MV",
	}
}

func voltageUfix8200mvField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 1, resolution: 0.2, unit: "V", fieldType: "VOLTAGE_UFIX8_200MV",
	}
}

func voltageI1610mvField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.01, unit: "V", hasSign: true, fieldType: "VOLTAGE_FIX16_10MV",
	}
}

func radioFrequencyField(nam string, res float64) pgnField {
	return pgnField{
		name: nam, size: 8 * 4, resolution: res, unit: "Hz", fieldType: "RADIO_FREQUENCY_UFIX32",
	}
}

func frequencyField(nam string, res float64) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: res, unit: "Hz", fieldType: "FREQUENCY_UFIX16",
	}
}

func speedI16MmField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.001, unit: "m/s", hasSign: true, fieldType: "SPEED_FIX16_MM",
	}
}

func speedI16CmField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.01, unit: "m/s", hasSign: true, fieldType: "SPEED_FIX16_CM",
	}
}

func speedU16CmField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.01, unit: "m/s", fieldType: "SPEED_UFIX16_CM",
	}
}

func speedU16DmField(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.1, unit: "m/s", fieldType: "SPEED_UFIX16_DM", description: desc,
	}
}

func distanceFix16MField(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 1, hasSign: true, unit: "m", description: desc, fieldType: "DISTANCE_FIX16_M",
	}
}

func distanceFix16CmField(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.01, hasSign: true, unit: "m", description: desc, fieldType: "DISTANCE_FIX16_CM",
	}
}

func distanceFix16MmField(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.001, hasSign: true, unit: "m", description: desc, fieldType: "DISTANCE_FIX16_MM",
	}
}

func distanceFix32MmField(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 4, resolution: 0.001, hasSign: true, unit: "m", description: desc, fieldType: "DISTANCE_FIX32_MM",
	}
}

func distanceFix32CmField(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 4, resolution: 0.01, hasSign: true, unit: "m", description: desc, fieldType: "DISTANCE_FIX32_CM",
	}
}

func distanceFix64Field(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 8, resolution: 1e-6, hasSign: true, unit: "m", description: desc, fieldType: "DISTANCE_FIX64",
	}
}

func lengthUfix8DamField(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8, resolution: 10, unit: "m", fieldType: "LENGTH_UFIX8_DAM", description: desc,
	}
}

func lengthUfix16CmField(nam string) pgnField {
	return pgnField{
		name: nam, size: 16, resolution: 0.01, unit: "m", fieldType: "LENGTH_UFIX16_CM",
	}
}

func lengthUfix16DmField(nam string) pgnField {
	return pgnField{
		name: nam, size: 16, resolution: 0.1, unit: "m", fieldType: "LENGTH_UFIX16_DM",
	}
}

func lengthUfix32MField(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 32, resolution: 1, unit: "m", fieldType: "LENGTH_UFIX32_M", description: desc,
	}
}

func lengthUfix32CmField(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 32, resolution: 0.01, unit: "m", fieldType: "LENGTH_UFIX32_CM", description: desc,
	}
}

func lengthUfix32MmField(nam string) pgnField {
	return pgnField{
		name: nam, size: 32, resolution: 0.001, unit: "m", fieldType: "LENGTH_UFIX32_MM",
	}
}

func currentUfix8AField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 1, resolution: 1, unit: "A", fieldType: "CURRENT_UFIX8_A",
	}
}

//nolint:unparam
func currentUfix16AField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 1, unit: "A", fieldType: "CURRENT_UFIX16_A",
	}
}

func currentUfix16DaField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.1, unit: "A", fieldType: "CURRENT_UFIX16_DA",
	}
}

func currentFix16DaField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.1, hasSign: true, unit: "A", fieldType: "CURRENT_FIX16_DA",
	}
}

func currentFix24CaField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 3, resolution: 0.01, hasSign: true, unit: "A", fieldType: "CURRENT_FIX24_CA",
	}
}

func electricChargeUfix16Ah(nam string) pgnField {
	return pgnField{
		name: nam, fieldType: "ELECTRIC_CHARGE_UFIX16_AH",
	}
}

func peukertField(nam string) pgnField {
	return pgnField{
		name: nam, fieldType: "PEUKERT_EXPONENT",
	}
}

// Fully defined NUMBER fields

//nolint:unparam
func pgnPGNField(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 3, resolution: 1, fieldType: "PGN", description: desc,
	}
}

func instanceField() pgnField {
	return pgnField{
		name: "Instance", size: 8 * 1, resolution: 1, fieldType: "UINT8",
	}
}

func powerFactorU16Field() pgnField {
	return pgnField{
		name: "Power factor", size: 8 * 2, resolution: 1 / 16384., unit: "Cos Phi", fieldType: "UFIX16",
	}
}

func powerFactorU8Field() pgnField {
	return pgnField{
		name: "Power factor", size: 8 * 1, resolution: 0.01, unit: "Cos Phi", fieldType: "UFIX8",
	}
}

// End of NUMBER fields

func manufacturerField(unt, desc string, prop bool) pgnField {
	return pgnField{
		name: "Manufacturer Code", size: 11, resolution: 1, description: desc, unit: unt,
		lookup: lookupInfo{
			lookupType:   lookupTypePair,
			functionPair: lookupFunctionPairForTyp["MANUFACTURER_CODE"],
			name:         "MANUFACTURER_CODE",
		},
		proprietary: prop,
		fieldType:   "MANUFACTURER",
	}
}

func industryField(unt, desc string, prop bool) pgnField {
	return pgnField{
		name: "Industry Code", size: 3, resolution: 1, unit: unt, description: desc,
		lookup: lookupInfo{
			lookupType:   lookupTypePair,
			functionPair: lookupFunctionPairForTyp["INDUSTRY_CODE"],
			name:         "INDUSTRY_CODE",
		},
		proprietary: prop,
		fieldType:   "INDUSTRY",
	}
}

func marineIndustryField() pgnField {
	return industryField("=4", "Marine Industry", false)
}

func company(id string) []pgnField {
	return []pgnField{manufacturerField("="+id, "", false), reservedField(2), marineIndustryField()}
}

func manufacturerFields() []pgnField {
	return []pgnField{manufacturerField("", "", false), reservedField(2), industryField("", "", false)}
}

func manufacturerProprietaryFields1() pgnField {
	return manufacturerField("", "Only in PGN when Commanded PGN is proprietary", true)
}

func manufacturerProprietaryFields2() pgnField {
	return reservedPropField(2, "Only in PGN when Commanded PGN is proprietary")
}

func manufacturerProprietaryFields3() pgnField {
	return industryField("", "Only in PGN when Commanded PGN is proprietary", true)
}

//nolint:unused
func integerDescField(nam string, dataLen uint32, desc string) pgnField {
	return pgnField{
		name: nam, size: dataLen, resolution: 1, description: desc,
	}
}

//nolint:unused
func integerUnitField(nam string, dataLen uint32, unt string) pgnField {
	return pgnField{
		name: nam, size: dataLen, resolution: 1, unit: unt,
	}
}

//nolint:unused
func signedIntegerUnitField(nam string, dataLen uint32, unt string) pgnField {
	return pgnField{
		name: nam, size: dataLen, resolution: 1, unit: unt, hasSign: true,
	}
}

//nolint:unused
func integerField(nam string, dataLen uint32) pgnField {
	return integerDescField(nam, dataLen, "")
}

func uint8DescField(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 1, resolution: 1, fieldType: "UINT8", description: desc,
	}
}

//nolint:unparam
func fieldIndex(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 1, resolution: 1, fieldType: "FIELD_INDEX", description: desc,
	}
}

func uint8Field(nam string) pgnField {
	return uint8DescField(nam, "")
}

func uint16DescField(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 1, fieldType: "UINT16", description: desc,
	}
}

func uint16Field(nam string) pgnField {
	return uint16DescField(nam, "")
}

func uint32DescField(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 4, resolution: 1, fieldType: "UINT32", description: desc,
	}
}

func uint32Field(nam string) pgnField {
	return uint32DescField(nam, "")
}

//nolint:unparam
func matchLookupField(nam string, dataLen uint32, id, typ string) pgnField {
	return pgnField{
		name:       nam,
		size:       dataLen,
		resolution: 1,
		hasSign:    false,
		lookup: lookupInfo{
			lookupType:   lookupTypePair,
			functionPair: lookupFunctionPairForTyp[typ],
			name:         typ,
		},
		fieldType: "LOOKUP",
		unit:      "=" + id,
	}
}

func matchField(nam string, dataLen uint32, id, desc string) pgnField {
	return pgnField{
		name: nam, size: dataLen, resolution: 1, unit: "=" + id, description: desc, fieldType: "UNSIGNED_INTEGER",
	}
}

func simpleDescField(nam string, dataLen uint32, desc string) pgnField {
	return pgnField{
		name: nam, size: dataLen, resolution: 1, description: desc, fieldType: "UNSIGNED_INTEGER",
	}
}

func simpleField(nam string, dataLen uint32) pgnField {
	return pgnField{
		name: nam, size: dataLen, resolution: 1, fieldType: "UNSIGNED_INTEGER",
	}
}

func simpleSignedField(nam string, dataLen uint32) pgnField {
	return pgnField{
		name: nam, size: dataLen, resolution: 1, hasSign: true, fieldType: "INTEGER",
	}
}

func mmsiField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 4, resolution: 1, hasSign: false, rangeMin: 2000000, rangeMax: 999999999, fieldType: "MMSI",
	}
}

//nolint:unparam
func decimalField(nam string, dataLen uint32, desc string) pgnField {
	return pgnField{
		name: nam, size: dataLen, resolution: 1, description: desc, fieldType: "DECIMAL",
	}
}

//nolint:unused
func decimalUnitField(nam string, dataLen uint32, unt string) pgnField {
	return pgnField{
		name: nam, size: dataLen, resolution: 1, unit: unt, fieldType: "DECIMAL",
	}
}

func stringlzField(nam string, dataLen uint32) pgnField {
	return pgnField{
		name: nam, size: dataLen, resolution: 0, fieldType: "STRING_LZ",
	}
}

func stringFixDescField(nam string, dataLen uint32, desc string) pgnField {
	return pgnField{
		name: nam, size: dataLen, resolution: 0, description: desc, fieldType: "STRING_FIX",
	}
}

//nolint:unused
func stringvarField(nam string) pgnField {
	return pgnField{
		name: nam, size: lenVariable, resolution: 0, fieldType: "STRING_LZ",
	}
}

func stringlauField(nam string) pgnField {
	return pgnField{
		name: nam, size: lenVariable, resolution: 0, fieldType: "STRING_LAU",
	}
}

func stringFixField(nam string, dataLen uint32) pgnField {
	return stringFixDescField(nam, dataLen, "")
}

func temperatureHighField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.1, unit: "K", fieldType: "TEMPERATURE_HIGH",
	}
}

func temperatureField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.01, unit: "K", fieldType: "TEMPERATURE",
	}
}

//nolint:unused
func temperatureUint8OffsetField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 1, offset: 233, resolution: 1, unit: "K", fieldType: "TEMPERATURE_UINT8_OFFSET",
	}
}

func temperatureU24Field(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 3, resolution: 0.001, unit: "K", fieldType: "TEMPERATURE_UFIX24",
	}
}

func temperatureDeltaFix16Field(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.001, unit: "K", hasSign: true, fieldType: "FIX16", description: desc,
	}
}

func volumetricFlowField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.1, unit: "L/h", hasSign: true, fieldType: "VOLUMETRIC_FLOW",
	}
}

func concentrationUint16Field(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 1, unit: "ppm", fieldType: "CONCENTRATION_UINT16_PPM",
	}
}

func volumeUfix16LField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 1, unit: "L", fieldType: "VOLUME_UFIX16_L",
	}
}

func volumeUfix32DlField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 4, resolution: 0.1, unit: "L", fieldType: "VOLUME_UFIX32_DL",
	}
}

func timeUfix16SField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 1, unit: "s", fieldType: "TIME_UFIX16_S",
	}
}

func timeFix32MsField(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 4, resolution: 0.001, unit: "s", hasSign: true, fieldType: "TIME_FIX32_MS", description: desc,
	}
}

func timeUfix85msField(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 1, resolution: 0.005, unit: "s", hasSign: false, fieldType: "TIME_UFIX8_5MS", description: desc,
	}
}

func timeUfix16MinField(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 60, unit: "s", hasSign: false, fieldType: "TIME_UFIX16_MIN", description: desc,
	}
}

func timeUfix16MsField(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.001, unit: "s", hasSign: false, fieldType: "TIME_UFIX16_MS", description: desc,
	}
}

func timeUfix16CsField(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.01, unit: "s", hasSign: false, fieldType: "TIME_UFIX16_CS", description: desc,
	}
}

func timeFix165csField(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.05, unit: "s", hasSign: true, fieldType: "TIME_FIX16_5CS", description: desc,
	}
}

func timeFix16MinField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 60., unit: "s", hasSign: true, fieldType: "TIME_FIX16_MIN",
	}
}

func timeUfix24MsField(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 3, resolution: 0.001, unit: "s", hasSign: false, fieldType: "TIME_UFIX24_MS", description: desc,
	}
}

//nolint:unparam
func timeUfix32SField(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 4, resolution: 1, unit: "s", hasSign: false, fieldType: "TIME_UFIX32_S", description: desc,
	}
}

//nolint:unparam
func timeUfix32MsField(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 4, resolution: 0.001, unit: "s", hasSign: false, fieldType: "TIME_UFIX32_MS", description: desc,
	}
}

func timeField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 4, resolution: 0.0001, unit: "s", hasSign: false, fieldType: "TIME",
		description: "Seconds since midnight", rangeMin: 0, rangeMax: 86402,
	}
}

func dateField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 1, unit: "d", hasSign: false, fieldType: "DATE",
	}
}

func variableField(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: lenVariable, description: desc, fieldType: "VARIABLE",
	}
}

func keyValueField(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: lenVariable, description: desc, fieldType: "KEY_VALUE",
	}
}

func energyUint32Field(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 4, resolution: 1, unit: "kWh", fieldType: "ENERGY_UINT32",
	}
}

//nolint:unparam
func powerI32OffsetField(nam string) pgnField {
	return pgnField{
		name: nam, hasSign: true, fieldType: "POWER_FIX32_OFFSET",
	}
}

//nolint:unparam
func powerI32VaOffsetField(nam string) pgnField {
	return pgnField{
		name: nam, hasSign: true, fieldType: "POWER_FIX32_VA_OFFSET",
	}
}

func powerI32VarOffsetField(nam string) pgnField {
	return pgnField{
		name: nam, hasSign: true, fieldType: "POWER_FIX32_VAR_OFFSET",
	}
}

func powerU16Field(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 1, unit: "W", fieldType: "POWER_UINT16",
	}
}

func powerU16VarField(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 1, unit: "VAR", description: desc, fieldType: "POWER_UINT16_VAR",
	}
}

func powerI32Field(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 4, resolution: 1, hasSign: true, unit: "W", fieldType: "POWER_INT32",
	}
}

func powerU32Field(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 4, resolution: 1, unit: "W", fieldType: "POWER_UINT32",
	}
}

//nolint:unused
func powerU32VaField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 4, resolution: 1, unit: "VA", fieldType: "POWER_UINT32_VA",
	}
}

func powerU32VarField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 4, resolution: 1, unit: "VAR", fieldType: "POWER_UINT32_VAR",
	}
}

func percentageU8Field(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 1, resolution: 1, unit: "%", fieldType: "PERCENTAGE_UINT8",
	}
}

//nolint:unused
func percentageU8HighresField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 1, resolution: .4, unit: "%", fieldType: "PERCENTAGE_UINT8_HIGHRES",
	}
}

func percentageI8Field(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 1, resolution: 1, hasSign: true, unit: "%", fieldType: "PERCENTAGE_INT8",
	}
}

func percentageI16Field(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: resPercentage, hasSign: true, unit: "%", fieldType: "PERCENTAGE_FIX16",
	}
}

func rotationFix16Field(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: (1e-3 / 32.0), hasSign: true, unit: "rad/s", fieldType: "ROTATION_FIX16",
	}
}

func rotationUfix16RPMField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.25, hasSign: false, unit: "rpm", fieldType: "ROTATION_UFIX16_RPM",
	}
}

//nolint:unused
func rotationUfix16RpmHighresField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.125, hasSign: false, unit: "rpm", fieldType: "ROTATION_UFIX16_RPM_HIGHRES",
	}
}

func rotationFix32Field(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 4, resolution: (1e-6 / 32.0), hasSign: true, unit: "rad/s", fieldType: "ROTATION_FIX32",
	}
}

func pressureUfix16HPAField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 100, unit: "Pa", fieldType: "PRESSURE_UFIX16_HPA",
	}
}

//nolint:unused
func pressureUint8KpaField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 1, resolution: 500, unit: "Pa", fieldType: "PRESSURE_UINT8_KPA",
	}
}

//nolint:unused
func pressureUint82kpaField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 1, resolution: 2000, unit: "Pa", fieldType: "PRESSURE_UINT8_2KPA",
	}
}

func pressureUfix16KpaField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 1000, hasSign: false, unit: "Pa", fieldType: "PRESSURE_UFIX16_KPA",
	}
}

func pressureRateFix16PaField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 1, hasSign: true, unit: "Pa/hr", fieldType: "PRESSURE_RATE_FIX16_PA",
	}
}

func pressureFix16KpaField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 1000, hasSign: true, unit: "Pa", fieldType: "PRESSURE_FIX16_KPA",
	}
}

func pressureFix32DpaField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 4, resolution: 0.1, hasSign: true, unit: "Pa", fieldType: "PRESSURE_FIX32_DPA",
	}
}

func pressureUfix32DpaField(nam string) pgnField {
	return pgnField{
		name: nam, size: 8 * 4, resolution: 0.1, hasSign: false, unit: "Pa", fieldType: "PRESSURE_UFIX32_DPA",
	}
}

func gainField(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.01, hasSign: true, fieldType: "GAIN_FIX16", description: desc,
	}
}

func magneticFix16Field(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.01, hasSign: true, unit: "T", fieldType: "MAGNETIC_FIELD_FIX16",
		description: desc,
	}
}

func angleFix16DdegField(nam, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 2, resolution: 0.1, hasSign: true, unit: "deg", fieldType: "ANGLE_FIX16_DDEG",
		description: desc,
	}
}

func floatField(nam, unt, desc string) pgnField {
	return pgnField{
		name: nam, size: 8 * 4, hasSign: true, unit: unt, fieldType: "FLOAT", description: desc,
		resolution: 1, rangeMin: -1 * math.MaxFloat32, rangeMax: math.MaxFloat32,
	}
}

var immutPGNs []pgnInfo

func initPGNs() {
	//nolint:lll,dupword
	immutPGNs = []pgnInfo{
		/* PDU1 (addressed) single-frame PGN range 0E800 to 0xEEFF (59392 - 61183) */

		{
			description: "0xE800-0xEEFF: Standardized single-frame addressed",
			pgn:         0xe800,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList:   [33]pgnField{binaryField("Data", 8*8, "")},
			fallback:    true,
			explanation: "Standardized PGNs in PDU1 (addressed) single-frame PGN range 0xE800 to " +
				"0xEE00 (59392 - 60928). " +
				"When this is shown during analysis it means the PGN is not reverse engineered yet.",
		},

		/************ Protocol PGNs ************/
		/* http://www.nmea.org/Assets/july%202010%20nmea2000_v1-301_app_b_pgn_field_list.pdf */
		/* http://www.maretron.com/products/pdf/J2K100-Data_Sheet.pdf */
		/* http://www.nmea.org/Assets/pgn059392.pdf */
		/* http://www8.garmin.com/manuals/GPSMAP4008_NMEA2000NetworkFundamentals.pdf */
		/* http://www.furunousa.com/Furuno/Doc/0/8JT2BMDDIB249FCNUK64DKLV67/GP330B%20NMEA%20PGNs.pdf */
		/* http://www.nmea.org/Assets/20140710%20nmea-2000-060928%20iso%20address%20claim%20pgn%20corrigendum.pdf */
		{
			description: "ISO Acknowledgement",
			pgn:         59392,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				lookupField("Control", 8*1, "ISO_CONTROL"),
				uint8Field("Group Function"),
				reservedField(24),
				pgnPGNField("PGN", "Parameter Group Number of requested information"),
			},
			interval: math.MaxUint16,
			explanation: "This message is provided by ISO 11783 for a handshake mechanism between transmitting and receiving devices. " +
				"This message is the possible response to acknowledge the reception of a 'normal broadcast' message or the " +
				"response to a specific command to indicate compliance or failure.",
		},

		{
			description: "ISO Request",
			pgn:         59904,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList:   [33]pgnField{pgnPGNField("PGN", "")},
			interval:    math.MaxUint16,
			explanation: "As defined by ISO, this message has a data length of 3 bytes with no padding added to complete the single " +
				"frame. The appropriate response to this message is based on the PGN being requested, and whether the receiver " +
				"supports the requested PGN.",
		},

		/* For a good explanation of ISO 11783 Transport Protocol (as used in J1939) see
		 * http://www.simmasoftware.com/j1939-presentation.pdf
		 *
		 * First: Transmit a RTS message to the specific address that says:
		 *   1. I'm about to send the following PGN in multiple packets.
		 *   2. I'm sending X amount of data.
		 *   3. I'm sending Y number of packets.
		 *   4. I can send Z number of packets at once.
		 * Second: Wait for CTS: CTS says:
		 *   1. I can receive M number of packets at once.
		 *   2. Start sending with sequence number N.
		 * Third: Send data. Then repeat steps starting with #2. When all data sent, wait for ACK.
		 */

		// ISO 11783 defines this PGN as part of the Transport Protocol method used for transmitting messages that have 9 or more data
		// bytes. This PGN represents a single packet of a multipacket message.
		{
			description: "ISO Transport Protocol, Data Transfer",
			pgn:         60160,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList:   [33]pgnField{uint8Field("SID"), binaryField("Data", 8*7, "")},
			interval:    math.MaxUint16,
			explanation: "ISO 11783 defines this PGN as part of the Transport Protocol method used for transmitting messages that have " +
				"9 or more data bytes. This PGN represents a single packet of a multipacket message.",
		},

		// ''ISO 11783 defines this group function PGN as part of the Transport Protocol method used for transmitting messages that have
		// 9 or more data bytes. This PGN's role in the transport process is determined by the group function value found in the first
		// data byte of the PGN.''
		{
			description: "ISO Transport Protocol, Connection Management - Request To Send",
			pgn:         60416,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				matchLookupField("Group Function Code", 8*1, "16", "ISO_COMMAND"),
				simpleDescField("Message size", 8*2, "bytes"),
				simpleDescField("Packets", 8*1, "packets"),
				simpleDescField("Packets reply", 8*1, "packets sent in response to CTS"), // This one is still mysterious to me...
				pgnPGNField("PGN", ""),
			},
			interval: math.MaxUint16,
			url:      "https://embeddedflakes.com/j1939-transport-protocol/",
			explanation: "ISO 11783 defines this group function PGN as part of the Transport Protocol method used for transmitting " +
				"messages that have 9 or more data bytes. This PGN's role in the transport process is to prepare the receiver " +
				"for the fact that this sender wants to transmit a long message. The receiver will respond with CTS.",
		},

		{
			description: "ISO Transport Protocol, Connection Management - Clear To Send",
			pgn:         60416,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				matchLookupField("Group Function Code", 8*1, "17", "ISO_COMMAND"),
				simpleDescField("Max packets", 8*1, "Number of frames that can be sent before another CTS is required"),
				simpleDescField("Next SID", 8*1, "Number of next frame to be transmitted"),
				reservedField(8 * 2),
				pgnPGNField("PGN", ""),
			},
			interval: math.MaxUint16,
			url:      "https://embeddedflakes.com/j1939-transport-protocol/",
			explanation: "ISO 11783 defines this group function PGN as part of the Transport Protocol method used for transmitting " +
				"messages that have 9 or more data bytes. This PGN's role in the transport process is to signal to the sender " +
				"that the receive is ready to receive a number of frames.",
		},

		{
			description: "ISO Transport Protocol, Connection Management - End Of Message",
			pgn:         60416,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				matchLookupField("Group Function Code", 8*1, "19", "ISO_COMMAND"),
				simpleDescField("Total message size", 8*2, "bytes"),
				simpleDescField("Total number of frames received", 8*1, "Total number of of frames received"),
				reservedField(8 * 1),
				pgnPGNField("PGN", ""),
			},
			interval: math.MaxUint16,
			url:      "https://embeddedflakes.com/j1939-transport-protocol/",
			explanation: "ISO 11783 defines this group function PGN as part of the Transport Protocol method used for transmitting messages that " +
				"have 9 or more data bytes. This PGN's role in the transport process is to mark the end of the message.",
		},

		{
			description: "ISO Transport Protocol, Connection Management - Broadcast Announce",
			pgn:         60416,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				matchLookupField("Group Function Code", 8*1, "32", "ISO_COMMAND"),
				simpleDescField("Message size", 8*2, "bytes"),
				simpleDescField("Packets", 8*1, "frames"),
				reservedField(8 * 1),
				pgnPGNField("PGN", ""),
			},
			interval: math.MaxUint16,
			url:      "https://embeddedflakes.com/j1939-transport-protocol/",
			explanation: "ISO 11783 defines this group function PGN as part of the Transport Protocol method used for transmitting " +
				"messages that have 9 or more data bytes. This PGN's role in the transport process is to announce a broadcast " +
				"of a long message spanning multiple frames.",
		},

		{
			description: "ISO Transport Protocol, Connection Management - Abort",
			pgn:         60416,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				matchLookupField("Group Function Code", 8*1, "255", "ISO_COMMAND"),
				binaryField("Reason", 8*1, ""),
				reservedField(8 * 3),
				pgnPGNField("PGN", ""),
			},
			interval: math.MaxUint16,
			url:      "https://embeddedflakes.com/j1939-transport-protocol/",
			explanation: "ISO 11783 defines this group function PGN as part of the Transport Protocol method used for transmitting " +
				"messages that have 9 or more data bytes. This PGN's role in the transport process is to announce an abort " +
				"of a long message spanning multiple frames.",
		},

		{
			description: "ISO Address Claim",
			pgn:         60928,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				simpleDescField("Unique Number", 21, "ISO Identity Number"),
				manufacturerField("", "", false),
				simpleDescField("Device Instance Lower", 3, "ISO ECU Instance"),
				simpleDescField("Device Instance Upper", 5, "ISO Function Instance"),
				lookupTripletField("Device Function", 8*1, "DEVICE_FUNCTION", "ISO Function", 7 /*Device Class*/),
				spareField(1),
				lookupField("Device Class", 7, "DEVICE_CLASS"),
				simpleDescField("System Instance", 4, "ISO Device Class Instance"),
				lookupField("Industry Group", 3, "INDUSTRY_CODE"),
				// "Arbitrary address capable" is explained at
				// https://embeddedflakes.com/network-management-in-sae-j1939/#Arbitrary_Address_Capable
				simpleDescField("Arbitrary address capable",
					1,
					"Field indicates whether the device is capable to claim arbitrary source "+
						"address. Value is 1 for NMEA200 devices. Could be 0 for J1939 device claims"),
			},
			interval: math.MaxUint16,
			explanation: "This network management message is used to claim network address, reply to devices requesting the claimed " +
				"address, and to respond with device information (NAME) requested by the ISO Request or Complex Request Group " +
				"Function. This PGN contains several fields that are requestable, either independently or in any combination.",
		},

		/* PDU1 (addressed) single-frame PGN range 0EF00 to 0xEFFF (61184 - 61439) */

		{
			description: "0xEF00: Manufacturer Proprietary single-frame addressed",
			pgn:         61184,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList:   varLenFieldListToFixed(append(manufacturerFields(), binaryField("Data", 8*6, ""))),
			fallback:    true,
			explanation: "Manufacturer proprietary PGNs in PDU1 (addressed) single-frame PGN 0xEF00 (61184). " +
				"When this is shown during analysis it means the PGN is not reverse engineered yet.",
		},

		/* The following probably have the wrong Proprietary ID */
		{
			description: "Seatalk: Wireless Keypad Light Control",
			pgn:         61184,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList: varLenFieldListToFixed(append(company("1851"),
				matchField("Proprietary ID", 8*1, "1", "Wireless Keypad Light Control"),
				uint8Field("Variant"),
				uint8Field("Wireless Setting"),
				uint8Field("Wired Setting"),
				reservedField(8*2))),
		},

		{
			description: "Seatalk: Wireless Keypad Control",
			pgn:         61184,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList: varLenFieldListToFixed(append(company("1851"),
				uint8Field("PID"),
				uint8Field("Variant"),
				uint8Field("Beep Control"),
				reservedField(8*3))),
		},

		{
			description: "Victron Battery Register",
			pgn:         61184,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList:   varLenFieldListToFixed(append(company("358"), uint16Field("Register Id"), simpleField("Payload", 8*4))),
		},

		/* PDU2 non-addressed single-frame PGN range 0xF000 - 0xFEFF (61440 - 65279) */

		{
			description: "0xF000-0xFEFF: Standardized single-frame non-addressed",
			pgn:         61440,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList:   varLenFieldListToFixed(append(manufacturerFields(), binaryField("Data", 8*6, ""))),
			fallback:    true,
			explanation: "PGNs in PDU2 (non-addressed) single-frame PGN range 0xF000 to " +
				"0xFEFF (61440 - 65279). " +
				"When this is shown during analysis it means the PGN is not reverse engineered yet.",
		},

		/* Maretron ACM 100 manual documents PGN 65001-65030 */

		{
			description: "Bus #1 Phase C Basic AC Quantities",
			pgn:         65001,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				voltageU16VField("Line-Line AC RMS Voltage"),
				voltageU16VField("Line-Neutral AC RMS Voltage"),
				frequencyField("AC Frequency", 1/128.0),
				reservedField(8 * 2),
			},
		},

		{
			description: "Bus #1 Phase B Basic AC Quantities",
			pgn:         65002,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				voltageU16VField("Line-Line AC RMS Voltage"),
				voltageU16VField("Line-Neutral AC RMS Voltage"),
				frequencyField("AC Frequency", 1/128.0),
				reservedField(8 * 2),
			},
		},

		{
			description: "Bus #1 Phase A Basic AC Quantities",
			pgn:         65003,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				voltageU16VField("Line-Line AC RMS Voltage"),
				voltageU16VField("Line-Neutral AC RMS Voltage"),
				frequencyField("AC Frequency", 1/128.0),
				reservedField(8 * 2),
			},
		},

		{
			description: "Bus #1 Average Basic AC Quantities",
			pgn:         65004,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				voltageU16VField("Line-Line AC RMS Voltage"),
				voltageU16VField("Line-Neutral AC RMS Voltage"),
				frequencyField("AC Frequency", 1/128.0),
				reservedField(8 * 2),
			},
		},

		{
			description: "Utility Total AC Energy",
			pgn:         65005,
			complete:    packetStatusResolutionUnknown,
			packetType:  packetTypeSingle,
			fieldList:   [33]pgnField{energyUint32Field("Total Energy Export"), energyUint32Field("Total Energy Import")},
		},

		{
			description: "Utility Phase C AC Reactive Power",
			pgn:         65006,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				powerU16VarField("Reactive Power", ""),
				powerFactorU16Field(),
				lookupField("Power Factor Lagging", 2, "POWER_FACTOR"),
				reservedField(8*3 + 6),
			},
		},

		{
			description: "Utility Phase C AC Power",
			pgn:         65007,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList:   [33]pgnField{powerI32OffsetField("Real Power"), powerI32VaOffsetField("Apparent Power")},
		},

		{
			description: "Utility Phase C Basic AC Quantities",
			pgn:         65008,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				voltageU16VField("Line-Line AC RMS Voltage"),
				voltageU16VField("Line-Neutral AC RMS Voltage"),
				frequencyField("AC Frequency", 1/128.0),
				currentUfix16AField("AC RMS Current"),
			},
		},

		{
			description: "Utility Phase B AC Reactive Power",
			pgn:         65009,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				powerU16VarField("Reactive Power", ""),
				powerFactorU16Field(),
				lookupField("Power Factor Lagging", 2, "POWER_FACTOR"),
				reservedField(8*3 + 6),
			},
		},

		{
			description: "Utility Phase B AC Power",
			pgn:         65010,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList:   [33]pgnField{powerI32OffsetField("Real Power"), powerI32VaOffsetField("Apparent Power")},
		},

		{
			description: "Utility Phase B Basic AC Quantities",
			pgn:         65011,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				voltageU16VField("Line-Line AC RMS Voltage"),
				voltageU16VField("Line-Neutral AC RMS Voltage"),
				frequencyField("AC Frequency", 1/128.0),
				currentUfix16AField("AC RMS Current"),
			},
		},

		{
			description: "Utility Phase A AC Reactive Power",
			pgn:         65012,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				powerI32VarOffsetField("Reactive Power"),
				powerFactorU16Field(),
				lookupField("Power Factor Lagging", 2, "POWER_FACTOR"),
				reservedField(8*1 + 6),
			},
		},

		{
			description: "Utility Phase A AC Power",
			pgn:         65013,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList:   [33]pgnField{powerI32OffsetField("Real Power"), powerI32VaOffsetField("Apparent Power")},
		},

		{
			description: "Utility Phase A Basic AC Quantities",
			pgn:         65014,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				voltageU16VField("Line-Line AC RMS Voltage"),
				voltageU16VField("Line-Neutral AC RMS Voltage"),
				frequencyField("AC Frequency", 1/128.0),
				currentUfix16AField("AC RMS Current"),
			},
		},

		{
			description: "Utility Total AC Reactive Power",
			pgn:         65015,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				powerI32VarOffsetField("Reactive Power"),
				powerFactorU16Field(),
				lookupField("Power Factor Lagging", 2, "POWER_FACTOR"),
				reservedField(8*1 + 6),
			},
		},

		{
			description: "Utility Total AC Power",
			pgn:         65016,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList:   [33]pgnField{powerI32OffsetField("Real Power"), powerI32VaOffsetField("Apparent Power")},
		},

		{
			description: "Utility Average Basic AC Quantities",
			pgn:         65017,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				voltageU16VField("Line-Line AC RMS Voltage"),
				voltageU16VField("Line-Neutral AC RMS Voltage"),
				frequencyField("AC Frequency", 1/128.0),
				currentUfix16AField("AC RMS Current"),
			},
		},

		{
			description: "Generator Total AC Energy",
			pgn:         65018,
			complete:    packetStatusResolutionUnknown,
			packetType:  packetTypeSingle,
			fieldList:   [33]pgnField{energyUint32Field("Total Energy Export"), energyUint32Field("Total Energy Import")},
		},

		{
			description: "Generator Phase C AC Reactive Power",
			pgn:         65019,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				powerI32VarOffsetField("Reactive Power"),
				powerFactorU16Field(),
				lookupField("Power Factor Lagging", 2, "POWER_FACTOR"),
				reservedField(8*1 + 6),
			},
		},

		{
			description: "Generator Phase C AC Power",
			pgn:         65020,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList:   [33]pgnField{powerI32OffsetField("Real Power"), powerI32VarOffsetField("Apparent Power")},
		},

		{
			description: "Generator Phase C Basic AC Quantities",
			pgn:         65021,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				voltageU16VField("Line-Line AC RMS Voltage"),
				voltageU16VField("Line-Neutral AC RMS Voltage"),
				frequencyField("AC Frequency", 1/128.0),
				currentUfix16AField("AC RMS Current"),
			},
		},

		{
			description: "Generator Phase B AC Reactive Power",
			pgn:         65022,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				powerI32VarOffsetField("Reactive Power"),
				powerFactorU16Field(),
				lookupField("Power Factor Lagging", 2, "POWER_FACTOR"),
				reservedField(8*1 + 6),
			},
		},

		{
			description: "Generator Phase B AC Power",
			pgn:         65023,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList:   [33]pgnField{powerI32OffsetField("Real Power"), powerI32VaOffsetField("Apparent Power")},
		},

		{
			description: "Generator Phase B Basic AC Quantities",
			pgn:         65024,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				voltageU16VField("Line-Line AC RMS Voltage"),
				voltageU16VField("Line-Neutral AC RMS Voltage"),
				frequencyField("AC Frequency", 1/128.0),
				currentUfix16AField("AC RMS Current"),
			},
		},

		{
			description: "Generator Phase A AC Reactive Power",
			pgn:         65025,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				powerI32VarOffsetField("Reactive Power"),
				powerFactorU16Field(),
				lookupField("Power Factor Lagging", 2, "POWER_FACTOR"),
				reservedField(8*1 + 6),
			},
		},

		{
			description: "Generator Phase A AC Power",
			pgn:         65026,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList:   [33]pgnField{powerI32OffsetField("Real Power"), powerI32VaOffsetField("Apparent Power")},
		},

		{
			description: "Generator Phase A Basic AC Quantities",
			pgn:         65027,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				voltageU16VField("Line-Line AC RMS Voltage"),
				voltageU16VField("Line-Neutral AC RMS Voltage"),
				frequencyField("AC Frequency", 1/128.0),
				currentUfix16AField("AC RMS Current"),
			},
		},

		{
			description: "Generator Total AC Reactive Power",
			pgn:         65028,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				powerI32VarOffsetField("Reactive Power"),
				powerFactorU16Field(),
				lookupField("Power Factor Lagging", 2, "POWER_FACTOR"),
				reservedField(8*1 + 6),
			},
		},

		{
			description: "Generator Total AC Power",
			pgn:         65029,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList:   [33]pgnField{powerI32OffsetField("Real Power"), powerI32VaOffsetField("Apparent Power")},
		},

		{
			description: "Generator Average Basic AC Quantities",
			pgn:         65030,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				voltageU16VField("Line-Line AC RMS Voltage"),
				voltageU16VField("Line-Neutral AC RMS Voltage"),
				frequencyField("AC Frequency", 1/128.0),
				currentUfix16AField("AC RMS Current"),
			},
		},

		{
			description: "ISO Commanded Address",
			pgn:         65240,
			complete:    packetStatusComplete,
			packetType:  packetTypeISOTP,
			/* ISO 11783 defined this message to provide a mechanism for assigning a network address to a node. The NAME information in
			   the data portion of the message must match the name information of the node whose network address is to be set. */
			fieldList: [33]pgnField{
				binaryField("Unique Number", 21, "ISO Identity Number"),
				manufacturerField("Manufacturer Code", "", false),
				simpleDescField("Device Instance Lower", 3, "ISO ECU Instance"),
				simpleDescField("Device Instance Upper", 5, "ISO Function Instance"),
				lookupTripletField("Device Function", 8*1, "DEVICE_FUNCTION", "ISO Function", 7 /*Device Class*/),
				reservedField(1),
				lookupField("Device Class", 7, "DEVICE_CLASS"),
				simpleDescField("System Instance", 4, "ISO Device Class Instance"),
				lookupField("Industry Code", 3, "INDUSTRY_CODE"),
				reservedField(1),
				uint8Field("New Source Address"),
			},
		},

		/* proprietary PDU2 (non addressed) single-frame range 0xFF00 to 0xFFFF (65280 - 65535) */

		{
			description: "0xFF00-0xFFFF: Manufacturer Proprietary single-frame non-addressed",
			pgn:         65280,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList:   varLenFieldListToFixed(append(manufacturerFields(), binaryField("Data", 8*6, ""))),
			fallback:    true,
			explanation: "Manufacturer proprietary PGNs in PDU2 (non-addressed) single-frame PGN range 0xFF00 to " +
				"0xFFFF (65280 - 65535). " +
				"When this is shown during analysis it means the PGN is not reverse engineered yet.",
		},

		{
			description: "Furuno: Heave",
			pgn:         65280,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList:   varLenFieldListToFixed(append(company("1855"), distanceFix32MmField("Heave", ""), reservedField(8*2))),
		},

		{
			description: "Maretron: Proprietary DC Breaker Current",
			pgn:         65284,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: varLenFieldListToFixed(append(company("137"),
				uint8Field("Bank Instance"),
				uint8Field("Indicator Number"),
				currentUfix16DaField("Breaker Current"),
				reservedField(8*2))),
		},

		{
			description: "Airmar: Boot State Acknowledgment",
			pgn:         65285,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList:   varLenFieldListToFixed(append(company("135"), lookupField("Boot State", 3, "BOOT_STATE"), reservedField(45))),
			url:         "http://www.airmartechnology.com/uploads/installguide/DST200UserlManual.pdf",
		},

		{
			description: "Lowrance: Temperature",
			pgn:         65285,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: varLenFieldListToFixed(append(company("140"),
				lookupField("Temperature Source", 8*1, "TEMPERATURE_SOURCE"),
				temperatureField("Actual Temperature"),
				reservedField(8*3))),
		},

		{
			description: "Chetco: Dimmer",
			pgn:         65286,
			complete:    packetStatusIncompleteLookup,
			packetType:  packetTypeSingle,
			fieldList: varLenFieldListToFixed(append(company("409"),
				instanceField(),
				uint8Field("Dimmer1"),
				uint8Field("Dimmer2"),
				uint8Field("Dimmer3"),
				uint8Field("Dimmer4"),
				uint8Field("Control"))),
		},

		{
			description: "Airmar: Boot State Request",
			pgn:         65286,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList:   varLenFieldListToFixed(append(company("135"), reservedField(8*6))),
			url:         "http://www.airmartechnology.com/uploads/installguide/DST200UserlManual.pdf",
		},

		{
			description: "Airmar: Access Level",
			pgn:         65287,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: varLenFieldListToFixed(append(company("135"),
				uint8Field("Format Code"),
				lookupField("Access Level", 3, "ACCESS_LEVEL"),
				reservedField(5),
				uint32DescField(
					"Access Seed/Key",
					"When transmitted, it provides a seed for an unlock operation. It is used to provide the key during PGN 126208."))),
			url: "http://www.airmartechnology.com/uploads/installguide/DST200UserlManual.pdf",
		},

		{
			description: "Simnet: Configure Temperature Sensor",
			pgn:         65287,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList:   varLenFieldListToFixed(append(company("1857"), reservedField(8*6))),
		},

		{
			description: "Seatalk: Alarm",
			pgn:         65288,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList: varLenFieldListToFixed(append(company("1851"),
				binaryField("SID", 8*1, ""),
				lookupField("Alarm Status", 8*1, "SEATALK_ALARM_STATUS"),
				lookupField("Alarm ID", 8*1, "SEATALK_ALARM_ID"),
				lookupField("Alarm Group", 8*1, "SEATALK_ALARM_GROUP"),
				binaryField("Alarm Priority", 8*2, ""))),
		},

		{
			description: "Simnet: Trim Tab Sensor Calibration",
			pgn:         65289,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList:   varLenFieldListToFixed(append(company("1857"), reservedField(8*6))),
		},

		{
			description: "Simnet: Paddle Wheel Speed Configuration",
			pgn:         65290,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList:   varLenFieldListToFixed(append(company("1857"), reservedField(8*6))),
		},

		{
			description: "Simnet: Clear Fluid Level Warnings",
			pgn:         65292,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList:   varLenFieldListToFixed(append(company("1857"), reservedField(8*6))),
		},

		{
			description: "Simnet: LGC-2000 Configuration",
			pgn:         65293,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList:   varLenFieldListToFixed(append(company("1857"), reservedField(8*6))),
		},

		{
			description: "Diverse Yacht Services: Load Cell",
			pgn:         65293,
			complete:    packetStatusResolutionUnknown,
			packetType:  packetTypeSingle,
			fieldList:   varLenFieldListToFixed(append(company("641"), instanceField(), reservedField(8*1), uint32Field("Load Cell"))),
		},

		{
			description: "Simnet: AP Unknown 1",
			pgn:         65302,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList: varLenFieldListToFixed(append(company("1857"),
				uint8Field("A"),
				uint8Field("B"),
				uint16Field("C"),
				uint8Field("D"),
				reservedField(8*1))),
			interval:    1000,
			explanation: "Seen as sent by AC-42 only so far.",
		},

		{
			description: "Simnet: Device Status",
			pgn:         65305,
			complete:    packetStatusLookupsUnknown,
			packetType:  packetTypeSingle,
			fieldList: varLenFieldListToFixed(append(company("1857"),
				lookupField("Model", 8*1, "SIMNET_DEVICE_MODEL"),
				matchLookupField("Report", 8*1, "2", "SIMNET_DEVICE_REPORT"),
				lookupField("Status", 8*1, "SIMNET_AP_STATUS"),
				spareField(8*3))),
			interval:    1000,
			explanation: "This PGN is reported by an Autopilot Computer (AC/NAC)",
		},

		{
			description: "Simnet: Device Status Request",
			pgn:         65305,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: varLenFieldListToFixed(append(company("1857"),
				lookupField("Model", 8*1, "SIMNET_DEVICE_MODEL"),
				matchLookupField("Report", 8*1, "3", "SIMNET_DEVICE_REPORT"),
				spareField(8*4))),
			interval: 1000,
			explanation: "This PGN is sent by an active AutoPilot head controller (AP, MFD, Triton2)." +
				" It is used by the AC (AutoPilot Controller) to verify that there is an active controller." +
				" If this PGN is not sent regularly the AC may report an error and go to standby.",
		},

		{
			description: "Simnet: Pilot Mode",
			pgn:         65305,
			complete:    packetStatusLookupsUnknown,
			packetType:  packetTypeSingle,
			fieldList: varLenFieldListToFixed(append(company("1857"),
				lookupField("Model", 8*1, "SIMNET_DEVICE_MODEL"),
				matchLookupField("Report", 8*1, "10", "SIMNET_DEVICE_REPORT"),
				bitlookupField("Mode", 8*2, "SIMNET_AP_MODE_BITFIELD"),
				spareField(8*2))),
			interval:    1000,
			explanation: "This PGN is reported by an Autopilot Computer (AC/NAC)",
		},

		{
			description: "Simnet: Device Mode Request",
			pgn:         65305,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: varLenFieldListToFixed(append(company("1857"),
				lookupField("Model", 8*1, "SIMNET_DEVICE_MODEL"),
				matchLookupField("Report", 8*1, "11", "SIMNET_DEVICE_REPORT"),
				spareField(8*4))),
			interval: 1000,
			explanation: "This PGN is sent by an active AutoPilot head controller (AP, MFD, Triton2)." +
				" It is used by the AC (AutoPilot Controller) to verify that there is an active controller." +
				" If this PGN is not sent regularly the AC may report an error and go to standby.",
		},

		{
			description: "Simnet: Sailing Processor Status",
			pgn:         65305,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList: varLenFieldListToFixed(append(company("1857"),
				lookupField("Model", 8*1, "SIMNET_DEVICE_MODEL"),
				matchLookupField("Report", 8*1, "23", "SIMNET_DEVICE_REPORT"),
				binaryField("Data", 8*4, ""))),
			interval:    1000,
			explanation: "This PGN has been seen to be reported by a Sailing Processor.",
		},

		{
			description: "Navico: Wireless Battery Status",
			pgn:         65309,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList: varLenFieldListToFixed(append(company("275"),
				uint8Field("Status"),
				percentageU8Field("Battery Status"),
				percentageU8Field("Battery Charge Status"),
				reservedField(8*3))),
		},

		{
			description: "Navico: Wireless Signal Status",
			pgn:         65312,
			complete:    packetStatusFieldsUnknown,
			packetType:  packetTypeSingle,
			fieldList:   varLenFieldListToFixed(append(company("275"), uint8Field("Unknown"), percentageU8Field("Signal Strength"), reservedField(8*4))),
		},

		{
			description: "Simnet: AP Unknown 2",
			pgn:         65340,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList: varLenFieldListToFixed(append(company("1857"),
				uint8Field("A"),
				uint8Field("B"),
				uint8Field("C"),
				uint8Field("D"),
				uint8Field("E"),
				reservedField(8*1))),
			interval:    1000,
			explanation: "Seen as sent by AC-42 only so far.",
		},

		{
			description: "Simnet: Autopilot Angle",
			pgn:         65341,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList: varLenFieldListToFixed(append(company("1857"),
				reservedField(8*2),
				lookupField("Mode", 8*1, "SIMNET_AP_MODE"),
				reservedField(8*1),
				angleU16Field("Angle", ""))),
		},

		{
			description: "Seatalk: Pilot Wind Datum",
			pgn:         65345,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList: varLenFieldListToFixed(append(company("1851"),
				angleU16Field("Wind Datum", ""),
				angleU16Field("Rolling Average Wind Angle", ""),
				reservedField(8*2))),
		},

		{
			description: "Simnet: Magnetic Field",
			pgn:         65350,
			complete:    packetStatusIncomplete | packetStatusMissingcompanyFields,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				angleI16Field("A", ""),
				percentageU8Field("B"),
				angleI16Field("C", ""),
				angleI16Field("D", ""),
				reservedField(8 * 1),
			},
		},

		{
			description: "Seatalk: Pilot Heading",
			pgn:         65359,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList: varLenFieldListToFixed(append(company("1851"),
				binaryField("SID", 8*1, ""),
				angleU16Field("Heading True", ""),
				angleU16Field("Heading Magnetic", ""),
				reservedField(8*1))),
		},

		{
			description: "Seatalk: Pilot Locked Heading",
			pgn:         65360,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: varLenFieldListToFixed(append(company("1851"),
				binaryField("SID", 8*1, ""),
				angleU16Field("Target Heading True", ""),
				angleU16Field("Target Heading Magnetic", ""),
				reservedField(8*1))),
		},

		{
			description: "Seatalk: Silence Alarm",
			pgn:         65361,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: varLenFieldListToFixed(append(company("1851"),
				lookupField("Alarm ID", 8*1, "SEATALK_ALARM_ID"),
				lookupField("Alarm Group", 8*1, "SEATALK_ALARM_GROUP"),
				reservedField(32))),
		},

		{
			description: "Seatalk: Keypad Message",
			pgn:         65371,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList: varLenFieldListToFixed(append(company("1851"),
				uint8Field("Proprietary ID"),
				uint8Field("First key"),
				uint8Field("Second key"),
				simpleField("First key state", 2),
				simpleField("Second key state", 2),
				reservedField(4),
				uint8Field("Encoder Position"),
				reservedField(8*1))),
		},

		{
			description: "SeaTalk: Keypad Heartbeat",
			pgn:         65374,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList: varLenFieldListToFixed(append(company("1851"),
				uint8Field("Proprietary ID"),
				uint8Field("Variant"),
				uint8Field("Status"),
				reservedField(8*3))),
		},

		{
			description: "Seatalk: Pilot Mode",
			pgn:         65379,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList: varLenFieldListToFixed(append(company("1851"),
				binaryField("Pilot Mode", 8*2, ""),
				binaryField("Sub Mode", 8*2, ""),
				binaryField("Pilot Mode Data", 8*1, ""),
				reservedField(8*1))),
		},

		{
			description: "Airmar: Depth Quality Factor",
			pgn:         65408,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList: varLenFieldListToFixed(append(company("135"),
				uint8Field("SID"),
				lookupField("Depth Quality Factor", 4, "AIRMAR_DEPTH_QUALITY_FACTOR"),
				reservedField(36))),
			url: "http://www.airmartechnology.com/uploads/installguide/DST200UserlManual.pdf",
		},

		{
			description: "Airmar: Speed Pulse Count",
			pgn:         65409,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: varLenFieldListToFixed(append(company("135"),
				uint8Field("SID"),
				timeUfix16MsField("Duration of interval", ""),
				uint16Field("Number of pulses received"),
				reservedField(8*1))),
			url: "http://www.airmartechnology.com/uploads/installguide/DST200UserlManual.pdf",
		},

		{
			description: "Airmar: Device Information",
			pgn:         65410,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList: varLenFieldListToFixed(append(company("135"),
				uint8Field("SID"),
				temperatureField("Internal Device Temperature"),
				voltageU1610mvField("Supply Voltage"),
				reservedField(8*1))),
			interval: math.MaxUint16,
			url:      "http://www.airmartechnology.com/uploads/installguide/DST200UserlManual.pdf",
		},

		{
			description: "Simnet: AP Unknown 3",
			pgn:         65420,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList: varLenFieldListToFixed(append(company("1857"),
				uint8Field("A"),
				uint8Field("B"),
				uint8Field("C"),
				uint8Field("D"),
				uint8Field("E"),
				reservedField(8*1))),
			interval:    1000,
			explanation: "Seen as sent by AC-42 only so far.",
		},

		{
			description: "Simnet: Autopilot Mode",
			pgn:         65480,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList:   varLenFieldListToFixed(append(company("1857"), reservedField(8*6))),
		},

		/* PDU1 (addressed) fast-packet PGN range 0x1ED00 to 0x1EE00 (126208 - 126464) */
		/* Only 0x1ED00 and 0x1EE00 seem to be used? */
		{
			description: "0x1ED00 - 0x1EE00: Standardized fast-packet addressed",
			pgn:         0x1ed00,
			complete:    packetStatusIncompleteLookup,
			packetType:  packetTypeFast,
			fieldList:   [33]pgnField{binaryField("Data", 8*common.FastPacketMaxSize, "")},
			fallback:    true,
			explanation: "Standardized PGNs in PDU1 (addressed) fast-packet PGN range 0x1ED00 to " +
				"0x1EE00 (65536 - 126464). " +
				"When this is shown during analysis it means the PGN is not reverse engineered yet.",
		},

		{
			description: "NMEA - Request group function",
			pgn:         126208,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				matchLookupField("Function Code", 8*1, "0", "GROUP_FUNCTION"),
				pgnPGNField("PGN", "Requested PGN"),
				timeUfix32MsField("Transmission interval", ""),
				timeUfix16CsField("Transmission interval offset", ""),
				uint8DescField("Number of Parameters", "How many parameter pairs will follow"),
				fieldIndex("Parameter", "Parameter index"),
				variableField("Value", "Parameter value"),
			},
			interval: math.MaxUint16,
			explanation: "This is the Request variation of this group function PGN. The receiver shall respond by sending the requested " +
				"PGN, at the desired transmission interval.",
			url:             "http://www.nmea.org/Assets/20140109%20nmea-2000-corrigendum-tc201401031%20pgn%20126208.pdf",
			repeatingField1: 5,
			repeatingCount1: 2,
			repeatingStart1: 6,
		},

		{
			description: "NMEA - Command group function",
			pgn:         126208,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				matchLookupField("Function Code", 8*1, "1", "GROUP_FUNCTION"),
				pgnPGNField("PGN", "Commanded PGN"),
				lookupField("Priority", 4, "PRIORITY"),
				reservedField(4),
				uint8DescField("Number of Parameters", "How many parameter pairs will follow"),
				fieldIndex("Parameter", "Parameter index"),
				variableField("Value", "Parameter value"),
			},
			interval: math.MaxUint16,
			explanation: "This is the Command variation of this group function PGN. This instructs the receiver to modify its internal " +
				"state for the passed parameters. The receiver shall reply with an Acknowledge reply.",
			repeatingField1: 5,
			repeatingCount1: 2,
			repeatingStart1: 6,
		},

		{
			description: "NMEA - Acknowledge group function",
			pgn:         126208,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				matchLookupField("Function Code", 8*1, "2", "GROUP_FUNCTION"),
				pgnPGNField("PGN", "Commanded PGN"),
				lookupField("PGN error code", 4, "PGN_ERROR_CODE"),
				lookupField("Transmission interval/Priority error code", 4, "TRANSMISSION_INTERVAL"),
				uint8Field("Number of Parameters"),
				lookupField("Parameter", 4, "PARAMETER_FIELD"),
			},
			interval: math.MaxUint16,
			explanation: "This is the Acknowledge variation of this group function PGN. When a device receives a Command, it will " +
				"attempt to perform the command (change its parameters) and reply positively or negatively.",
			repeatingField1: 5,
			repeatingCount1: 1,
			repeatingStart1: 6,
		},

		{
			description: "NMEA - Read Fields group function",
			pgn:         126208,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				matchLookupField("Function Code", 8*1, "3", "GROUP_FUNCTION"),
				pgnPGNField("PGN", "Commanded PGN"),
				manufacturerProprietaryFields1(),
				manufacturerProprietaryFields2(),
				manufacturerProprietaryFields3(),
				uint8Field("Unique ID"),
				uint8Field("Number of Selection Pairs"),
				uint8Field("Number of Parameters"),
				fieldIndex("Selection Parameter", "Parameter index"),
				variableField("Selection Value", ""),
				fieldIndex("Parameter", "Parameter index"),
			},
			interval: math.MaxUint16,
			explanation: "This is the Read Fields variation of this group function PGN. The receiver shall respond by sending a Read " +
				"Reply variation of this PGN, containing the desired values." +
				" This PGN is special as it contains two sets of repeating fields, and the fields that contain the information " +
				"how many repetitions there are do not have a fixed offset in the PGN as the fields 3 to 5 are only present if " +
				"field 2 is for a proprietary PGN",
			repeatingField1: 7,
			repeatingCount1: 2,
			repeatingStart1: 9,
			repeatingField2: 8,
			repeatingCount2: 1,
			repeatingStart2: 11,
		},

		{
			description: "NMEA - Read Fields reply group function",
			pgn:         126208,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				matchLookupField("Function Code", 8*1, "4", "GROUP_FUNCTION"),
				pgnPGNField("PGN", "Commanded PGN"),
				manufacturerProprietaryFields1(),
				manufacturerProprietaryFields2(),
				manufacturerProprietaryFields3(),
				uint8Field("Unique ID"),
				uint8Field("Number of Selection Pairs"),
				uint8Field("Number of Parameters"),
				fieldIndex("Selection Parameter", "Parameter index"),
				variableField("Selection Value", ""),
				fieldIndex("Parameter", "Parameter index"),
				variableField("Value", ""),
			},
			interval: math.MaxUint16,
			explanation: "This is the Read Fields Reply variation of this group function PGN. The receiver is responding to a Read Fields request." +
				" This PGN is special as it contains two sets of repeating fields, and the fields that contain the information how many " +
				"repetitions there are do not have a fixed offset in the PGN as the fields 3 to 5 are only present if field 2 is for a " +
				"proprietary PGN",
			repeatingField1: 7,
			repeatingCount1: 2,
			repeatingStart1: 9,
			repeatingField2: 8,
			repeatingCount2: 2,
			repeatingStart2: 11,
		},

		{
			description: "NMEA - Write Fields group function",
			pgn:         126208,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				matchLookupField("Function Code", 8*1, "5", "GROUP_FUNCTION"),
				pgnPGNField("PGN", "Commanded PGN"),
				manufacturerProprietaryFields1(),
				manufacturerProprietaryFields2(),
				manufacturerProprietaryFields3(),
				uint8Field("Unique ID"),
				uint8Field("Number of Selection Pairs"),
				uint8Field("Number of Parameters"),
				fieldIndex("Selection Parameter", "Parameter index"),
				variableField("Selection Value", ""),
				fieldIndex("Parameter", "Parameter index"),
				variableField("Value", ""),
			},
			interval: math.MaxUint16,
			explanation: "This is the Write Fields variation of this group function PGN. The receiver shall modify internal state and " +
				"reply with a Write Fields Reply message." +
				" This PGN is special as it contains two sets of repeating fields, and the fields that contain the information " +
				"how many repetitions there are do not have a fixed offset in the PGN as the fields 3 to 5 are only present if " +
				"field 2 is for a proprietary PGN",
			repeatingField1: 7,
			repeatingCount1: 2,
			repeatingStart1: 9,
			repeatingField2: 8,
			repeatingCount2: 2,
			repeatingStart2: 11,
		},

		{
			description: "NMEA - Write Fields reply group function",
			pgn:         126208,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				matchLookupField("Function Code", 8*1, "6", "GROUP_FUNCTION"),
				pgnPGNField("PGN", "Commanded PGN"),
				manufacturerProprietaryFields1(),
				manufacturerProprietaryFields2(),
				manufacturerProprietaryFields3(),
				uint8Field("Unique ID"),
				uint8Field("Number of Selection Pairs"),
				uint8Field("Number of Parameters"),
				fieldIndex("Selection Parameter", "Parameter index"),
				variableField("Selection Value", ""),
				fieldIndex("Parameter", "Parameter index"),
				variableField("Value", ""),
			},
			interval: math.MaxUint16,
			explanation: "This is the Write Fields Reply variation of this group function PGN. The receiver is responding to a Write Fields request." +
				" This PGN is special as it contains two sets of repeating fields, and the fields that contain the information how many " +
				"repetitions there are do not have a fixed offset in the PGN as the fields 3 to 5 are only present if field 2 is for a " +
				"proprietary PGN",
			repeatingField1: 7,
			repeatingCount1: 2,
			repeatingStart1: 9,
			repeatingField2: 8,
			repeatingCount2: 2,
			repeatingStart2: 11,
		},

		/************ RESPONSE TO REQUEST PGNS **************/

		{
			description:     "PGN List (Transmit and Receive)",
			pgn:             126464,
			complete:        packetStatusComplete,
			packetType:      packetTypeFast,
			fieldList:       [33]pgnField{lookupField("Function Code", 8*1, "PGN_LIST_FUNCTION"), pgnPGNField("PGN", "")},
			interval:        math.MaxUint16,
			repeatingField1: math.MaxUint8,
			repeatingCount1: 1,
			repeatingStart1: 2,
		},

		/* proprietary PDU1 (addressed) fast-packet PGN range 0x1EF00 to 0x1EFFF (126720 - 126975) */

		{
			description: "0x1EF00-0x1EFFF: Manufacturer Proprietary fast-packet addressed",
			pgn:         126720,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList:   varLenFieldListToFixed(append(manufacturerFields(), binaryField("Data", 8*221, ""))),
			fallback:    true,
			explanation: "Manufacturer Proprietary PGNs in PDU1 (addressed) fast-packet PGN range 0x1EF00 to " +
				"0x1EFFF (126720 - 126975). " +
				"When this is shown during analysis it means the PGN is not reverse engineered yet.",
		},

		{
			description: "Seatalk1: Pilot Mode",
			pgn:         126720,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("1851"),
				matchField("Proprietary ID", 8*2, "33264", "0x81f0"),
				matchField("command", 8*1, "132", "0x84"),
				binaryField("Unknown 1", 8*3, ""),
				lookupField("Pilot Mode", 8*1, "SEATALK_PILOT_MODE"),
				uint8Field("Sub Mode"),
				binaryField("Pilot Mode Data", 8*1, ""),
				binaryField("Unknown 2", 8*10, ""))),
		},

		{
			description: "Fusion: Media Control",
			pgn:         126720,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchField("Proprietary ID", 8*1, "3", "Media Control"),
				uint8Field("Unknown"),
				uint8Field("Source ID"),
				lookupField("Command", 8*1, "FUSION_COMMAND"))),
		},

		{
			description: "Fusion: Sirius Control",
			pgn:         126720,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchField("Proprietary ID", 8*1, "30", "Sirius Control"),
				uint8Field("Unknown"),
				uint8Field("Source ID"),
				lookupField("Command", 8*1, "FUSION_SIRIUS_COMMAND"))),
		},

		{
			description: "Fusion: Request Status",
			pgn:         126720,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList:   varLenFieldListToFixed(append(company("419"), matchLookupField("Proprietary ID", 8*1, "1", "FUSION_MESSAGE_ID"), uint8Field("Unknown"))),
		},

		{
			description: "Fusion: Set Source",
			pgn:         126720,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchLookupField("Proprietary ID", 8*1, "2", "FUSION_MESSAGE_ID"),
				uint8Field("Unknown"),
				uint8Field("Source ID"))),
		},

		{
			description: "Fusion: Set Mute",
			pgn:         126720,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchLookupField("Proprietary ID", 8*1, "23", "FUSION_MESSAGE_ID"),
				lookupField("Command", 8*1, "FUSION_MUTE_COMMAND"))),
		},

		{
			description: "Fusion: Set Zone Volume",
			pgn:         126720,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchLookupField("Proprietary ID", 8*1, "24", "FUSION_MESSAGE_ID"),
				uint8Field("Unknown"),
				uint8Field("Zone"),
				uint8Field("Volume"))),
		},

		{
			description: "Fusion: Set All Volumes",
			pgn:         126720,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchLookupField("Proprietary ID", 8*1, "25", "FUSION_MESSAGE_ID"),
				uint8Field("Unknown"),
				uint8Field("Zone1"),
				uint8Field("Zone2"),
				uint8Field("Zone3"),
				uint8Field("Zone4"))),
		},

		/* Seatalk1 code from http://thomasknauf.de/rap/seatalk2.htm */
		{
			description: "Seatalk1: Keystroke",
			pgn:         126720,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("1851"),
				matchField("Proprietary ID", 8*2, "33264", "0x81f0"),
				matchField("command", 8*1, "134", "0x86"),
				uint8Field("device"),
				lookupField("key", 8*1, "SEATALK_KEYSTROKE"),
				uint8DescField("keyInverted", "Bit negated version of key"),
				binaryField("Unknown data", 8*14, "")),
			// xx xx xx xx xx c1 c2 cd 64 80 d3 42 f1 c8 (if xx=0xff =>working or xx xx xx xx xx = [A5 FF FF FF FF | 00 00 00 FF FF |
			// FF FF FF FF FF | 42 00 F8 02 05])
			),
		},

		{
			description: "Seatalk1: Device Identification",
			pgn:         126720,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("1851"),
				matchField("Proprietary ID", 8*2, "33264", "0x81f0"),
				matchField("command", 8*1, "144", "0x90"),
				reservedField(8*1),
				lookupField("device", 8*1, "SEATALK_DEVICE_ID"))),
		},

		{
			description: "Seatalk1: Display Brightness",
			pgn:         126720,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("1851"),
				matchField("Proprietary ID", 8*2, "3212", "0x0c8c"),
				lookupField("Group", 8*1, "SEATALK_NETWORK_GROUP"),
				binaryField("Unknown 1", 8*1, ""),
				matchField("Command", 8*1, "0", "Brightness"),
				percentageU8Field("Brightness"),
				binaryField("Unknown 2", 8*1, ""))),
		},

		{
			description: "Seatalk1: Display Color",
			pgn:         126720,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("1851"),
				matchField("Proprietary ID", 8*2, "3212", "0x0c8c"),
				lookupField("Group", 8*1, "SEATALK_NETWORK_GROUP"),
				binaryField("Unknown 1", 8*1, ""),
				matchField("Command", 8*1, "1", "Color"),
				lookupField("Color", 8*1, "SEATALK_DISPLAY_COLOR"),
				binaryField("Unknown 2", 8*1, ""))),
		},

		{
			description: "Airmar: Attitude Offset",
			pgn:         126720,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("135"),
				matchLookupField("Proprietary ID", 8*1, "32", "AIRMAR_COMMAND"),
				angleI16Field("Azimuth offset", "Positive: sensor rotated to port, negative: sensor rotated to starboard"),
				angleI16Field("Pitch offset", "Positive: sensor tilted to bow, negative: sensor tilted to stern"),
				angleI16Field("Roll offset", "Positive: sensor tilted to port, negative: sensor tilted to starboard"))),
			interval: math.MaxUint16,
			url:      "http://www.airmartechnology.com/uploads/installguide/DST200UserlManual.pdf",
		},

		{
			description: "Airmar: Calibrate Compass",
			pgn:         126720,
			complete:    packetStatusFieldsUnknown,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("135"),
				matchLookupField("Proprietary ID", 8*1, "33", "AIRMAR_COMMAND"),
				lookupField("Calibrate Function", 8*1, "AIRMAR_CALIBRATE_FUNCTION"),
				lookupField("Calibration Status", 8*1, "AIRMAR_CALIBRATE_STATUS"),
				uint8DescField("Verify Score", "TBD"),
				gainField("X-axis gain value", "default 100, range 50 to 500"),
				gainField("Y-axis gain value", "default 100, range 50 to 500"),
				gainField("Z-axis gain value", "default 100, range 50 to 500"),
				magneticFix16Field("X-axis linear offset", "default 0, range -320.00 to 320.00"),
				magneticFix16Field("Y-axis linear offset", "default 0, range -320.00 to 320.00"),
				magneticFix16Field("Z-axis linear offset", "default 0, range -320.00 to 320.00"),
				angleFix16DdegField("X-axis angular offset", "default 0, range 0 to 3600"),
				timeFix165csField("Pitch and Roll damping", "default 30, range 0 to 200"),
				timeFix165csField("Compass/Rate gyro damping",
					"default -30, range -2400 to 2400, negative indicates rate gyro is to be used in compass calculations"))),
			interval: math.MaxUint16,
			url:      "http://www.airmartechnology.com/uploads/installguide/DST200UserlManual.pdf",
		},

		{
			description: "Airmar: True Wind Options",
			pgn:         126720,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("135"),
				matchLookupField("Proprietary ID", 8*1, "34", "AIRMAR_COMMAND"),
				lookupFieldDesc("COG substitution for HDG", 2, "YES_NO", "Allow use of COG when HDG not available?"),
				reservedField(22))),
			interval: math.MaxUint16,
			url:      "http://www.airmartechnology.com/uploads/installguide/PB200UserManual.pdf",
		},

		{
			description: "Airmar: Simulate Mode",
			pgn:         126720,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("135"),
				matchLookupField("Proprietary ID", 8*1, "35", "AIRMAR_COMMAND"),
				lookupField("Simulate Mode", 2, "OFF_ON"),
				reservedField(22))),
			interval: math.MaxUint16,
			url:      "http://www.airmartechnology.com/uploads/installguide/DST200UserlManual.pdf",
		},

		{
			description: "Airmar: Calibrate Depth",
			pgn:         126720,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("135"),
				matchLookupField("Proprietary ID", 8*1, "40", "AIRMAR_COMMAND"),
				speedU16DmField("Speed of Sound Mode", "actual allowed range is 1350.0 to 1650.0 m/s"),
				reservedField(8))),
			interval: math.MaxUint16,
			url:      "http://www.airmartechnology.com/uploads/installguide/DST200UserlManual.pdf",
		},

		{
			description: "Airmar: Calibrate Speed",
			pgn:         126720,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("135"),
				matchLookupField("Proprietary ID", 8*1, "41", "AIRMAR_COMMAND"),
				uint8DescField("Number of pairs of data points", "actual range is 0 to 25. 254=restore default speed curve"),
				frequencyField("Input frequency", 0.1),
				speedU16CmField("Output speed"))),
			repeatingField1: 5,
			repeatingCount1: 2,
			repeatingStart1: 6,
			interval:        math.MaxUint16,
			url:             "http://www.airmartechnology.com/uploads/installguide/DST200UserlManual.pdf",
		},

		{
			description: "Airmar: Calibrate Temperature",
			pgn:         126720,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("135"),
				matchLookupField("Proprietary ID", 8*1, "42", "AIRMAR_COMMAND"),
				lookupField("Temperature instance", 2, "AIRMAR_TEMPERATURE_INSTANCE"),
				reservedField(6),
				temperatureDeltaFix16Field("Temperature offset", "actual range is -9.999 to +9.999 K"))),
			interval: math.MaxUint16,
			url:      "http://www.airmartechnology.com/uploads/installguide/DST200UserlManual.pdf",
		},

		{
			description: "Airmar: Speed Filter None",
			pgn:         126720,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("135"),
				matchLookupField("Proprietary ID", 8*1, "43", "AIRMAR_COMMAND"),
				matchField("Filter type", 4, "0", "No filter"),
				reservedField(4),
				timeUfix16CsField("Sample interval", "Interval of time between successive samples of the paddlewheel pulse accumulator"))),
			interval: math.MaxUint16,
			url:      "http://www.airmartechnology.com/uploads/installguide/DST200UserlManual.pdf",
		},

		{
			description: "Airmar: Speed Filter IIR",
			pgn:         126720,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("135"),
				matchLookupField("Proprietary ID", 8*1, "43", "AIRMAR_COMMAND"),
				matchField("Filter type", 4, "1", "IIR filter"),
				reservedField(4),
				timeUfix16CsField("Sample interval", "Interval of time between successive samples of the paddlewheel pulse accumulator"),
				timeUfix16CsField("Filter duration", "Duration of filter, must be bigger than the sample interval"))),
			interval: math.MaxUint16,
			url:      "http://www.airmartechnology.com/uploads/installguide/DST200UserlManual.pdf",
		},

		{
			description: "Airmar: Temperature Filter None",
			pgn:         126720,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("135"),
				matchLookupField("Proprietary ID", 8*1, "44", "AIRMAR_COMMAND"),
				matchField("Filter type", 4, "0", "No filter"),
				reservedField(4),
				timeUfix16CsField("Sample interval", "Interval of time between successive samples of the water temperature thermistor"))),
			interval: math.MaxUint16,
			url:      "http://www.airmartechnology.com/uploads/installguide/DST200UserlManual.pdf",
		},

		{
			description: "Airmar: Temperature Filter IIR",
			pgn:         126720,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("135"),
				matchLookupField("Proprietary ID", 8*1, "44", "AIRMAR_COMMAND"),
				matchField("Filter type", 4, "1", "IIR filter"),
				reservedField(4),
				timeUfix16CsField("Sample interval", "Interval of time between successive samples of the water temperature thermistor"),
				timeUfix16CsField("Filter duration", "Duration of filter, must be bigger than the sample interval"))),
			interval: math.MaxUint16,
			url:      "http://www.airmartechnology.com/uploads/installguide/DST200UserlManual.pdf",
		},

		{
			description: "Airmar: NMEA 2000 options",
			pgn:         126720,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("135"),
				matchLookupField("Proprietary ID", 8*1, "46", "AIRMAR_COMMAND"),
				lookupField("Transmission Interval", 2, "AIRMAR_TRANSMISSION_INTERVAL"),
				reservedField(22))),
			interval: math.MaxUint16,
			url:      "http://www.airmartechnology.com/uploads/installguide/DST200UserlManual.pdf",
		},

		{
			description: "Airmar: Addressable Multi-Frame",
			pgn:         126720,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList:   varLenFieldListToFixed(append(company("135"), uint8Field("Proprietary ID"))),
		},

		{
			description: "Maretron: Slave Response",
			pgn:         126720,
			complete:    packetStatusLookupsUnknown,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("137"),
				simpleDescField("Product code", 8*2, "0x1b2=SSC200"),
				uint16Field("Software code"),
				uint8DescField("Command", "0x50=Deviation calibration result"),
				uint8Field("Status"))),
		},

		{
			description: "Garmin: Day Mode",
			pgn:         126720,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("229"),
				matchField("Unknown ID 1", 8*1, "222", "Always 222"),
				matchField("Unknown ID 2", 8*1, "5", "Always 5"),
				matchField("Unknown ID 3", 8*1, "5", "Always 5"),
				matchField("Unknown ID 4", 8*1, "5", "Always 5"),
				spareField(8*2),
				matchLookupField("Mode", 8*1, "0", "GARMIN_COLOR_MODE"),
				spareField(8*1),
				lookupField("Backlight", 8*1, "GARMIN_BACKLIGHT_LEVEL"))),
		},

		{
			description: "Garmin: Night Mode",
			pgn:         126720,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("229"),
				matchField("Unknown ID 1", 8*1, "222", "Always 222"),
				matchField("Unknown ID 2", 8*1, "5", "Always 5"),
				matchField("Unknown ID 3", 8*1, "5", "Always 5"),
				matchField("Unknown ID 4", 8*1, "5", "Always 5"),
				spareField(8*2),
				matchLookupField("Mode", 8*1, "1", "GARMIN_COLOR_MODE"),
				spareField(8*1),
				lookupField("Backlight", 8*1, "GARMIN_BACKLIGHT_LEVEL"))),
		},

		{
			description: "Garmin: Color mode",
			pgn:         126720,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("229"),
				matchField("Unknown ID 1", 8*1, "222", "Always 222"),
				matchField("Unknown ID 2", 8*1, "5", "Always 5"),
				matchField("Unknown ID 3", 8*1, "5", "Always 5"),
				matchField("Unknown ID 4", 8*1, "5", "Always 5"),
				spareField(8*2),
				matchLookupField("Mode", 8*1, "13", "GARMIN_COLOR_MODE"),
				spareField(8*1),
				lookupField("Color", 8*1, "GARMIN_COLOR"))),
		},

		/* PDU2 (non addressed) mixed single/fast packet PGN range 0x1F000 to 0x1FEFF (126976 - 130815) */
		{
			description: "0x1F000-0x1FEFF: Standardized mixed single/fast packet non-addressed",
			pgn:         126976,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeMixed,
			fieldList:   [33]pgnField{binaryField("Data", 8*common.FastPacketMaxSize, "")},
			fallback:    true,
			explanation: "Standardized PGNs in PDU2 (non-addressed) mixed single/fast packet PGN range 0x1F000 to " +
				"0x1FEFF (126976 - 130815). " +
				"When this is shown during analysis it means the PGN is not reverse engineered yet.",
		},

		{
			description: "Alert",
			pgn:         126983,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Alert Type", 4, "ALERT_TYPE"),
				lookupField("Alert Category", 4, "ALERT_CATEGORY"),
				uint8Field("Alert System"),
				uint8Field("Alert Sub-System"),
				uint16Field("Alert ID"),
				simpleField("Data Source Network ID NAME", 8*8),
				uint8Field("Data Source Instance"),
				uint8Field("Data Source Index-Source"),
				uint8Field("Alert Occurrence Number"),
				lookupField("Temporary Silence Status", 1, "YES_NO"),
				lookupField("Acknowledge Status", 1, "YES_NO"),
				lookupField("Escalation Status", 1, "YES_NO"),
				lookupField("Temporary Silence Support", 1, "YES_NO"),
				lookupField("Acknowledge Support", 1, "YES_NO"),
				lookupField("Escalation Support", 1, "YES_NO"),
				reservedField(2),
				simpleField("Acknowledge Source Network ID NAME", 8*8),
				lookupField("Trigger Condition", 4, "ALERT_TRIGGER_CONDITION"),
				lookupField("Threshold Status", 4, "ALERT_THRESHOLD_STATUS"),
				uint8Field("Alert Priority"),
				lookupField("Alert State", 8*1, "ALERT_STATE"),
			},
		},

		{
			description: "Alert Response",
			pgn:         126984,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Alert Type", 4, "ALERT_TYPE"),
				lookupField("Alert Category", 4, "ALERT_CATEGORY"),
				uint8Field("Alert System"),
				uint8Field("Alert Sub-System"),
				uint16Field("Alert ID"),
				simpleField("Data Source Network ID NAME", 8*8),
				uint8Field("Data Source Instance"),
				uint8Field("Data Source Index-Source"),
				uint8Field("Alert Occurrence Number"),
				simpleField("Acknowledge Source Network ID NAME", 8*8),
				lookupField("Response Command", 2, "ALERT_RESPONSE_COMMAND"),
				reservedField(6),
			},
		},

		{
			description: "Alert Text",
			pgn:         126985,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Alert Type", 4, "ALERT_TYPE"),
				lookupField("Alert Category", 4, "ALERT_CATEGORY"),
				uint8Field("Alert System"),
				uint8Field("Alert Sub-System"),
				uint16Field("Alert ID"),
				simpleField("Data Source Network ID NAME", 8*8),
				uint8Field("Data Source Instance"),
				uint8Field("Data Source Index-Source"),
				uint8Field("Alert Occurrence Number"),
				lookupField("Language ID", 8*1, "ALERT_LANGUAGE_ID"),
				stringlauField("Alert Text Description"),
				stringlauField("Alert Location Text Description"),
			},
		},

		{
			description: "Alert Configuration",
			pgn:         126986,
			complete:    packetStatusIncomplete | packetStatusIntervalUnknown,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Alert Type", 4, "ALERT_TYPE"),
				lookupField("Alert Category", 4, "ALERT_CATEGORY"),
				uint8Field("Alert System"),
				uint8Field("Alert Sub-System"),
				uint16Field("Alert ID"),
				simpleField("Data Source Network ID NAME", 8*8),
				uint8Field("Data Source Instance"),
				uint8Field("Data Source Index-Source"),
				uint8Field("Alert Occurrence Number"),
				/* Unknown field lengths past this point, except Alert Control is likely 2 bits */
				simpleField("Alert Control", 2),
				simpleField("User Defined Alert Assignment", 2),
				reservedField(4),
				uint8Field("Reactivation Period"),
				uint8Field("Temporary Silence Period"),
				uint8Field("Escalation Period"),
			},
		},

		{
			description: "Alert Threshold",
			pgn:         126987,
			complete:    packetStatusResolutionUnknown | packetStatusIntervalUnknown,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Alert Type", 4, "ALERT_TYPE"),
				lookupField("Alert Category", 4, "ALERT_CATEGORY"),
				uint8Field("Alert System"),
				uint8Field("Alert Sub-System"),
				uint16Field("Alert ID"),
				simpleField("Data Source Network ID NAME", 8*8),
				uint8Field("Data Source Instance"),
				uint8Field("Data Source Index-Source"),
				uint8Field("Alert Occurrence Number"),
				uint8DescField("Number of Parameters", "Total Number of Threshold Parameters"),
				uint8Field("Parameter Number"),
				uint8Field("Trigger Method"),
				uint8Field("Threshold Data Format"),
				simpleField("Threshold Level", 8*8),
			},
			repeatingField1: 10,
			repeatingCount1: 4,
			repeatingStart1: 11,
		},

		{
			description: "Alert Value",
			pgn:         126988,
			complete:    packetStatusResolutionUnknown | packetStatusIntervalUnknown,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Alert Type", 4, "ALERT_TYPE"),
				lookupField("Alert Category", 4, "ALERT_CATEGORY"),
				uint8Field("Alert System"),
				uint8Field("Alert Sub-System"),
				uint16Field("Alert ID"),
				simpleField("Data Source Network ID NAME", 8*8),
				uint8Field("Data Source Instance"),
				uint8Field("Data Source Index-Source"),
				uint8Field("Alert Occurrence Number"),
				uint8DescField("Number of Parameters", "Total Number of Value Parameters"),
				uint8Field("Value Parameter Number"),
				uint8Field("Value Data Format"),
				simpleField("Value Data", 8*8),
			},
			repeatingField1: 10,
			repeatingCount1: 3,
			repeatingStart1: 11,
		},

		/* http://www.maretron.com/support/manuals/GPS100UM_1.2.pdf */
		{
			description: "System Time",
			pgn:         126992,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				lookupField("Source", 4, "SYSTEM_TIME"),
				reservedField(4),
				dateField("Date"),
				timeField("Time"),
			},
			interval: 1000,
			explanation: "The purpose of this PGN is twofold: To provide a regular transmission of UTC time and date. To provide " +
				"synchronism for measurement data.",
		},

		/* http://www.nmea.org/Assets/20140102%20nmea-2000-126993%20heartbeat%20pgn%20corrigendum.pdf */
		/* http://www.nmea.org/Assets/20190624%20NMEA%20Heartbeat%20Information%20Amendment%20AT%2020190623HB.pdf */
		{
			description: "Heartbeat",
			pgn:         126993,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				timeUfix16MsField(
					"Data transmit offset",
					"Offset in transmit time from time of request command: 0x0 = transmit immediately, 0xFFFF = Do not change offset."),
				uint8Field("Sequence Counter"),
				lookupField("Controller 1 State", 2, "CONTROLLER_STATE"),
				lookupField("Controller 2 State", 2, "CONTROLLER_STATE"),
				lookupField("Equipment Status", 2, "EQUIPMENT_STATUS"),
				reservedField(34),
			},
			explanation: "Reception of this PGN confirms that a device is still present on the network.  Reception of this PGN may also be used to " +
				"maintain an address to NAME association table within the receiving device.  The transmission interval may be used by the " +
				"receiving unit to determine the time-out value for the connection supervision.  The value contained in Field 1 of this " +
				"PGN " +
				"reflects the PGN's current Transmission Interval. Changes to this PGN's Transmission Interval shall be reflected in Field " +
				"1.  The transmission interval can only be changed by using the Request Group Function PGN 126208 with no pairs of request " +
				"parameters provided. Field 3 of the Request Group Function PGN 126208 may contain values between 1,000ms and 60,000ms.  " +
				"This PGN cannot be requested by the ISO Request PGN 059904 or Request Group Function PGN 126208. In Request Group " +
				"Function " +
				"PGN 126208, setting Field 3 to a value of 0xFFFF FFFF and Field 4 to a value of 0xFFFF: 'Transmit now without changing " +
				"timing variables.' is prohibited.  The Command Group Function PGN 126208 shall not be used with this PGN.  Fields 3 and 4 " +
				"of this PGN provide information which can be used to distinguish short duration disturbances from permanent failures. See " +
				"ISO 11898 -1 Sections 6.12, 6.13, 6.14, 13.1.1, 13.1.4, 13.1.4.3 and Figure 16 ( node status transition diagram) for " +
				"additional context.",
			url: "http://www.nmea.org/Assets/20140102%20nmea-2000-126993%20heartbeat%20pgn%20corrigendum.pdf",
		},

		{
			description: "Product Information",
			pgn:         126996,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				versionField("NMEA 2000 Version"),
				uint16Field("Product Code"),
				stringFixField("Model ID", 8*32),
				stringFixField("Software Version Code", 8*32),
				stringFixField("Model Version", 8*32),
				stringFixField("Model Serial Code", 8*32),
				uint8Field("Certification Level"),
				uint8Field("Load Equivalency"),
			},
			interval: math.MaxUint16,
			explanation: "Provides product information onto the network that could be important for determining quality of data coming " +
				"from this product.",
		},

		{
			description: "Configuration Information",
			pgn:         126998,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				stringlauField("Installation Description #1"),
				stringlauField("Installation Description #2"),
				stringlauField("Manufacturer Information"),
			},
			interval: math.MaxUint16,
			explanation: "Free-form alphanumeric fields describing the installation (e.g., starboard engine room location) of the " +
				"device and installation notes (e.g., calibration data).",
		},

		/************ PERIODIC DATA PGNs **************/
		/* http://www.nmea.org/Assets/july%202010%20nmea2000_v1-301_app_b_pgn_field_list.pdf */
		/* http://www.maretron.com/support/manuals/USB100UM_1.2.pdf */
		/* http://www8.garmin.com/manuals/GPSMAP4008_NMEA2000NetworkFundamentals.pdf */

		/* http://www.nmea.org/Assets/20130906%20nmea%202000%20%20man%20overboard%20notification%20%28mob%29%20pgn%20127233%20amendment.pdf
		 */
		{
			description: "Man Overboard Notification",
			pgn:         127233,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				uint32DescField("MOB Emitter ID", "Identifier for each MOB emitter, unique to the vessel"),
				lookupField("Man Overboard Status", 3, "MOB_STATUS"),
				reservedField(5),
				timeField("Activation Time"),
				lookupField("Position Source", 3, "MOB_POSITION_SOURCE"),
				reservedField(5),
				dateField("Position Date"),
				timeField("Position Time"),
				latitudeI32Field("Latitude"),
				longitudeI32Field("Longitude"),
				lookupField("COG Reference", 2, "DIRECTION_REFERENCE"),
				reservedField(6),
				angleU16Field("COG", ""),
				speedU16CmField("SOG"),
				mmsiField("MMSI of vessel of origin"),
				lookupField("MOB Emitter Battery Low Status", 3, "LOW_BATTERY"),
				reservedField(5),
			},
			explanation: "The MOB PGN is intended to provide notification from a MOB monitoring system. The included position information may be " +
				"that of the vessel or the MOB device itself as identified in field “X”, position source. Additional information may " +
				"include the current state of the MOB device, time of activation, and MOB device battery status.\n" +
				"This PGN may be used to set a MOB waypoint, or to initiate an alert process.\n" +
				"This PGN may be used to command or register a MOB device emitter Ids or other applicable fields in the message with an " +
				"MOB " +
				"System or other equipment. If the fields in this PGN are configured over the network, the Command Group Function (PGN " +
				"126208) shall be used.\n" +
				"Queries for this PGN shall be requested using either the ISO Request (PGN 059904) or the NMEA Request Group Function (PGN " +
				"126208).\n" +
				"A device receiving an ISO (PGN 059904) for this PGN (127233), shall respond by providing as many of these PGNs (127233) " +
				"as " +
				"necessary for every MOB Emitter ID that has associated data fields.\n" +
				"If a Request Group Function (PGN 126208) requesting this PGN (127233) is received, the receiving device shall respond in " +
				"the following manner:\n" +
				"•If no requested fields have been included with the Request Group Function then the response is to return one or more " +
				"PGNs, just like responding to the ISO Request (PGN 055904) described above.\n" +
				"•If the Request Group Function (PGN 126208) includes the MOB Emitter ID field or MOB Status field, then the response " +
				"shall " +
				"be filtered by these fields contained within this request resulting in one or more PGN (127233) responses.\n" +
				"If the MOB Emitter ID requested is not considered a valid MOB Emitter ID by the receiving device, then the appropriate " +
				"response would be the Acknowledge Group Function (PGN 126208), containing the error state for PGN error code (Field 3) of " +
				"“0x3 = Access denied.” And the requested MOB Emitter ID field parameter error code (Field 6) of “0x3 = Requested or " +
				"command parameter out-of- range;”.\n" +
				"The Default update rate of this PGN is autonomous, as it is dependant upon notification rates of MOB devices.",
		},

		{
			description: "Heading/Track control",
			pgn:         127237,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Rudder Limit Exceeded", 2, "YES_NO"),
				lookupField("Off-Heading Limit Exceeded", 2, "YES_NO"),
				lookupField("Off-Track Limit Exceeded", 2, "YES_NO"),
				lookupField("Override", 2, "YES_NO"),
				lookupField("Steering Mode", 3, "STEERING_MODE"),
				lookupField("Turn Mode", 3, "TURN_MODE"),
				lookupField("Heading Reference", 2, "DIRECTION_REFERENCE"),
				reservedField(5),
				lookupField("Commanded Rudder Direction", 3, "DIRECTION_RUDDER"),
				angleI16Field("Commanded Rudder Angle", ""),
				angleU16Field("Heading-To-Steer (Course)", ""),
				angleU16Field("Track", ""),
				angleU16Field("Rudder Limit", ""),
				angleU16Field("Off-Heading Limit", ""),
				angleI16Field("Radius of Turn Order", ""),
				rotationFix16Field("Rate of Turn Order"),
				distanceFix16MField("Off-Track Limit", ""),
				angleU16Field("Vessel Heading", ""),
			},
			interval: 250,
		},

		/* http://www.maretron.com/support/manuals/RAA100UM_1.0.pdf */
		{
			description: "Rudder",
			pgn:         127245,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				instanceField(),
				lookupField("Direction Order", 3, "DIRECTION_RUDDER"),
				reservedField(5),
				angleI16Field("Angle Order", ""),
				angleI16Field("Position", ""),
				reservedField(8 * 2),
			},
			interval: 100,
		},

		/* NMEA + Simrad AT10 */
		/* http://www.maretron.com/support/manuals/SSC200UM_1.7.pdf */
		/* molly_rose_E80start.kees */
		{
			description: "Vessel Heading",
			pgn:         127250,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				angleU16Field("Heading", ""),
				angleI16Field("Deviation", ""),
				angleI16Field("Variation", ""),
				lookupField("Reference", 2, "DIRECTION_REFERENCE"),
				reservedField(6),
			},
			interval: 100,
		},

		/* http://www.maretron.com/support/manuals/SSC200UM_1.7.pdf */
		/* Lengths observed from Simrad RC42 */
		{
			description: "Rate of Turn",
			pgn:         127251,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList:   [33]pgnField{uint8Field("SID"), rotationFix32Field("Rate"), reservedField(8 * 3)},
			interval:    100,
		},

		{
			description: "Heave",
			pgn:         127252,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList:   [33]pgnField{uint8Field("SID"), distanceFix16CmField("Heave", ""), reservedField(8 * 5)},
		},

		{
			description: "Attitude",
			pgn:         127257,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				angleI16Field("Yaw", ""),
				angleI16Field("Pitch", ""),
				angleI16Field("Roll", ""),
				reservedField(8 * 1),
			},
			interval: 1000,
		},

		/* NMEA + Simrad AT10 */
		/* http://www.maretron.com/support/manuals/GPS100UM_1.2.pdf */
		{
			description: "Magnetic Variation",
			pgn:         127258,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				lookupField("Source", 4, "MAGNETIC_VARIATION"),
				reservedField(4),
				dateField("Age of service"),
				angleI16Field("Variation", ""),
				reservedField(8 * 2),
			},
			interval: 1000,
		},

		/* Engine group PGNs all derived PGN Numbers from              */
		/* http://www.maretron.com/products/pdf/J2K100-Data_Sheet.pdf  */
		/* http://www.floscan.com/html/blue/NMEA2000.php               */
		/* http://www.osukl.com/wp-content/uploads/2015/04/3155-UM.pdf */
		{
			description: "Engine Parameters, Rapid Update",
			pgn:         127488,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				lookupField("Instance", 8*1, "ENGINE_INSTANCE"),
				rotationUfix16RPMField("Speed"),
				pressureUfix16HPAField("Boost Pressure"),
				simpleSignedField("Tilt/Trim", 8*1),
				reservedField(8 * 2),
			},
			interval: 100,
		},

		// http://www.osukl.com/wp-content/uploads/2015/04/3155-UM.pdf
		// samples/susteranna-actisense-serial.raw:
		//   2016-04-09T16:41:39.628Z,2,127489,16,255,26,00,2f,06,ff,ff,e3,73,65,05,ff,7f,72,10,00,00,ff,ff,ff,ff,ff,06,00,00,00,7f,7f
		{
			description: "Engine Parameters, Dynamic",
			pgn:         127489,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Instance", 8*1, "ENGINE_INSTANCE"),
				pressureUfix16HPAField("Oil pressure"),
				temperatureHighField("Oil temperature"),
				temperatureField("Temperature"),
				voltageI1610mvField("Alternator Potential"),
				volumetricFlowField("Fuel Rate"),
				timeUfix32SField("Total Engine hours", ""),
				pressureUfix16HPAField("Coolant Pressure"),
				pressureUfix16KpaField("Fuel Pressure"),
				reservedField(8 * 1),
				bitlookupField("Discrete Status 1", 8*2, "ENGINE_STATUS_1"),
				bitlookupField("Discrete Status 2", 8*2, "ENGINE_STATUS_2"),
				percentageI8Field("Engine Load"),
				percentageI8Field("Engine Torque"),
			},
			interval: 500,
		},

		{
			description: "Electric Drive Status, Dynamic",
			pgn:         127490,
			complete:    packetStatusPDFOnly,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("Inverter/Motor Identifier"),
				simpleField("Operating Mode", 4),
				reservedField(4),
				temperatureField("Motor Temperature"),
				temperatureField("Inverter Temperature"),
				temperatureField("Coolant Temperature"),
				temperatureField("Gear Temperature"),
				uint16Field("Shaft Torque"),
			},
			explanation: "This PGN is used to report status of Electric Drive Status control and can be used with Command Group " +
				"Function (PGN Electric propulsion motor status) to command equipment. ",
		},

		{
			description: "Electric Energy Storage Status, Dynamic",
			pgn:         127491,
			complete:    packetStatusPDFOnly,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("Energy Storage Identifier"),
				uint8Field("State of Charge"),
				timeUfix16MinField("Time Remaining", "Time remaining at current rate of discharge"),
				temperatureField("Highest Cell Temperature"),
				temperatureField("Lowest Cell Temperature"),
				temperatureField("Average Cell Temperature"),
				currentFix16DaField("Max Discharge Current"),
				currentFix16DaField("Max Charge Current"),
				simpleField("Cooling System Status", 4),
				simpleField("Heating System Status", 4),
			},
			explanation: "This PGN is used to provide electric propulsion motor status and relevant data.",
		},

		{
			description: "Transmission Parameters, Dynamic",
			pgn:         127493,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				lookupField("Instance", 8, "ENGINE_INSTANCE"),
				lookupField("Transmission Gear", 2, "GEAR_STATUS"),
				reservedField(6),
				pressureUfix16HPAField("Oil pressure"),
				temperatureHighField("Oil temperature"),
				uint8Field("Discrete Status 1"),
				reservedField(8 * 1),
			},
			interval: 100,
		},

		{
			description: "Electric Drive Information",
			pgn:         127494,
			complete:    packetStatusPDFOnly,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("Inverter/Motor Identifier"),
				simpleField("Motor Type", 4),
				reservedField(4),
				voltageU16100mvField("Motor Voltage Rating"),
				powerU32Field("Maximum Continuous Motor Power"),
				powerU32Field("Maximum Boost Motor Power"),
				temperatureField("Maximum Motor Temperature Rating"),
				rotationUfix16RPMField("Rated Motor Speed"),
				temperatureField("Maximum Controller Temperature Rating"),
				uint16Field("Motor Shaft Torque Rating"),
				voltageU16100mvField("Motor DC-Voltage Derating Threshold"),
				voltageU16100mvField("Motor DC-Voltage Cut Off Threshold"),
				timeUfix32SField("Drive/Motor Hours", ""),
			},
			explanation: "This PGN is used to provide information about electric motor specifications and ratings.",
		},

		{
			description: "Electric Energy Storage Information",
			pgn:         127495,
			complete:    packetStatusPDFOnly,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("Energy Storage Identifier"),
				simpleField("Motor Type", 4),
				reservedField(4),
				simpleField("Storage Chemistry/Conversion", 8),
				temperatureField("Maximum Temperature Derating"),
				temperatureField("Maximum Temperature Shut Off"),
				temperatureField("Minimum Temperature Derating"),
				temperatureField("Minimum Temperature Shut Off"),
				energyUint32Field("Usable Battery Energy"),
				uint8Field("State of Health"),
				uint16Field("Battery Cycle Counter"),
				simpleField("Battery Full Status", 2),
				simpleField("Battery Empty Status", 2),
				reservedField(4),
				uint8Field("Maximum Charge (SOC)"),
				uint8Field("Minimum Charge (SOC)"),
			},
			explanation: "This PGN is used to provide the status on power storage sources such as batteries." +
				"This PGN is new in v3.0 and has not been observed yet; field lengths and precisions are guesses.",
		},

		{
			description: "Trip Parameters, Vessel",
			pgn:         127496,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				timeUfix32MsField("Time to Empty", ""),
				lengthUfix32CmField("Distance to Empty", ""),
				volumeUfix16LField("Estimated Fuel Remaining"),
				timeUfix32MsField("Trip Run Time", ""),
			},
			interval: 1000,
		},

		{
			description: "Trip Parameters, Engine",
			pgn:         127497,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Instance", 8*1, "ENGINE_INSTANCE"),
				volumeUfix16LField("Trip Fuel Used"),
				volumetricFlowField("Fuel Rate, Average"),
				volumetricFlowField("Fuel Rate, Economy"),
				volumetricFlowField("Instantaneous Fuel Economy"),
			},
			interval: 1000,
		},

		{
			description: "Engine Parameters, Static",
			pgn:         127498,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Instance", 8*1, "ENGINE_INSTANCE"),
				rotationUfix16RPMField("Rated Engine Speed"),
				stringFixField("VIN", 8*17),
				stringFixField("Software ID", 8*32),
			},
			interval: math.MaxUint16,
		},

		{
			description: "Load Controller Connection State/Control",
			pgn:         127500,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("Sequence ID"),
				uint8Field("Connection ID"),
				uint8Field("State"),
				uint8Field("Status"),
				uint8Field("Operational Status & Control"),
				uint8Field("PWM Duty Cycle"),
				uint8Field("TimeON"),
				uint8Field("TimeOFF"),
			},
			url: "https://github.com/canboat/canboat/issues/366",
		},

		{
			description: "Binary Switch Bank Status",
			pgn:         127501,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				instanceField(),
				lookupField("Indicator1", 2, "OFF_ON"),
				lookupField("Indicator2", 2, "OFF_ON"),
				lookupField("Indicator3", 2, "OFF_ON"),
				lookupField("Indicator4", 2, "OFF_ON"),
				lookupField("Indicator5", 2, "OFF_ON"),
				lookupField("Indicator6", 2, "OFF_ON"),
				lookupField("Indicator7", 2, "OFF_ON"),
				lookupField("Indicator8", 2, "OFF_ON"),
				lookupField("Indicator9", 2, "OFF_ON"),
				lookupField("Indicator10", 2, "OFF_ON"),
				lookupField("Indicator11", 2, "OFF_ON"),
				lookupField("Indicator12", 2, "OFF_ON"),
				lookupField("Indicator13", 2, "OFF_ON"),
				lookupField("Indicator14", 2, "OFF_ON"),
				lookupField("Indicator15", 2, "OFF_ON"),
				lookupField("Indicator16", 2, "OFF_ON"),
				lookupField("Indicator17", 2, "OFF_ON"),
				lookupField("Indicator18", 2, "OFF_ON"),
				lookupField("Indicator19", 2, "OFF_ON"),
				lookupField("Indicator20", 2, "OFF_ON"),
				lookupField("Indicator21", 2, "OFF_ON"),
				lookupField("Indicator22", 2, "OFF_ON"),
				lookupField("Indicator23", 2, "OFF_ON"),
				lookupField("Indicator24", 2, "OFF_ON"),
				lookupField("Indicator25", 2, "OFF_ON"),
				lookupField("Indicator26", 2, "OFF_ON"),
				lookupField("Indicator27", 2, "OFF_ON"),
				lookupField("Indicator28", 2, "OFF_ON"),
			},
		},

		{
			description: "Switch Bank Control",
			pgn:         127502,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				instanceField(),
				lookupField("Switch1", 2, "OFF_ON"),
				lookupField("Switch2", 2, "OFF_ON"),
				lookupField("Switch3", 2, "OFF_ON"),
				lookupField("Switch4", 2, "OFF_ON"),
				lookupField("Switch5", 2, "OFF_ON"),
				lookupField("Switch6", 2, "OFF_ON"),
				lookupField("Switch7", 2, "OFF_ON"),
				lookupField("Switch8", 2, "OFF_ON"),
				lookupField("Switch9", 2, "OFF_ON"),
				lookupField("Switch10", 2, "OFF_ON"),
				lookupField("Switch11", 2, "OFF_ON"),
				lookupField("Switch12", 2, "OFF_ON"),
				lookupField("Switch13", 2, "OFF_ON"),
				lookupField("Switch14", 2, "OFF_ON"),
				lookupField("Switch15", 2, "OFF_ON"),
				lookupField("Switch16", 2, "OFF_ON"),
				lookupField("Switch17", 2, "OFF_ON"),
				lookupField("Switch18", 2, "OFF_ON"),
				lookupField("Switch19", 2, "OFF_ON"),
				lookupField("Switch20", 2, "OFF_ON"),
				lookupField("Switch21", 2, "OFF_ON"),
				lookupField("Switch22", 2, "OFF_ON"),
				lookupField("Switch23", 2, "OFF_ON"),
				lookupField("Switch24", 2, "OFF_ON"),
				lookupField("Switch25", 2, "OFF_ON"),
				lookupField("Switch26", 2, "OFF_ON"),
				lookupField("Switch27", 2, "OFF_ON"),
				lookupField("Switch28", 2, "OFF_ON"),
			},
		},

		/* http://www.nmea.org/Assets/nmea-2000-corrigendum-1-2010-1.pdf */
		{
			description: "AC Input Status",
			pgn:         127503,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				instanceField(),
				uint8Field("Number of Lines"),
				simpleField("Line", 2),
				lookupField("Acceptability", 2, "ACCEPTABILITY"),
				reservedField(4),
				voltageU1610mvField("Voltage"),
				currentUfix16DaField("Current"),
				frequencyField("Frequency", 0.01),
				currentUfix16DaField("Breaker Size"),
				powerU32Field("Real Power"),
				powerU32VarField("Reactive Power"),
				powerFactorU8Field(),
			},
			interval:        1500,
			repeatingField1: 2,
			repeatingCount1: 10,
			repeatingStart1: 3,
		},

		/* http://www.nmea.org/Assets/nmea-2000-corrigendum-1-2010-1.pdf */
		{
			description: "AC Output Status",
			pgn:         127504,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				instanceField(),
				uint8Field("Number of Lines"),
				lookupField("Line", 2, "LINE"),
				lookupField("Waveform", 3, "WAVEFORM"),
				reservedField(3),
				voltageU1610mvField("Voltage"),
				currentUfix16DaField("Current"),
				frequencyField("Frequency", 0.01),
				currentUfix16DaField("Breaker Size"),
				powerU32Field("Real Power"),
				powerU32VarField("Reactive Power"),
				powerFactorU8Field(),
			},
			interval:        1500,
			repeatingField1: 2,
			repeatingCount1: 10,
			repeatingStart1: 3,
		},

		/* http://www.maretron.com/support/manuals/TLA100UM_1.2.pdf */
		/* Observed from EP65R */
		{
			description: "Fluid Level",
			pgn:         127505,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				simpleField("Instance", 4),
				lookupField("Type", 4, "TANK_TYPE"),
				percentageI16Field("Level"),
				volumeUfix32DlField("Capacity"),
				reservedField(8 * 1),
			},
			interval: 2500,
		},

		{
			description: "DC Detailed Status",
			pgn:         127506,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				instanceField(),
				lookupField("DC Type", 8*1, "DC_SOURCE"),
				uint8Field("State of Charge"),
				uint8Field("State of Health"),
				timeUfix16MinField("Time Remaining", "Time remaining at current rate of discharge"),
				voltageU1610mvField("Ripple Voltage"),
				electricChargeUfix16Ah("Remaining capacity"),
			},
			interval: 1500,
		},

		// http://www.osukl.com/wp-content/uploads/2015/04/3155-UM.pdf
		{
			description: "Charger Status",
			pgn:         127507,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				instanceField(),
				uint8Field("Battery Instance"),
				lookupField("Operating State", 4, "CHARGER_STATE"),
				lookupField("Charge Mode", 4, "CHARGER_MODE"),
				lookupField("Enabled", 2, "OFF_ON"),
				lookupField("Equalization Pending", 2, "OFF_ON"),
				reservedField(4),
				timeUfix16MinField("Equalization Time Remaining", ""),
			},
			interval: 1500,
		},

		{
			description: "Battery Status",
			pgn:         127508,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				instanceField(),
				voltageU1610mvField("Voltage"),
				currentFix16DaField("Current"),
				temperatureField("Temperature"),
				uint8Field("SID"),
			},
			interval: 1500,
		},

		{
			description: "Inverter Status",
			pgn:         127509,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				instanceField(),
				uint8Field("AC Instance"),
				uint8Field("DC Instance"),
				lookupField("Operating State", 4, "INVERTER_STATE"),
				lookupField("Inverter Enable", 2, "OFF_ON"),
				reservedField(2),
			},
			interval: 1500,
			url:      "https://web.archive.org/web/20140913025729/https://www.nmea.org/Assets/20140102%20nmea-2000-127509%20pgn%20corrigendum.pdf",
			explanation: "The NMEA wrote in the link in the URL that this PGN is obsolete and superceded by PGN 127751, but that PGN reference is " +
				"obviously incorrect. They probably meant PGN 127511. " +
				"The other interesting thing is that this PGN is only four bytes long but still referenced as a Fast PGN, which matches " +
				"various sources; see github issue #428.",
		},

		{
			description: "Charger Configuration Status",
			pgn:         127510,
			complete:    packetStatusPDFOnly,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				instanceField(),
				uint8Field("Battery Instance"),
				lookupField("Charger Enable/Disable", 2, "OFF_ON"),
				reservedField(6),
				percentageU8Field("Charge Current Limit"),
				lookupField("Charging Algorithm", 4, "CHARGING_ALGORITHM"),
				lookupField("Charger Mode", 4, "CHARGER_MODE"),
				lookupFieldDesc(
					"Estimated Temperature",
					4,
					"DEVICE_TEMP_STATE",
					"If there is no battery temperature sensor the charger will use this field to steer the charging algorithm"),
				lookupField("Equalize One Time Enable/Disable", 2, "OFF_ON"),
				lookupField("Over Charge Enable/Disable", 2, "OFF_ON"),
				timeUfix16MinField("Equalize Time", ""),
			},
			interval: math.MaxUint16,
		},

		{
			description: "Inverter Configuration Status",
			pgn:         127511,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				instanceField(),
				uint8Field("AC Instance"),
				uint8Field("DC Instance"),
				simpleField("Inverter Enable/Disable", 2),
				reservedField(6),
				uint8Field("Inverter Mode"),
				uint8Field("Load Sense Enable/Disable"),
				uint8Field("Load Sense Power Threshold"),
				uint8Field("Load Sense Interval"),
			},
			interval: math.MaxUint16,
		},

		{
			description: "AGS Configuration Status",
			pgn:         127512,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList:   [33]pgnField{instanceField(), uint8Field("Generator Instance"), uint8Field("AGS Mode"), reservedField(8 * 5)},
			interval:    math.MaxUint16,
		},

		/* #143, @ksltd writes that it is definitely 10 bytes and that
		 * nominal voltage is a lookup, Peukert Exponent and Charge Efficiency
		 * are 8 bits. It follows that Temperature Coefficient must be 8 bits
		 * as well to fit in 10 bytes.
		 *
		 * I'm now actually following https://github.com/ttlappalainen/NMEA2000/
		 * The Supports Equalization is 2 bits, Battery Type, Chemistry and
		 * Nominal voltage are all 4 bits. Capacity and Peukert are both 2 bytes.
		 * but this only adds up to 8 bytes... Maybe the 10 was as this is transmitted
		 * as FAST pgn?
		 */
		{
			description: "Battery Configuration Status",
			pgn:         127513,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				instanceField(),
				lookupField("Battery Type", 4, "BATTERY_TYPE"),
				lookupField("Supports Equalization", 2, "YES_NO"),
				reservedField(2),
				lookupField("Nominal Voltage", 4, "BATTERY_VOLTAGE"),
				lookupField("Chemistry", 4, "BATTERY_CHEMISTRY"),
				electricChargeUfix16Ah("Capacity"),
				percentageI8Field("Temperature Coefficient"),
				peukertField("Peukert Exponent"),
				percentageI8Field("Charge Efficiency Factor"),
			},
			interval: math.MaxUint16,
		},

		{
			description: "AGS Status",
			pgn:         127514,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				instanceField(),
				uint8Field("Generator Instance"),
				uint8Field("AGS Operating State"),
				uint8Field("Generator State"),
				uint8Field("Generator On Reason"),
				uint8Field("Generator Off Reason"),
				reservedField(8 * 2),
			},
			interval: 1500,
		},

		{
			description: "AC Power / Current - Phase A",
			pgn:         127744,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				uint8Field("Connection Number"),
				currentUfix16DaField("AC RMS Current"),
				powerI32Field("Power"),
			},
		},

		{
			description: "AC Power / Current - Phase B",
			pgn:         127745,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				uint8Field("Connection Number"),
				currentUfix16DaField("AC RMS Current"),
				powerI32Field("Power"),
			},
		},

		{
			description: "AC Power / Current - Phase C",
			pgn:         127746,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				uint8Field("Connection Number"),
				currentUfix16DaField("AC RMS Current"),
				powerI32Field("Power"),
			},
		},

		{
			description: "Converter Status",
			pgn:         127750,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				binaryField("SID", 8*1, ""),
				uint8Field("Connection Number"),
				lookupField("Operating State", 8*1, "CONVERTER_STATE"),
				lookupField("Temperature State", 2, "GOOD_WARNING_ERROR"),
				lookupField("Overload State", 2, "GOOD_WARNING_ERROR"),
				lookupField("Low DC Voltage State", 2, "GOOD_WARNING_ERROR"),
				lookupField("Ripple State", 2, "GOOD_WARNING_ERROR"),
				reservedField(8 * 4),
			},
		},

		{
			description: "DC Voltage/Current",
			pgn:         127751,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				binaryField("SID", 8*1, ""),
				uint8Field("Connection Number"),
				voltageU16100mvField("DC Voltage"),
				currentFix24CaField("DC Current"),
				reservedField(8 * 1),
			},
		},

		{
			description: "Leeway Angle",
			pgn:         128000,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList:   [33]pgnField{uint8Field("SID"), angleI16Field("Leeway Angle", ""), reservedField(8 * 5)},
			url:         "https://www.nmea.org/Assets/20170204%20nmea%202000%20leeway%20pgn%20final.pdf",
			explanation: "This PGN provides the Nautical Leeway Angle. Nautical leeway angle is defined as the angle between the " +
				"direction a vessel is heading (pointing) and the direction it is actually travelling (tracking thru the " +
				"water). It is commonly provided by dual-axis speed sensors.",
		},

		{
			description: "Vessel Acceleration",
			pgn:         128001,
			complete:    packetStatusPDFOnly,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				simpleSignedField("Longitudinal Acceleration", 16),
				simpleSignedField("Transverse Acceleration", 16),
				simpleSignedField("Vertical Acceleration", 16),
				reservedField(8 * 1),
			},
			explanation: "The Vessel Acceleration PGN transmits the acceleration of the vessel in all three axes, ahead/astern, " +
				"port/starboard, and up/down.",
		},

		{
			description: "Electric Drive Status, Rapid Update",
			pgn:         128002,
			complete:    packetStatusPDFOnly,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("Inverter/Motor Controller"),
				simpleField("Active Motor Mode", 2),
				simpleField("Brake Mode", 2),
				reservedField(4),
				rotationUfix16RPMField("Rotational Shaft Speed"),
				voltageU16100mvField("Motor DC Voltage"),
				currentFix16DaField("Motor DC Current"),
			},
			explanation: "This PGN is used to provide the Electric Propulsion Drive System Status.",
		},

		{
			description: "Electric Energy Storage Status, Rapid Update",
			pgn:         128003,
			complete:    packetStatusPDFOnly,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("Energy Storage Identifier"),
				simpleField("Battery Status", 2),
				simpleField("Isolation Status", 2),
				simpleField("Battery Error", 4),
				voltageU16100mvField("Battery Voltage"),
				currentFix16DaField("Battery Current"),
				reservedField(8 * 2),
			},
			explanation: "Electric Energy Storage Status message provides important energy storage information global at a rapid update rate.",
		},

		{
			description: "Thruster Control Status",
			pgn:         128006,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				uint8Field("Identifier"),
				lookupField("Direction Control", 4, "THRUSTER_DIRECTION_CONTROL"),
				lookupField("Power Enabled", 2, "OFF_ON"),
				lookupField("Retract Control", 2, "THRUSTER_RETRACT_CONTROL"),
				percentageU8Field("Speed Control"),
				bitlookupField("Control Events", 8*1, "THRUSTER_CONTROL_EVENTS"),
				timeUfix85msField("Command Timeout", ""),
				angleU16Field("Azimuth Control", ""),
			},
		},

		{
			description: "Thruster Information",
			pgn:         128007,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("Identifier"),
				lookupField("Motor Type", 4, "THRUSTER_MOTOR_TYPE"),
				reservedField(4),
				powerU16Field("Power Rating"),
				temperatureField("Maximum Temperature Rating"),
				rotationUfix16RPMField("Maximum Rotational Speed"),
			},
		},

		{
			description: "Thruster Motor Status",
			pgn:         128008,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				uint8Field("Identifier"),
				bitlookupField("Motor Events", 8*1, "THRUSTER_MOTOR_EVENTS"),
				currentUfix8AField("Current"),
				temperatureField("Temperature"),
				timeUfix16MinField("Operating Time", ""),
			},
		},

		/* http://www.maretron.com/support/manuals/DST100UM_1.2.pdf */
		{
			description: "Speed",
			pgn:         128259,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				speedU16CmField("Speed Water Referenced"),
				speedU16CmField("Speed Ground Referenced"),
				lookupField("Speed Water Referenced Type", 8*1, "WATER_REFERENCE"),
				simpleField("Speed Direction", 4),
				reservedField(12),
			},
			interval: 1000,
		},

		/* http://www.maretron.com/support/manuals/DST100UM_1.2.pdf */
		{
			description: "Water Depth",
			pgn:         128267,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				lengthUfix32CmField("Depth", "Depth below transducer"),
				distanceFix16MmField("Offset", "Distance between transducer and surface (positive) or keel (negative)"),
				lengthUfix8DamField("Range", "Max measurement range"),
			},
			interval: 1000,
		},

		/* http://www.nmea.org/Assets/nmea-2000-digital-interface-white-paper.pdf */
		{
			description: "Distance Log",
			pgn:         128275,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				dateField("Date"),
				timeField("Time"),
				lengthUfix32MField("Log", "Total cumulative distance"),
				lengthUfix32MField("Trip Log", "Distance since last reset"),
			},
			interval: 1000,
		},

		{
			description: "Tracked Target Data",
			pgn:         128520,
			complete:    packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				simpleDescField("Target ID #", 8*1, "Number of route, waypoint, event, mark, etc."),
				lookupField("Track Status", 2, "TRACKING"),
				lookupField("Reported Target", 1, "YES_NO"),
				lookupField("Target Acquisition", 1, "TARGET_ACQUISITION"),
				lookupField("Bearing Reference", 2, "DIRECTION_REFERENCE"),
				reservedField(2),
				angleU16Field("Bearing", ""),
				lengthUfix32MmField("Distance"),
				angleU16Field("Course", ""),
				speedU16CmField("Speed"),
				lengthUfix32CmField("CPA", ""),
				timeFix32MsField("TCPA", "negative = time elapsed since event, positive = time to go"),
				timeField("UTC of Fix"),
				stringFixField("Name", 8*common.FastPacketMaxSize),
			},
			interval: 1000,
		},

		{
			description: "Elevator Car Status",
			pgn:         128538,
			complete:    packetStatusPDFOnly,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				uint8Field("Elevator Car ID"),
				uint8Field("Elevator Car Usage"),
				simpleField("Smoke Sensor Status", 2),
				simpleField("Limit Switch Sensor Status", 2),
				simpleField("Proximity Switch Sensor Status", 2),
				simpleField("Inertial Measurement Unit (IMU) Sensor Status", 2),
				simpleField("Elevator Load Limit Status", 2),
				simpleField("Elevator Load Balance Status", 2),
				simpleField("Elevator Load Sensor 1 Status", 2),
				simpleField("Elevator Load Sensor 2 Status", 2),
				simpleField("Elevator Load Sensor 3 Status", 2),
				simpleField("Elevator Load Sensor 4 Status", 2),
				reservedField(4),
				simpleField("Elevator Car Motion Status", 2),
				simpleField("Elevator Car Door Status", 2),
				simpleField("Elevator Car Emergency Button Status", 2),
				simpleField("Elevator Car Buzzer Status", 2),
				simpleField("Open Door Button Status", 2),
				simpleField("Close Door Button Status", 2),
				reservedField(4),
				uint8Field("Current Deck"),
				uint8Field("Destination Deck"),
				uint8Field("Total Number of Decks"),
				uint16Field("Weight of Load Cell 1"),
				uint16Field("Weight of Load Cell 2"),
				uint16Field("Weight of Load Cell 3"),
				uint16Field("Weight of Load Cell 4"),
				speedI16CmField("Speed of Elevator Car"),
				simpleField("Elevator Brake Status", 2),
				simpleField("Elevator Motor rotation control Status", 2),
				reservedField(4),
			},
			explanation: "This PGN provides the status information of an elevator car. This includes the elevator car id and type, " +
				"sensors for load and weight limits, smoke detection, door status, motor status, and brake status. Also " +
				"provided are weight and speed measurements, current and destination deck location, proximity switch status, " +
				"inertial measurement unit status and Emergency button and buzzer status.",
		},

		{
			description: "Elevator Motor Control",
			pgn:         128768,
			complete:    packetStatusPDFOnly,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				uint8Field("Elevator Car ID"),
				uint8Field("Elevator Car Usage"),
				simpleField("Motor Acceleration/Deceleration profile selection", 4),
				simpleField("Motor Rotational Control Status", 2),
				reservedField(2 + 8*4),
			},
			explanation: "This PGN provides the status of an elevator motor controller. Settings of the elevator motor controller may " +
				"be changed using the NMEA Command Group Function.",
		},

		{
			description: "Elevator Deck Push Button",
			pgn:         128769,
			complete:    packetStatusPDFOnly,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				uint8Field("Elevator Call Button ID"),
				uint8Field("Deck Button ID"),
				uint8Field("Elevator Car Usage"),
				uint8Field("Elevator Car Button Selection"),
				reservedField(8 * 3),
			},
			explanation: "Transmit data of Deck controller to Elevator Main controller.",
		},

		{
			description: "Windlass Control Status",
			pgn:         128776,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				uint8Field("Windlass ID"),
				lookupField("Windlass Direction Control", 2, "WINDLASS_DIRECTION"),
				lookupField("Anchor Docking Control", 2, "OFF_ON"),
				lookupField("Speed Control Type", 2, "SPEED_TYPE"),
				reservedField(2),
				binaryField("Speed Control", 8*1, "0=Off,Single speed:1-100=On,Dual Speed:1-49=Slow/50-100=Fast,Proportional:10-100"),
				lookupField("Power Enable", 2, "OFF_ON"),
				lookupField("Mechanical Lock", 2, "OFF_ON"),
				lookupField("Deck and Anchor Wash", 2, "OFF_ON"),
				lookupField("Anchor Light", 2, "OFF_ON"),
				timeUfix85msField("Command Timeout", "If timeout elapses the thruster stops operating and reverts to static mode"),
				bitlookupField("Windlass Control Events", 4, "WINDLASS_CONTROL"),
				reservedField(12),
			},
			url: "https://www.nmea.org/Assets/20190613%20windlass%20amendment,%20128776,%20128777,%20128778.pdf",
		},

		{
			description: "Anchor Windlass Operating Status",
			pgn:         128777,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				uint8Field("Windlass ID"),
				lookupField("Windlass Direction Control", 2, "WINDLASS_DIRECTION"),
				lookupField("Windlass Motion Status", 2, "WINDLASS_MOTION"),
				lookupField("Rode Type Status", 2, "RODE_TYPE"),
				reservedField(2),
				lengthUfix16DmField("Rode Counter Value"),
				speedU16CmField("Windlass Line Speed"),
				lookupField("Anchor Docking Status", 2, "DOCKING_STATUS"),
				bitlookupField("Windlass Operating Events", 6, "WINDLASS_OPERATION"),
			},
			url: "https://www.nmea.org/Assets/20190613%20windlass%20amendment,%20128776,%20128777,%20128778.pdf",
		},

		{
			description: "Anchor Windlass Monitoring Status",
			pgn:         128778,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				uint8Field("Windlass ID"),
				bitlookupField("Windlass Monitoring Events", 8, "WINDLASS_MONITORING"),
				voltageUfix8200mvField("Controller voltage"),
				currentUfix8AField("Motor current"),
				timeUfix16MinField("Total Motor Time", ""),
				reservedField(8 * 1),
			},
			url: "https://www.nmea.org/Assets/20190613%20windlass%20amendment,%20128776,%20128777,%20128778.pdf",
		},

		{
			description: "Linear Actuator Control/Status",
			pgn:         128780,
			complete:    packetStatusPDFOnly,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("Actuator Identifier"),
				uint8Field("Commanded Device Position"),
				uint8Field("Device Position"),
				uint16Field("Maximum Device Travel"),
				uint8Field("Direction of Travel"),
				reservedField(8 * 2),
			},
			explanation: "Actuator is a broad description of any device that embodies moving an object between two fixed limits, such as raising or " +
				"lowering an outboard engine assembly. In the context of this PGN, the word \"Device\" refers to the object being moved. " +
				"In " +
				"the case of multiple Actuators per controller, the Actuator Identifier field specifies which Actuator the PGN message is " +
				"intended for, and all following data fields refer only to that Actuator. This PGN supports manufacturer calibrated " +
				"systems " +
				"and retrofit systems where it is impractical for the installer to enter the Maximum Travel distance of the device.",
		},

		{
			description: "Position, Rapid Update",
			pgn:         129025,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList:   [33]pgnField{latitudeI32Field("Latitude"), longitudeI32Field("Longitude")},
			interval:    100,
		},

		{
			description: "COG & SOG, Rapid Update",
			pgn:         129026,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				lookupField("COG Reference", 2, "DIRECTION_REFERENCE"),
				reservedField(6),
				angleU16Field("COG", ""),
				speedU16CmField("SOG"),
				reservedField(8 * 2),
			},
			interval: 250,
			url:      "http://www.maretron.com/support/manuals/GPS100UM_1.2.pdf",
		},

		{
			description: "Position Delta, Rapid Update",
			pgn:         129027,
			complete:    packetStatusNotSeen,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				simpleField("Time Delta", 8*2),
				simpleSignedField("Latitude Delta", 8*2),
				simpleSignedField("Longitude Delta", 8*2),
				reservedField(8 * 1),
			},
			interval: 100,
		},

		{
			description: "Altitude Delta, Rapid Update",
			pgn:         129028,
			complete:    packetStatusNotSeen,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				simpleSignedField("Time Delta", 8*2),
				simpleField("GNSS Quality", 2),
				simpleField("Direction", 2),
				reservedField(4),
				angleU16Field("COG", ""),
				simpleSignedField("Altitude Delta", 8*2),
			},
			interval: 100,
		},

		/* http://www.maretron.com/support/manuals/GPS100UM_1.2.pdf */
		{
			description: "GNSS Position Data",
			pgn:         129029,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				dateField("Date"),
				timeField("Time"),
				latitudeI64Field("Latitude"),
				longitudeI64Field("Longitude"),
				distanceFix64Field("Altitude", "Altitude referenced to WGS-84"),
				lookupField("GNSS type", 4, "GNS"),
				lookupField("Method", 4, "GNS_METHOD"),
				lookupField("Integrity", 2, "GNS_INTEGRITY"),
				reservedField(6),
				simpleDescField("Number of SVs", 8*1, "Number of satellites used in solution"),
				dilutionOfPrecisionFix16Field("HDOP", "Horizontal dilution of precision"),
				dilutionOfPrecisionFix16Field("PDOP", "Positional dilution of precision"),
				distanceFix32CmField("Geoidal Separation", "Geoidal Separation"),
				simpleDescField("Reference Stations", 8*1, "Number of reference stations"),
				lookupField("Reference Station Type", 4, "GNS"),
				simpleField("Reference Station ID", 12),
				timeUfix16CsField("Age of DGNSS Corrections", ""),
			},
			interval:        1000,
			repeatingField1: 15,
			repeatingCount1: 3,
			repeatingStart1: 16,
		},

		{
			description: "Time & Date",
			pgn:         129033,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList:   [33]pgnField{dateField("Date"), timeField("Time"), timeFix16MinField("Local Offset")},
			interval:    1000,
		},

		{
			description: "AIS Class A Position Report",
			pgn:         129038,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Message ID", 6, "AIS_MESSAGE_ID"),
				lookupField("Repeat Indicator", 2, "REPEAT_INDICATOR"),
				mmsiField("User ID"),
				latitudeI32Field("Longitude"),
				longitudeI32Field("Latitude"),
				lookupField("Position Accuracy", 1, "POSITION_ACCURACY"),
				lookupField("RAIM", 1, "RAIM_FLAG"),
				lookupFieldDesc("Time Stamp", 6, "TIME_STAMP", "0-59 = UTC second when the report was generated"),
				angleU16Field("COG", ""),
				speedU16CmField("SOG"),
				binaryField("Communication State",
					19,
					"Information used by the TDMA slot allocation algorithm and synchronization information"),
				lookupField("AIS Transceiver information", 5, "AIS_TRANSCEIVER"),
				angleU16Field("Heading", "True heading"),
				rotationFix16Field("Rate of Turn"),
				lookupField("Nav Status", 4, "NAV_STATUS"),
				lookupField("Special Maneuver Indicator", 2, "AIS_SPECIAL_MANEUVER"),
				reservedField(2),
				spareField(3),
				reservedField(5),
				uint8Field("Sequence ID"),
			},
			url:      "https://www.itu.int/rec/R-REC-M.1371-5-201402-I/en",
			interval: math.MaxUint16,
		},

		{
			description: "AIS Class B Position Report",
			pgn:         129039,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Message ID", 6, "AIS_MESSAGE_ID"),
				lookupField("Repeat Indicator", 2, "REPEAT_INDICATOR"),
				mmsiField("User ID"),
				longitudeI32Field("Longitude"),
				latitudeI32Field("Latitude"),
				lookupField("Position Accuracy", 1, "POSITION_ACCURACY"),
				lookupField("RAIM", 1, "RAIM_FLAG"),
				lookupField("Time Stamp", 6, "TIME_STAMP"),
				angleU16Field("COG", ""),
				speedU16CmField("SOG"),
				binaryField("Communication State",
					19,
					"Information used by the TDMA slot allocation algorithm and synchronization information"),
				lookupField("AIS Transceiver information", 5, "AIS_TRANSCEIVER"),
				angleU16Field("Heading", "True heading"),
				spareNamedField("Regional Application", 8),
				spareNamedField("Regional Application B", 2),
				lookupField("Unit type", 1, "AIS_TYPE"),
				lookupFieldDesc("Integrated Display", 1, "YES_NO", "Whether the unit can show messages 12 and 14"),
				lookupField("DSC", 1, "YES_NO"),
				lookupField("Band", 1, "AIS_BAND"),
				lookupField("Can handle Msg 22", 1, "YES_NO"),
				lookupField("AIS mode", 1, "AIS_MODE"),
				lookupField("AIS communication state", 1, "AIS_COMMUNICATION_STATE"),
				reservedField(15),
			},
			url:      "https://www.itu.int/rec/R-REC-M.1371-5-201402-I/en",
			interval: math.MaxUint16,
		},

		{
			description: "AIS Class B Extended Position Report",
			pgn:         129040,
			complete:    packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Message ID", 6, "AIS_MESSAGE_ID"),
				lookupField("Repeat Indicator", 2, "REPEAT_INDICATOR"),
				mmsiField("User ID"),
				longitudeI32Field("Longitude"),
				latitudeI32Field("Latitude"),
				lookupField("Position Accuracy", 1, "POSITION_ACCURACY"),
				lookupField("RAIM", 1, "RAIM_FLAG"),
				lookupField("Time Stamp", 6, "TIME_STAMP"),
				angleU16Field("COG", ""),
				speedU16CmField("SOG"),
				spareNamedField("Regional Application", 8),
				spareNamedField("Regional Application B", 4),
				reservedField(4),
				lookupField("Type of ship", 8*1, "SHIP_TYPE"),
				angleU16Field("True Heading", ""),
				reservedField(4),
				lookupField("GNSS type", 4, "POSITION_FIX_DEVICE"),
				lengthUfix16DmField("Length"),
				lengthUfix16DmField("Beam"),
				lengthUfix16DmField("Position reference from Starboard"),
				lengthUfix16DmField("Position reference from Bow"),
				stringFixField("Name", 8*20),
				lookupField("DTE", 1, "AVAILABLE"),
				lookupField("AIS mode", 1, "AIS_MODE"),
				spareField(4),
				lookupField("AIS Transceiver information", 5, "AIS_TRANSCEIVER"),
				reservedField(5),
			},
			url:      "https://www.itu.int/rec/R-REC-M.1371-5-201402-I/en",
			interval: math.MaxUint16,
		},

		{
			description: "AIS Aids to Navigation (AtoN) Report",
			pgn:         129041,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Message ID", 6, "AIS_MESSAGE_ID"),
				lookupField("Repeat Indicator", 2, "REPEAT_INDICATOR"),
				mmsiField("User ID"),
				longitudeI32Field("Longitude"),
				latitudeI32Field("Latitude"),
				lookupField("Position Accuracy", 1, "POSITION_ACCURACY"),
				lookupField("RAIM", 1, "RAIM_FLAG"),
				lookupField("Time Stamp", 6, "TIME_STAMP"),
				lengthUfix16DmField("Length/Diameter"),
				lengthUfix16DmField("Beam/Diameter"),
				lengthUfix16DmField("Position Reference from Starboard Edge"),
				lengthUfix16DmField("Position Reference from True North Facing Edge"),
				lookupField("AtoN Type", 5, "ATON_TYPE"),
				lookupField("Off Position Indicator", 1, "YES_NO"),
				lookupField("Virtual AtoN Flag", 1, "YES_NO"),
				lookupField("Assigned Mode Flag", 1, "AIS_ASSIGNED_MODE"),
				spareField(1),
				lookupField("Position Fixing Device Type", 4, "POSITION_FIX_DEVICE"),
				reservedField(3),
				binaryField("AtoN Status", 8, "00000000 = default"),
				lookupField("AIS Transceiver information", 5, "AIS_TRANSCEIVER"),
				reservedField(3),
				stringlauField("AtoN Name"),
			},
			url:      "https://www.itu.int/rec/R-REC-M.1371-5-201402-I/en",
			interval: math.MaxUint16,
		},

		{
			description: "Datum",
			pgn:         129044,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				stringFixDescField("Local Datum",
					8*4,
					"defined in IHO Publication S-60, Appendices B and C. First three chars are datum ID as per IHO tables."+
						" Fourth char is local datum subdivision code."),
				latitudeI32Field("Delta Latitude"),
				longitudeI32Field("Delta Longitude"),
				distanceFix32CmField("Delta Altitude", ""),
				stringFixDescField("Reference Datum",
					8*4,
					"defined in IHO Publication S-60, Appendices B and C."+
						" First three chars are datum ID as per IHO tables."+
						" Fourth char is local datum subdivision code."),
			},
			interval: 10000,
		},

		{
			description: "User Datum",
			pgn:         129045,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				distanceFix32CmField("Delta X", "Delta shift in X axis from WGS 84"),
				distanceFix32CmField("Delta Y", "Delta shift in Y axis from WGS 84"),
				distanceFix32CmField("Delta Z", "Delta shift in Z axis from WGS 84"),
				floatField(
					"Rotation in X",
					"",
					"Rotational shift in X axis from WGS 84. Rotations presented use the geodetic sign convention.  When looking along the "+
						"positive axis towards the origin, counter-clockwise rotations are positive."),
				floatField(
					"Rotation in Y",
					"",
					"Rotational shift in Y axis from WGS 84. Rotations presented use the geodetic sign convention.  When looking along the "+
						"positive axis towards the origin, counter-clockwise rotations are positive."),
				floatField(
					"Rotation in Z",
					"",
					"Rotational shift in Z axis from WGS 84. Rotations presented use the geodetic sign convention.  When looking along the "+
						"positive axis towards the origin, counter-clockwise rotations are positive."),
				floatField("Scale", "ppm", ""),
				distanceFix32CmField("Ellipsoid Semi-major Axis", "Semi-major axis (a) of the User Datum ellipsoid"),
				floatField("Ellipsoid Flattening Inverse", "", "Flattening (1/f) of the User Datum ellipsoid"),
				stringFixDescField("Datum Name",
					8*4,
					"4 character code from IHO Publication S-60,Appendices B and C."+
						" First three chars are datum ID as per IHO tables."+
						" Fourth char is local datum subdivision code."),
			},
			interval: math.MaxUint16,
		},

		{
			description: "Cross Track Error",
			pgn:         129283,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				lookupField("XTE mode", 4, "RESIDUAL_MODE"),
				reservedField(2),
				lookupField("Navigation Terminated", 2, "YES_NO"),
				distanceFix32CmField("XTE", ""),
				reservedField(8 * 2),
			},
			interval: 1000,
		},

		{
			description: "Navigation Data",
			pgn:         129284,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				lengthUfix32CmField("Distance to Waypoint", ""),
				lookupField("Course/Bearing reference", 2, "DIRECTION_REFERENCE"),
				lookupField("Perpendicular Crossed", 2, "YES_NO"),
				lookupField("Arrival Circle Entered", 2, "YES_NO"),
				lookupField("Calculation Type", 2, "BEARING_MODE"),
				timeField("ETA Time"),
				dateField("ETA Date"),
				angleU16Field("Bearing, Origin to Destination Waypoint", ""),
				angleU16Field("Bearing, Position to Destination Waypoint", ""),
				uint32Field("Origin Waypoint Number"),
				uint32Field("Destination Waypoint Number"),
				latitudeI32Field("Destination Latitude"),
				longitudeI32Field("Destination Longitude"),
				speedI16CmField("Waypoint Closing Velocity"),
			},
			interval: 1000,
		},

		{
			description: "Navigation - Route/WP Information",
			pgn:         129285,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint16Field("Start RPS#"),
				uint16Field("nItems"),
				uint16Field("Database ID"),
				uint16Field("Route ID"),
				lookupField("Navigation direction in route", 3, "DIRECTION"),
				lookupField("Supplementary Route/WP data available", 2, "OFF_ON"),
				reservedField(3),
				stringlauField("Route Name"),
				reservedField(8 * 1),
				uint16Field("WP ID"),
				stringlauField("WP Name"),
				latitudeI32Field("WP Latitude"),
				longitudeI32Field("WP Longitude"),
			},
			interval:        math.MaxUint16,
			repeatingField1: 2,
			repeatingCount1: 4,
			repeatingStart1: 10,
		},

		{
			description: "Set & Drift, Rapid Update",
			pgn:         129291,
			complete:    packetStatusNotSeen,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				lookupField("Set Reference", 2, "DIRECTION_REFERENCE"),
				reservedField(6),
				angleU16Field("Set", ""),
				speedU16CmField("Drift"),
				reservedField(8 * 2),
			},
			interval: 1000,
		},

		{
			description: "Navigation - Route / Time to+from Mark",
			pgn:         129301,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				timeFix32MsField("Time to mark", "negative = elapsed since event, positive = time to go"),
				lookupField("Mark Type", 4, "MARK_TYPE"),
				reservedField(4),
				uint32Field("Mark ID"),
			},
			interval: 1000,
		},

		{
			description: "Bearing and Distance between two Marks",
			pgn:         129302,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				lookupField("Bearing Reference", 2, "DIRECTION_REFERENCE"),
				lookupField("Calculation Type", 2, "BEARING_MODE"),
				reservedField(4),
				angleU16Field("Bearing, Origin to Destination", ""),
				lengthUfix32CmField("Distance", ""),
				lookupField("Origin Mark Type", 4, "MARK_TYPE"),
				lookupField("Destination Mark Type", 4, "MARK_TYPE"),
				uint32Field("Origin Mark ID"),
				uint32Field("Destination Mark ID"),
			},
			interval: 1000,
		},

		/* http://www.maretron.com/support/manuals/GPS100UM_1.2.pdf */
		/* Haven't seen this yet (no way to send PGN 059904 yet) so lengths unknown */
		{
			description: "GNSS Control Status",
			pgn:         129538,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				simpleDescField("SV Elevation Mask", 8*2, "Will not use SV below this elevation"),
				dilutionOfPrecisionUfix16Field("PDOP Mask", "Will not report position above this PDOP"),
				dilutionOfPrecisionUfix16Field("PDOP Switch", "Will report 2D position above this PDOP"),
				signaltonoiseratioUfix16Field("SNR Mask", "Will not use SV below this SNR"),
				lookupField("GNSS Mode (desired)", 3, "GNSS_MODE"),
				lookupField("DGNSS Mode (desired)", 3, "DGNSS_MODE"),
				simpleField("Position/Velocity Filter", 2),
				simpleField("Max Correction Age", 8*2),
				lengthUfix16CmField("Antenna Altitude for 2D Mode"),
				lookupField("Use Antenna Altitude for 2D Mode", 2, "YES_NO"),
				reservedField(6),
			},
			interval: math.MaxUint16,
		},

		/* http://www.maretron.com/support/manuals/GPS100UM_1.2.pdf */
		{
			description: "GNSS DOPs",
			pgn:         129539,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				lookupField("Desired Mode", 3, "GNSS_MODE"),
				lookupField("Actual Mode", 3, "GNSS_MODE"),
				reservedField(2),
				dilutionOfPrecisionFix16Field("HDOP", "Horizontal dilution of precision"),
				dilutionOfPrecisionFix16Field("VDOP", "Vertical dilution of precision"),
				dilutionOfPrecisionFix16Field("TDOP", "Time dilution of precision"),
			},
			interval: 1000,
		},

		{
			description: "GNSS Sats in View",
			pgn:         129540,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				lookupField("Range Residual Mode", 2, "RANGE_RESIDUAL_MODE"),
				reservedField(6),
				uint8Field("Sats in View"),
				uint8Field("PRN"),
				angleI16Field("Elevation", ""),
				angleU16Field("Azimuth", ""),
				signaltonoiseratioUfix16Field("SNR", ""),
				int32Field("Range residuals", ""),
				lookupField("Status", 4, "SATELLITE_STATUS"),
				reservedField(4),
			},
			interval:        1000,
			repeatingField1: 4,
			repeatingCount1: 7,
			repeatingStart1: 5,
		},

		{
			description: "GPS Almanac Data",
			pgn:         129541,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("PRN"),
				uint16Field("GPS Week number"),
				binaryField("SV Health Bits", 8*1, ""),
				unsignedAlmanacParameterField("Eccentricity", 8*2, math.Pow(2, -21), "m/m", "'e' in table 20-VI in ICD-GPS-200"),
				unsignedAlmanacParameterField("Almanac Reference Time", 8*1, math.Pow(2, 12), "s", "'t~oa~' in table 20-VI in ICD-GPS-200"),
				signedAlmanacParameterField("Inclination Angle",
					8*2,
					math.Pow(2, -19),
					"semi-circle",
					"'\u03b4~i~' in table 20-VI in ICD-GPS-200"),
				signedAlmanacParameterField("Rate of Right Ascension",
					8*2,
					math.Pow(2, -38),
					"semi-circle/s",
					"'\u0307\u2126' in table 20-VI in ICD-GPS-200"),
				unsignedAlmanacParameterField("Root of Semi-major Axis",
					8*3,
					math.Pow(2, -11),
					"sqrt(m)",
					"'\u221a a' in table 20-VI in ICD-GPS-200"),
				signedAlmanacParameterField("Argument of Perigee",
					8*3,
					math.Pow(2, -23),
					"semi-circle",
					"'\u2126~0~' in table 20-VI in ICD-GPS-200"),
				signedAlmanacParameterField("Longitude of Ascension Node",
					8*3,
					math.Pow(2, -23),
					"semi-circle",
					"'\u03c9' in table 20-VI in ICD-GPS-200"),
				signedAlmanacParameterField("Mean Anomaly", 8*3, math.Pow(2, -23), "semi-circle", "'M~0~' in table 20-VI in ICD-GPS-200"),
				signedAlmanacParameterField("Clock Parameter 1", 11, math.Pow(2, -20), "s", "'a~f0~' in table 20-VI in ICD-GPS-200"),
				signedAlmanacParameterField("Clock Parameter 2", 11, math.Pow(2, -38), "s/s", "'a~f1~' in table 20-VI in ICD-GPS-200"),
				reservedField(2),
			},
			interval: math.MaxUint16,
		},

		{
			description: "GNSS Pseudorange Noise Statistics",
			pgn:         129542,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				uint16Field("RMS of Position Uncertainty"),
				uint8Field("STD of Major axis"),
				uint8Field("STD of Minor axis"),
				uint8Field("Orientation of Major axis"),
				uint8Field("STD of Lat Error"),
				uint8Field("STD of Lon Error"),
				uint8Field("STD of Alt Error"),
			},
			interval: 1000,
		},

		{
			description: "GNSS RAIM Output",
			pgn:         129545,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				simpleField("Integrity flag", 4),
				reservedField(4),
				uint8Field("Latitude expected error"),
				uint8Field("Longitude expected error"),
				uint8Field("Altitude expected error"),
				uint8Field("SV ID of most likely failed sat"),
				uint8Field("Probability of missed detection"),
				uint8Field("Estimate of pseudorange bias"),
				uint8Field("Std Deviation of bias"),
			},
			interval: math.MaxUint16,
		},

		{
			description: "GNSS RAIM Settings",
			pgn:         129546,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("Radial Position Error Maximum Threshold"),
				uint8Field("Probability of False Alarm"),
				uint8Field("Probability of Missed Detection"),
				uint8Field("Pseudorange Residual Filtering Time Constant"),
				reservedField(8 * 4),
			},
			interval: math.MaxUint16,
		},

		{
			description: "GNSS Pseudorange Error Statistics",
			pgn:         129547,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				uint16Field("RMS Std Dev of Range Inputs"),
				uint8Field("Std Dev of Major error ellipse"),
				uint8Field("Std Dev of Minor error ellipse"),
				uint8Field("Orientation of error ellipse"),
				uint8Field("Std Dev Lat Error"),
				uint8Field("Std Dev Lon Error"),
				uint8Field("Std Dev Alt Error"),
			},
			interval: math.MaxUint16,
		},

		{
			description: "DGNSS Corrections",
			pgn:         129549,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				uint16Field("Reference Station ID"),
				uint16Field("Reference Station Type"),
				uint8Field("Time of corrections"),
				uint8Field("Station Health"),
				reservedField(8 * 1),
				uint8Field("Satellite ID"),
				uint8Field("PRC"),
				uint8Field("RRC"),
				uint8Field("UDRE"),
				uint8Field("IOD"),
			},
			interval: math.MaxUint16,
		},

		{
			description: "GNSS Differential Correction Receiver Interface",
			pgn:         129550,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("Channel"),
				uint8Field("Frequency"),
				uint8Field("Serial Interface Bit Rate"),
				uint8Field("Serial Interface Detection Mode"),
				uint8Field("Differential Source"),
				uint8Field("Differential Operation Mode"),
			},
			interval: math.MaxUint16,
		},

		{
			description: "GNSS Differential Correction Receiver Signal",
			pgn:         129551,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				uint8Field("Channel"),
				uint8Field("Signal Strength"),
				uint8Field("Signal SNR"),
				uint8Field("Frequency"),
				uint8Field("Station Type"),
				uint8Field("Station ID"),
				uint8Field("Differential Signal Bit Rate"),
				uint8Field("Differential Signal Detection Mode"),
				uint8Field("Used as Correction Source"),
				reservedField(8 * 1),
				uint8Field("Differential Source"),
				uint8Field("Time since Last Sat Differential Sync"),
				uint8Field("Satellite Service ID No."),
			},
			interval: math.MaxUint16,
		},

		{
			description: "GLONASS Almanac Data",
			pgn:         129556,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8DescField("PRN", "Satellite ID number"),
				uint16DescField("NA", "Calendar day count within the four year period beginning with the previous leap year"),
				reservedField(2),
				simpleDescField("CnA", 1, "Generalized health of the satellite"),
				simpleDescField("HnA", 5, "Carrier frequency number"),
				simpleDescField("(epsilon)nA", 16, "Eccentricity"),
				simpleDescField("(deltaTnA)DOT", 8, "Rate of change of the draconitic circling time"),
				simpleDescField("(omega)nA", 16, "Rate of change of the draconitic circling time"),
				simpleDescField("(delta)TnA", 24, "Correction to the average value of the draconitic circling time"),
				simpleDescField("tnA", 24, "Time of the ascension node"),
				simpleDescField("(lambda)nA", 24, "Greenwich longitude of the ascension node"),
				simpleDescField("(delta)inA", 24, "Correction to the average value of the inclination angle"),
				simpleDescField("(tau)cA", 28, "System time scale correction"),
				simpleDescField("(tau)nA", 12, "Course value of the time scale shift"),
			},
			explanation: "Almanac data for GLONASS products. The alamant contains satellite vehicle course orbital parameters. These " +
				"parameters are described in the GLONASS ICS Section 4.5 Table 4.3. See URL.",
			url:      "https://www.unavco.org/help/glossary/docs/ICD_GLONASS_5.1_%282008%29_en.pdf",
			interval: math.MaxUint16,
		},

		{
			description: "AIS DGNSS Broadcast Binary Message",
			pgn:         129792,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Message ID", 6, "AIS_MESSAGE_ID"),
				simpleField("Repeat Indicator", 2),
				mmsiField("Source ID"),
				reservedField(1),
				lookupField("AIS Transceiver information", 5, "AIS_TRANSCEIVER"),
				spareField(2),
				longitudeI32Field("Longitude"),
				latitudeI32Field("Latitude"),
				reservedField(3),
				spareField(5),
				uint16Field("Number of Bits in Binary Data Field"),
				binaryField("Binary Data", lenVariable, ""),
			},
			url:      "https://www.itu.int/rec/R-REC-M.1371-5-201402-I/en",
			interval: math.MaxUint16,
		},

		{
			description: "AIS UTC and Date Report",
			pgn:         129793,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Message ID", 6, "AIS_MESSAGE_ID"),
				lookupField("Repeat Indicator", 2, "REPEAT_INDICATOR"),
				mmsiField("User ID"),
				longitudeI32Field("Longitude"),
				latitudeI32Field("Latitude"),
				lookupField("Position Accuracy", 1, "POSITION_ACCURACY"),
				lookupField("RAIM", 1, "RAIM_FLAG"),
				reservedField(6),
				timeField("Position Time"),
				binaryField("Communication State",
					19,
					"Information used by the TDMA slot allocation algorithm and synchronization information"),
				lookupField("AIS Transceiver information", 5, "AIS_TRANSCEIVER"),
				dateField("Position Date"),
				reservedField(4),
				lookupField("GNSS type", 4, "POSITION_FIX_DEVICE"),
				spareField(8 * 1),
			},
			url:      "https://www.itu.int/rec/R-REC-M.1371-5-201402-I/en",
			interval: math.MaxUint16,
		},

		/* http://www.navcen.uscg.gov/enav/ais/AIS_messages.htm */
		{
			description: "AIS Class A Static and Voyage Related Data",
			pgn:         129794,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Message ID", 6, "AIS_MESSAGE_ID"),
				lookupField("Repeat Indicator", 2, "REPEAT_INDICATOR"),
				mmsiField("User ID"),
				uint32DescField("IMO number", ",0=unavailable"),
				stringFixField("Callsign", 8*7),
				stringFixField("Name", 8*20),
				lookupField("Type of ship", 8*1, "SHIP_TYPE"),
				lengthUfix16DmField("Length"),
				lengthUfix16DmField("Beam"),
				lengthUfix16DmField("Position reference from Starboard"),
				lengthUfix16DmField("Position reference from Bow"),
				dateField("ETA Date"),
				timeField("ETA Time"),
				lengthUfix16CmField("Draft"),
				stringFixField("Destination", 8*20),
				lookupField("AIS version indicator", 2, "AIS_VERSION"),
				lookupField("GNSS type", 4, "POSITION_FIX_DEVICE"),
				lookupField("DTE", 1, "AVAILABLE"),
				reservedField(1),
				lookupField("AIS Transceiver information", 5, "AIS_TRANSCEIVER"),
				reservedField(3),
			},
			url:      "https://www.itu.int/rec/R-REC-M.1371-5-201402-I/en",
			interval: math.MaxUint16,
		},

		{
			description: "AIS Addressed Binary Message",
			pgn:         129795,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Message ID", 6, "AIS_MESSAGE_ID"),
				lookupField("Repeat Indicator", 2, "REPEAT_INDICATOR"),
				mmsiField("Source ID"),
				reservedField(1),
				lookupField("AIS Transceiver information", 5, "AIS_TRANSCEIVER"),
				simpleField("Sequence Number", 2),
				mmsiField("Destination ID"),
				reservedField(6),
				simpleField("Retransmit flag", 1),
				reservedField(1),
				uint16Field("Number of Bits in Binary Data Field"),
				binaryField("Binary Data", lenVariable, ""),
			},
			url:      "https://www.itu.int/rec/R-REC-M.1371-5-201402-I/en",
			interval: math.MaxUint16,
		},

		{
			description: "AIS Acknowledge",
			pgn:         129796,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Message ID", 6, "AIS_MESSAGE_ID"),
				lookupField("Repeat Indicator", 2, "REPEAT_INDICATOR"),
				mmsiField("Source ID"),
				reservedField(1),
				lookupField("AIS Transceiver information", 5, "AIS_TRANSCEIVER"),
				reservedField(2),
				uint32Field("Destination ID #1"),
				binaryField("Sequence Number for ID 1", 2, "reserved"),
				reservedField(6),
				binaryField("Sequence Number for ID n", 2, "reserved"),
				reservedField(6),
			},
			url:      "https://www.itu.int/rec/R-REC-M.1371-5-201402-I/en",
			interval: math.MaxUint16,
		},

		{
			description: "AIS Binary Broadcast Message",
			pgn:         129797,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Message ID", 6, "AIS_MESSAGE_ID"),
				lookupField("Repeat Indicator", 2, "REPEAT_INDICATOR"),
				uint32Field("Source ID"),
				reservedField(1),
				lookupField("AIS Transceiver information", 5, "AIS_TRANSCEIVER"),
				reservedField(2),
				uint16Field("Number of Bits in Binary Data Field"),
				binaryField("Binary Data", lenVariable, ""),
			},
			url:      "https://www.itu.int/rec/R-REC-M.1371-5-201402-I/en",
			interval: math.MaxUint16,
		},

		{
			description: "AIS SAR Aircraft Position Report",
			pgn:         129798,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Message ID", 6, "AIS_MESSAGE_ID"),
				lookupField("Repeat Indicator", 2, "REPEAT_INDICATOR"),
				mmsiField("User ID"),
				longitudeI32Field("Longitude"),
				latitudeI32Field("Latitude"),
				lookupField("Position Accuracy", 1, "POSITION_ACCURACY"),
				lookupField("RAIM", 1, "RAIM_FLAG"),
				lookupField("Time Stamp", 6, "TIME_STAMP"),
				angleU16Field("COG", ""),
				speedU16DmField("SOG", ""),
				binaryField("Communication State",
					19,
					"Information used by the TDMA slot allocation algorithm and synchronization information"),
				lookupField("AIS Transceiver information", 5, "AIS_TRANSCEIVER"),
				distanceFix32CmField("Altitude", ""),
				binaryField("Reserved for Regional Applications", 8*1, ""),
				lookupField("DTE", 1, "AVAILABLE"),
				reservedField(7),
			},
			url:      "https://www.itu.int/rec/R-REC-M.1371-5-201402-I/en",
			interval: math.MaxUint16,
		},

		{
			description: "Radio Frequency/Mode/Power",
			pgn:         129799,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				radioFrequencyField("Rx Frequency", 10),
				radioFrequencyField("Tx Frequency", 10),
				uint8Field("Radio Channel"),
				uint8Field("Tx Power"),
				uint8Field("Mode"),
				uint8Field("Channel Bandwidth"),
			},
			interval: math.MaxUint16,
		},

		{
			description: "AIS UTC/Date Inquiry",
			pgn:         129800,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Message ID", 6, "AIS_MESSAGE_ID"),
				lookupField("Repeat Indicator", 2, "REPEAT_INDICATOR"),
				mmsiField("Source ID"),
				lookupField("AIS Transceiver information", 5, "AIS_TRANSCEIVER"),
				reservedField(3),
				mmsiField("Destination ID"),
			},
			url:      "https://www.itu.int/rec/R-REC-M.1371-5-201402-I/en",
			interval: math.MaxUint16,
		},

		{
			description: "AIS Addressed Safety Related Message",
			pgn:         129801,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Message ID", 6, "AIS_MESSAGE_ID"),
				lookupField("Repeat Indicator", 2, "REPEAT_INDICATOR"),
				mmsiField("Source ID"),
				lookupField("AIS Transceiver information", 5, "AIS_TRANSCEIVER"),
				simpleField("Sequence Number", 2),
				reservedField(1),
				mmsiField("Destination ID"),
				simpleField("Retransmit flag", 1),
				reservedField(7),
				stringFixField("Safety Related Text", 8*117),
			},
			interval: math.MaxUint16,
			url:      "https://navcen.uscg.gov/ais-addressed-safety-related-message12",
		},

		{
			description: "AIS Safety Related Broadcast Message",
			pgn:         129802,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Message ID", 6, "AIS_MESSAGE_ID"),
				lookupField("Repeat Indicator", 2, "REPEAT_INDICATOR"),
				mmsiField("Source ID"),
				lookupField("AIS Transceiver information", 5, "AIS_TRANSCEIVER"),
				reservedField(3),
				stringFixField("Safety Related Text", 8*162),
			},
			interval: math.MaxUint16,
			url:      "https://www.navcen.uscg.gov/ais-safety-related-broadcast-message14",
		},

		{
			description: "AIS Interrogation",
			pgn:         129803,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Message ID", 6, "AIS_MESSAGE_ID"),
				lookupField("Repeat Indicator", 2, "REPEAT_INDICATOR"),
				mmsiField("Source ID"),
				reservedField(1),
				lookupField("AIS Transceiver information", 5, "AIS_TRANSCEIVER"),
				spareField(2),
				mmsiField("Destination ID 1"),
				lookupField("Message ID 1.1", 6, "AIS_MESSAGE_ID"),
				simpleField("Slot Offset 1.1", 12),
				spareField(2),
				lookupField("Message ID 1.2", 6, "AIS_MESSAGE_ID"),
				simpleField("Slot Offset 1.2", 12),
				spareField(2),
				mmsiField("Destination ID 2"),
				lookupField("Message ID 2.1", 6, "AIS_MESSAGE_ID"),
				simpleField("Slot Offset 2.1", 12),
				spareField(2),
				reservedField(4),
				uint8Field("SID"),
			},
			url:      "https://www.itu.int/rec/R-REC-M.1371-5-201402-I/en",
			interval: math.MaxUint16,
		},

		{
			description: "AIS Assignment Mode Command",
			pgn:         129804,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Message ID", 6, "AIS_MESSAGE_ID"),
				lookupField("Repeat Indicator", 2, "REPEAT_INDICATOR"),
				mmsiField("Source ID"),
				lookupField("AIS Transceiver information", 5, "AIS_TRANSCEIVER"),
				reservedField(3),
				mmsiField("Destination ID A"),
				uint16Field("Offset A"),
				uint16Field("Increment A"),
				mmsiField("Destination ID B"),
				uint16Field("Offset B"),
				uint16Field("Increment B"),
			},
			url:      "https://www.itu.int/rec/R-REC-M.1371-5-201402-I/en",
			interval: math.MaxUint16,
		},

		{
			description: "AIS Data Link Management Message",
			pgn:         129805,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Message ID", 6, "AIS_MESSAGE_ID"),
				lookupField("Repeat Indicator", 2, "REPEAT_INDICATOR"),
				mmsiField("Source ID"),
				lookupField("AIS Transceiver information", 5, "AIS_TRANSCEIVER"),
				reservedField(3),
				uint16Field("Offset"),
				uint8Field("Number of Slots"),
				uint8Field("Timeout"),
				uint16Field("Increment"),
			},
			url:             "https://www.itu.int/rec/R-REC-M.1371-5-201402-I/en",
			interval:        math.MaxUint16,
			repeatingField1: 255,
			repeatingCount1: 4,
			repeatingStart1: 6,
		},

		{
			description: "AIS Channel Management",
			pgn:         129806,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Message ID", 6, "AIS_MESSAGE_ID"),
				lookupField("Repeat Indicator", 2, "REPEAT_INDICATOR"),
				mmsiField("Source ID"),
				lookupField("AIS Transceiver information", 5, "AIS_TRANSCEIVER"),
				reservedField(3),
				simpleField("Channel A", 7),
				simpleField("Channel B", 7),
				reservedField(2),
				simpleDescField("Power", 8*1, "reserved"),
				uint8Field("Tx/Rx Mode"),
				longitudeI32Field("North East Longitude Corner 1"),
				latitudeI32Field("North East Latitude Corner 1"),
				longitudeI32Field("South West Longitude Corner 1"),
				latitudeI32Field("South West Latitude Corner 2"),
				reservedField(6),
				simpleField("Addressed or Broadcast Message Indicator", 2),
				simpleField("Channel A Bandwidth", 7),
				simpleField("Channel B Bandwidth", 7),
				reservedField(2),
				uint8Field("Transitional Zone Size"),
			},
			url:      "https://www.itu.int/rec/R-REC-M.1371-5-201402-I/en",
			interval: math.MaxUint16,
		},

		{
			description: "AIS Class B Group Assignment",
			pgn:         129807,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Message ID", 6, "AIS_MESSAGE_ID"),
				lookupField("Repeat Indicator", 2, "REPEAT_INDICATOR"),
				mmsiField("Source ID"),
				spareField(2),
				lookupField("Tx/Rx Mode", 4, "TX_RX_MODE"),
				reservedField(2),
				longitudeI32Field("North East Longitude Corner 1"),
				latitudeI32Field("North East Latitude Corner 1"),
				longitudeI32Field("South West Longitude Corner 1"),
				latitudeI32Field("South West Latitude Corner 2"),
				lookupField("Station Type", 4, "STATION_TYPE"),
				reservedField(4),
				uint8Field("Ship and Cargo Filter"),
				spareField(22),
				reservedField(2),
				lookupField("Reporting Interval", 4, "REPORTING_INTERVAL"),
				simpleField("Quiet Time", 4),
			},
			url:      "https://www.itu.int/rec/R-REC-M.1371-5-201402-I/en",
			interval: math.MaxUint16,
		},

		/* http://www.nmea.org/Assets/2000_20150328%20dsc%20technical%20corrigendum%20database%20version%202.100.pdf */
		/* This is like the worst PGN ever.
		 * 1. The "Nature of Distress or 1st Telecommand' field meaning depends on the 'DSC Category'.
		 * 2. The "Message address" (the 'to' field) meaning depends on the 'DSC format'.
		 * 3. Field 12 'MMSI of ship in destress' may have multiple interpretations.
		 * 4. Field 22 'DSC expansion field data' depends on field 21 for its meaning.
		 * 5. It contains a variable length field 'Telephone number', which means that bit offsets for subsequent fields
		 *    depend on this field's length.
		 *
		 * We solve #1 here by having two definitions.
		 */

		{
			description: "DSC Distress Call Information",
			pgn:         129808,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("DSC Format", 8*1, "DSC_FORMAT"),
				matchField("DSC Category", 8*1, "112", "Distress"),
				decimalField("DSC Message Address", 8*5, "MMSI, Geographic Area or blank"),
				lookupField("Nature of Distress", 8*1, "DSC_NATURE"),
				lookupField("Subsequent Communication Mode or 2nd Telecommand", 8*1, "DSC_SECOND_TELECOMMAND"),
				stringFixField("Proposed Rx Frequency/Channel", 8*6),
				stringFixField("Proposed Tx Frequency/Channel", 8*6),
				stringlauField("Telephone Number"),
				latitudeI32Field("Latitude of Vessel Reported"),
				longitudeI32Field("Longitude of Vessel Reported"),
				timeField("Time of Position"),
				decimalField("MMSI of Ship In Distress", 8*5, ""),
				uint8Field("DSC EOS Symbol"),
				lookupField("Expansion Enabled", 2, "YES_NO"),
				reservedField(6),
				stringFixField("Calling Rx Frequency/Channel", 8*6),
				stringFixField("Calling Tx Frequency/Channel", 8*6),
				timeField("Time of Receipt"),
				dateField("Date of Receipt"),
				uint16Field("DSC Equipment Assigned Message ID"),
				lookupField("DSC Expansion Field Symbol", 8*1, "DSC_EXPANSION_DATA"),
				stringlauField("DSC Expansion Field Data"),
			},
			interval:        math.MaxUint16,
			repeatingField1: 255,
			repeatingCount1: 2,
			repeatingStart1: 21,
			url:             "http://www.nmea.org/Assets/2000_20150328%20dsc%20technical%20corrigendum%20database%20version%202.100.pdf",
		},

		{
			description: "DSC Call Information",
			pgn:         129808,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("DSC Format Symbol", 8*1, "DSC_FORMAT"),
				lookupField("DSC Category Symbol", 8*1, "DSC_CATEGORY"),
				decimalField("DSC Message Address", 8*5, "MMSI, Geographic Area or blank"),
				lookupField("1st Telecommand", 8*1, "DSC_FIRST_TELECOMMAND"),
				lookupField("Subsequent Communication Mode or 2nd Telecommand", 8*1, "DSC_SECOND_TELECOMMAND"),
				stringFixField("Proposed Rx Frequency/Channel", 8*6),
				stringFixField("Proposed Tx Frequency/Channel", 8*6),
				stringlauField("Telephone Number"),
				latitudeI32Field("Latitude of Vessel Reported"),
				longitudeI32Field("Longitude of Vessel Reported"),
				timeField("Time of Position"),
				decimalField("MMSI of Ship In Distress", 8*5, ""),
				uint8Field("DSC EOS Symbol"),
				lookupField("Expansion Enabled", 2, "YES_NO"),
				reservedField(6),
				stringFixField("Calling Rx Frequency/Channel", 8*6),
				stringFixField("Calling Tx Frequency/Channel", 8*6),
				timeField("Time of Receipt"),
				dateField("Date of Receipt"),
				uint16Field("DSC Equipment Assigned Message ID"),
				lookupField("DSC Expansion Field Symbol", 8*1, "DSC_EXPANSION_DATA"),
				stringlauField("DSC Expansion Field Data"),
			},
			interval:        math.MaxUint16,
			repeatingField1: 255,
			repeatingCount1: 2,
			repeatingStart1: 21,
			url:             "http://www.nmea.org/Assets/2000_20150328%20dsc%20technical%20corrigendum%20database%20version%202.100.pdf",
		},

		{
			description: "AIS Class B static data (msg 24 Part A)",
			pgn:         129809,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Message ID", 6, "AIS_MESSAGE_ID"),
				lookupField("Repeat Indicator", 2, "REPEAT_INDICATOR"),
				mmsiField("User ID"),
				stringFixField("Name", 8*20),
				lookupField("AIS Transceiver information", 5, "AIS_TRANSCEIVER"),
				reservedField(3),
				uint8Field("Sequence ID"),
			},
			url:      "https://www.itu.int/rec/R-REC-M.1371-5-201402-I/en",
			interval: math.MaxUint16,
		},

		{
			description: "AIS Class B static data (msg 24 Part B)",
			pgn:         129810,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Message ID", 6, "AIS_MESSAGE_ID"),
				lookupField("Repeat Indicator", 2, "REPEAT_INDICATOR"),
				mmsiField("User ID"),
				lookupField("Type of ship", 8*1, "SHIP_TYPE"),
				stringFixField("Vendor ID", 8*7),
				stringFixField("Callsign", 8*7),
				lengthUfix16DmField("Length"),
				lengthUfix16DmField("Beam"),
				lengthUfix16DmField("Position reference from Starboard"),
				lengthUfix16DmField("Position reference from Bow"),
				mmsiField("Mothership User ID"),
				reservedField(2),
				spareField(6),
				lookupField("AIS Transceiver information", 5, "AIS_TRANSCEIVER"),
				reservedField(3),
				uint8Field("Sequence ID"),
			},
			url:      "https://www.itu.int/rec/R-REC-M.1371-5-201402-I/en",
			interval: math.MaxUint16,
		},

		{
			description: "Loran-C TD Data",
			pgn:         130052,
			complete:    packetStatusResolutionUnknown | packetStatusNotSeen | packetStatusIntervalUnknown,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				simpleSignedField("Group Repetition Interval (GRI)", 8*4),
				simpleSignedField("Master Range", 8*4),
				simpleSignedField("V Secondary TD", 8*4),
				simpleSignedField("W Secondary TD", 8*4),
				simpleSignedField("X Secondary TD", 8*4),
				simpleSignedField("Y Secondary TD", 8*4),
				simpleSignedField("Z Secondary TD", 8*4),
				bitlookupField("Station status: Master", 4, "STATION_STATUS"),
				bitlookupField("Station status: V", 4, "STATION_STATUS"),
				bitlookupField("Station status: W", 4, "STATION_STATUS"),
				bitlookupField("Station status: X", 4, "STATION_STATUS"),
				bitlookupField("Station status: Y", 4, "STATION_STATUS"),
				bitlookupField("Station status: Z", 4, "STATION_STATUS"),
				lookupField("Mode", 4, "RESIDUAL_MODE"),
				reservedField(4),
			},
			interval: 0,
		},

		{
			description: "Loran-C Range Data",
			pgn:         130053,
			complete:    packetStatusResolutionUnknown | packetStatusNotSeen | packetStatusIntervalUnknown,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				simpleSignedField("Group Repetition Interval (GRI)", 8*4),
				simpleSignedField("Master Range", 8*4),
				simpleSignedField("V Secondary Range", 8*4),
				simpleSignedField("W Secondary Range", 8*4),
				simpleSignedField("X Secondary Range", 8*4),
				simpleSignedField("Y Secondary Range", 8*4),
				simpleSignedField("Z Secondary Range", 8*4),
				bitlookupField("Station status: Master", 4, "STATION_STATUS"),
				bitlookupField("Station status: V", 4, "STATION_STATUS"),
				bitlookupField("Station status: W", 4, "STATION_STATUS"),
				bitlookupField("Station status: X", 4, "STATION_STATUS"),
				bitlookupField("Station status: Y", 4, "STATION_STATUS"),
				bitlookupField("Station status: Z", 4, "STATION_STATUS"),
				lookupField("Mode", 4, "RESIDUAL_MODE"),
				reservedField(4),
			},
			interval: 0,
		},

		{
			description: "Loran-C Signal Data",
			pgn:         130054,
			complete:    packetStatusResolutionUnknown | packetStatusNotSeen | packetStatusIntervalUnknown,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				simpleSignedField("Group Repetition Interval (GRI)", 8*4),
				stringFixField("Station identifier", 8*1),
				signaltonoiseratioFix16Field("Station SNR", ""),
				simpleSignedField("Station ECD", 8*4),
				simpleSignedField("Station ASF", 8*4),
			},
			interval: 0,
		},

		{
			description: "Label",
			pgn:         130060,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				simpleField("Hardware Channel ID", 8),
				simpleField("PGN", 24),
				simpleField("Data Source Instance Field Number", 8),
				simpleField("Data Source Instance Value", 8),
				simpleField("Secondary Enumeration Field Number", 8),
				simpleField("Secondary Enumeration Field Value", 8),
				simpleField("Parameter Field Number", 8),
				stringlauField("Label"),
			},
		},

		{
			description: "Channel Source Configuration",
			pgn:         130061,
			complete:    packetStatusResolutionUnknown | packetStatusNotSeen | packetStatusIntervalUnknown,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("Data Source Channel ID"),
				simpleField("Source Selection Status", 2),
				reservedField(2),
				binaryField("NAME Selection Criteria Mask", 12, ""),
				simpleField("Source NAME", 8*8),
				pgnPGNField("PGN", ""),
				uint8Field("Data Source Instance Field Number"),
				uint8Field("Data Source Instance Value"),
				uint8Field("Secondary Enumeration Field Number"),
				uint8Field("Secondary Enumeration Field Value"),
				uint8Field("Parameter Field Number"),
			},
			interval: 0,
		},

		{
			description: "Route and WP Service - Database List",
			pgn:         130064,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("Start Database ID"),
				uint8Field("nItems"),
				uint8Field("Number of Databases Available"),
				uint8Field("Database ID"),
				stringlauField("Database Name"),
				timeField("Database Timestamp"),
				dateField("Database Datestamp"),
				simpleField("WP Position Resolution", 6),
				reservedField(2),
				uint16Field("Number of Routes in Database"),
				uint16Field("Number of WPs in Database"),
				uint16Field("Number of Bytes in Database"),
			},
			interval:        math.MaxUint16,
			repeatingField1: 2,
			repeatingCount1: 9,
			repeatingStart1: 4,
		},

		{
			description: "Route and WP Service - Route List",
			pgn:         130065,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("Start Route ID"),
				uint8Field("nItems"),
				uint8Field("Number of Routes in Database"),
				uint8Field("Database ID"),
				uint8Field("Route ID"),
				stringlauField("Route Name"),
				reservedField(4),
				simpleField("WP Identification Method", 2),
				simpleField("Route Status", 2),
			},
			interval:        math.MaxUint16,
			repeatingField1: 2,
			repeatingCount1: 5,
			repeatingStart1: 5,
		},

		{
			description: "Route and WP Service - Route/WP-List Attributes",
			pgn:         130066,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("Database ID"),
				uint8Field("Route ID"),
				stringlauField("Route/WP-List Name"),
				timeField("Route/WP-List Timestamp"),
				dateField("Route/WP-List Datestamp"),
				uint8Field("Change at Last Timestamp"),
				uint16Field("Number of WPs in the Route/WP-List"),
				uint8Field("Critical supplementary parameters"),
				simpleField("Navigation Method", 2),
				simpleField("WP Identification Method", 2),
				simpleField("Route Status", 2),
				uint16Field("XTE Limit for the Route"),
				reservedField(2),
			},
			interval: math.MaxUint16,
		},

		{
			description: "Route and WP Service - Route - WP Name & Position",
			pgn:         130067,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("Start RPS#"),
				uint8Field("nItems"),
				uint16Field("Number of WPs in the Route/WP-List"),
				uint8Field("Database ID"),
				uint8Field("Route ID"),
				uint8Field("WP ID"),
				stringlauField("WP Name"),
				latitudeI32Field("WP Latitude"),
				longitudeI32Field("WP Longitude"),
			},
			interval:        math.MaxUint16,
			repeatingField1: 2,
			repeatingCount1: 4,
			repeatingStart1: 6,
		},

		{
			description: "Route and WP Service - Route - WP Name",
			pgn:         130068,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("Start RPS#"),
				uint8Field("nItems"),
				uint16Field("Number of WPs in the Route/WP-List"),
				uint8Field("Database ID"),
				uint8Field("Route ID"),
				uint8Field("WP ID"),
				stringlauField("WP Name"),
			},
			interval:        math.MaxUint16,
			repeatingField1: 2,
			repeatingCount1: 2,
			repeatingStart1: 6,
		},

		{
			description: "Route and WP Service - XTE Limit & Navigation Method",
			pgn:         130069,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("Start RPS#"),
				uint8Field("nItems"),
				uint16Field("Number of WPs with a specific XTE Limit or Nav. Method"),
				uint8Field("Database ID"),
				uint8Field("Route ID"),
				uint8Field("RPS#"),
				uint16Field("XTE limit in the leg after WP"),
				simpleField("Nav. Method in the leg after WP", 4),
				reservedField(4),
			},
			interval:        math.MaxUint16,
			repeatingField1: 2,
			repeatingCount1: 6,
			repeatingStart1: 4,
		},

		{
			description: "Route and WP Service - WP Comment",
			pgn:         130070,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("Start ID"),
				uint8Field("nItems"),
				uint16Field("Number of WPs with Comments"),
				uint8Field("Database ID"),
				uint8Field("Route ID"),
				uint8Field("WP ID / RPS#"),
				stringlauField("Comment"),
			},
			interval:        math.MaxUint16,
			repeatingField1: 2,
			repeatingCount1: 2,
			repeatingStart1: 6,
		},

		{
			description: "Route and WP Service - Route Comment",
			pgn:         130071,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("Start Route ID"),
				uint8Field("nItems"),
				uint16Field("Number of Routes with Comments"),
				uint8Field("Database ID"),
				uint8Field("Route ID"),
				stringlauField("Comment"),
			},
			interval:        math.MaxUint16,
			repeatingField1: 2,
			repeatingCount1: 2,
			repeatingStart1: 5,
		},

		{
			description: "Route and WP Service - Database Comment",
			pgn:         130072,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("Start Database ID"),
				uint8Field("nItems"),
				uint16Field("Number of Databases with Comments"),
				uint8Field("Database ID"),
				stringlauField("Comment"),
			},
			interval:        math.MaxUint16,
			repeatingField1: 2,
			repeatingCount1: 2,
			repeatingStart1: 4,
		},

		{
			description: "Route and WP Service - Radius of Turn",
			pgn:         130073,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("Start RPS#"),
				uint8Field("nItems"),
				uint16Field("Number of WPs with a specific Radius of Turn"),
				uint8Field("Database ID"),
				uint8Field("Route ID"),
				uint8Field("RPS#"),
				uint16Field("Radius of Turn"),
			},
			interval:        math.MaxUint16,
			repeatingField1: 2,
			repeatingCount1: 2,
			repeatingStart1: 6,
		},

		{
			description: "Route and WP Service - WP List - WP Name & Position",
			pgn:         130074,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("Start WP ID"),
				uint8Field("nItems"),
				uint16Field("Number of valid WPs in the WP-List"),
				uint8Field("Database ID"),
				reservedField(8 * 1),
				uint8Field("WP ID"),
				stringlauField("WP Name"),
				latitudeI32Field("WP Latitude"),
				longitudeI32Field("WP Longitude"),
			},
			interval:        math.MaxUint16,
			repeatingField1: 2,
			repeatingCount1: 4,
			repeatingStart1: 6,
		},

		{
			description: "Wind Data",
			pgn:         130306,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				speedU16CmField("Wind Speed"),
				angleU16Field("Wind Angle", ""),
				lookupField("Reference", 3, "WIND_REFERENCE"),
				reservedField(5 + 8*2),
			},
			interval: 100,
			url:      "http://askjackrabbit.typepad.com/ask_jack_rabbit/page/7/",
		},

		/* Water temperature, Transducer Measurement */
		{
			description: "Environmental Parameters (obsolete)",
			pgn:         130310,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				temperatureField("Water Temperature"),
				temperatureField("Outside Ambient Air Temperature"),
				pressureUfix16HPAField("Atmospheric Pressure"),
				reservedField(8 * 1),
			},
			explanation: "This PGN was succeeded by PGN 130310, but it should no longer be generated and separate PGNs in " +
				"range 130312..130315 should be used",
			interval: 500,
		},

		{
			description: "Environmental Parameters",
			pgn:         130311,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				lookupField("Temperature Source", 6, "TEMPERATURE_SOURCE"),
				lookupField("Humidity Source", 2, "HUMIDITY_SOURCE"),
				temperatureField("Temperature"),
				percentageI16Field("Humidity"),
				pressureUfix16HPAField("Atmospheric Pressure"),
			},
			explanation: "This PGN was introduced as a better version of PGN 130310, but it should no longer be generated and separate " +
				"PGNs in range 130312..130315 should be used",
			interval: 500,
		},

		{
			description: "Temperature",
			pgn:         130312,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				instanceField(),
				lookupField("Source", 8*1, "TEMPERATURE_SOURCE"),
				temperatureField("Actual Temperature"),
				temperatureField("Set Temperature"),
				reservedField(8 * 1),
			},
			interval: 2000,
		},

		{
			description: "Humidity",
			pgn:         130313,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				instanceField(),
				lookupField("Source", 8*1, "HUMIDITY_SOURCE"),
				percentageI16Field("Actual Humidity"),
				percentageI16Field("Set Humidity"),
				reservedField(8 * 1),
			},
			interval: 2000,
		},

		{
			description: "Actual Pressure",
			pgn:         130314,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				instanceField(),
				lookupField("Source", 8*1, "PRESSURE_SOURCE"),
				pressureFix32DpaField("Pressure"),
				reservedField(8 * 1),
			},
			interval: 2000,
		},

		{
			description: "Set Pressure",
			pgn:         130315,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				instanceField(),
				lookupField("Source", 8*1, "PRESSURE_SOURCE"),
				pressureUfix32DpaField("Pressure"),
				reservedField(8 * 1),
			},
			interval: math.MaxUint16,
		},

		{
			description: "Temperature Extended Range",
			pgn:         130316,
			complete:    packetStatusComplete,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				instanceField(),
				lookupField("Source", 8*1, "TEMPERATURE_SOURCE"),
				temperatureU24Field("Temperature"),
				temperatureHighField("Set Temperature"),
			},
		},

		{
			description: "Tide Station Data",
			pgn:         130320,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Mode", 4, "RESIDUAL_MODE"),
				lookupField("Tide Tendency", 2, "TIDE"),
				reservedField(2),
				dateField("Measurement Date"),
				timeField("Measurement Time"),
				latitudeI32Field("Station Latitude"),
				longitudeI32Field("Station Longitude"),
				distanceFix16MmField("Tide Level", "Relative to MLLW"),
				lengthUfix16CmField("Tide Level standard deviation"),
				stringlauField("Station ID"),
				stringlauField("Station Name"),
			},
			interval: 1000,
		},

		{
			description: "Salinity Station Data",
			pgn:         130321,
			complete:    packetStatusComplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Mode", 4, "RESIDUAL_MODE"),
				reservedField(4),
				dateField("Measurement Date"),
				timeField("Measurement Time"),
				latitudeI32Field("Station Latitude"),
				longitudeI32Field("Station Longitude"),
				floatField("Salinity", "ppt", ""),
				temperatureField("Water Temperature"),
				stringlauField("Station ID"),
				stringlauField("Station Name"),
			},
			interval: 1000,
		},

		{
			description: "Current Station Data",
			pgn:         130322,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				simpleField("Mode", 4),
				reservedField(4),
				dateField("Measurement Date"),
				timeField("Measurement Time"),
				latitudeI32Field("Station Latitude"),
				longitudeI32Field("Station Longitude"),
				lengthUfix32CmField("Measurement Depth", "Depth below transducer"),
				speedU16CmField("Current speed"),
				angleU16Field("Current flow direction", ""),
				temperatureField("Water Temperature"),
				stringlauField("Station ID"),
				stringlauField("Station Name"),
			},
			interval: 1000,
		},

		{
			description: "Meteorological Station Data",
			pgn:         130323,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				simpleField("Mode", 4),
				reservedField(4),
				dateField("Measurement Date"),
				timeField("Measurement Time"),
				latitudeI32Field("Station Latitude"),
				longitudeI32Field("Station Longitude"),
				speedU16CmField("Wind Speed"),
				angleU16Field("Wind Direction", ""),
				lookupField("Wind Reference", 3, "WIND_REFERENCE"),
				reservedField(5),
				speedU16CmField("Wind Gusts"),
				pressureUfix16HPAField("Atmospheric Pressure"),
				temperatureField("Ambient Temperature"),
				stringlauField("Station ID"),
				stringlauField("Station Name"),
			},
			interval: 1000,
		},

		{
			description: "Moored Buoy Station Data",
			pgn:         130324,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				simpleField("Mode", 4),
				reservedField(4),
				dateField("Measurement Date"),
				timeField("Measurement Time"),
				latitudeI32Field("Station Latitude"),
				longitudeI32Field("Station Longitude"),
				speedU16CmField("Wind Speed"),
				angleU16Field("Wind Direction", ""),
				lookupField("Wind Reference", 3, "WIND_REFERENCE"),
				reservedField(5),
				speedU16CmField("Wind Gusts"),
				uint16Field("Wave Height"),
				uint16Field("Dominant Wave Period"),
				pressureUfix16HPAField("Atmospheric Pressure"),
				pressureRateFix16PaField("Pressure Tendency Rate"),
				temperatureField("Air Temperature"),
				temperatureField("Water Temperature"),
				stringFixField("Station ID", 8*8),
			},
			interval: 1000,
		},

		{
			description: "Lighting System Settings",
			pgn:         130330,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				simpleField("Global Enable", 2),
				lookupField("Default Settings/Command", 3, "LIGHTING_COMMAND"),
				reservedField(3),
				stringlauField("Name of the lighting controller"),
				simpleField("Max Scenes", 8),
				simpleField("Max Scene Configuration Count", 8),
				simpleField("Max Zones", 8),
				simpleField("Max Color Sequences", 8),
				simpleField("Max Color Sequence Color Count", 8),
				simpleField("Number of Programs", 8),
				simpleField("Controller Capabilities", 8),
				simpleField("Identify Device", 32),
			},
			explanation: "This PGN provides a lighting controller settings and number of supported capabilities.",
		},

		{
			description: "Payload Mass",
			pgn:         130560,
			complete:    packetStatusResolutionUnknown | packetStatusNotSeen | packetStatusIntervalUnknown,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				simpleField("Measurement Status", 3),
				reservedField(5),
				uint8Field("Measurement ID"),
				uint32Field("Payload Mass"),
				reservedField(8 * 1),
			},
			interval: 0,
		},

		{
			description: "Lighting Zone",
			pgn:         130561,
			complete:    packetStatusPDFOnly,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				simpleField("Zone Index", 8),
				stringlauField("Zone Name"),
				simpleField("Red Component", 8),
				simpleField("Green Component", 8),
				simpleField("Blue Component", 8),
				simpleField("Color Temperature", 16),
				simpleField("Intensity", 8),
				simpleField("Program ID", 8),
				simpleField("Program Color Sequence Index", 8),
				simpleField("Program Intensity", 8),
				simpleField("Program Rate", 8),
				simpleField("Program Color Sequence", 8),
				lookupField("Zone Enabled", 2, "OFF_ON"),
				reservedField(6),
			},
			interval: math.MaxUint16,
			explanation: "This PGN is used to report or configure a name for a given zone. A zone is a grouping of devices that are " +
				"controlled by a Scene. This PGN is only sent upon request.",
		},

		{
			description: "Lighting Scene",
			pgn:         130562,
			complete:    packetStatusPDFOnly,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				simpleField("Scene Index", 8),
				stringlauField("Zone Name"),
				simpleField("Control", 8),
				simpleField("Configuration Count", 8),
				simpleField("Configuration Index", 8),
				simpleField("Zone Index", 8),
				simpleField("Devices ID", 32),
				simpleField("Program Index", 8),
				simpleField("Program Color Sequence Index", 8),
				simpleField("Program Intensity", 8),
				simpleField("Program Rate", 8),
				simpleField("Program Color Sequence Rate", 8),
			},
			repeatingCount1: 8,
			repeatingStart1: 5,
			repeatingField1: 4,
			explanation:     "A Lighting Scene is a sequence of zone program configurations.",
		},

		{
			description: "Lighting Device",
			pgn:         130563,
			complete:    packetStatusPDFOnly,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				simpleField("Device ID", 32),
				simpleField("Device Capabilities", 8),
				simpleField("Color Capabilities", 8),
				simpleField("Zone Index", 8),
				stringlauField("Name of Lighting Device"),
				simpleField("Status", 8),
				simpleField("Red Component", 8),
				simpleField("Green Component", 8),
				simpleField("Blue Component", 8),
				simpleField("Color Temperature", 16),
				simpleField("Intensity", 8),
				simpleField("Program ID", 8),
				simpleField("Program Color Sequence Index", 8),
				simpleField("Program Intensity", 8),
				simpleField("Program Rate", 8),
				simpleField("Program Color Sequence Rate", 8),
				lookupField("Enabled", 2, "OFF_ON"),
				reservedField(6),
			},
			explanation: "This PGN is used to provide status and capabilities of a lighting device. A lighting device may be a virtual " +
				"device connected to a lighting controller or physical device on the network.",
		},

		{
			description: "Lighting Device Enumeration",
			pgn:         130564,
			complete:    packetStatusPDFOnly,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				simpleField("Index of First Device", 16),
				simpleField("Total Number of Devices", 16),
				simpleField("Number of Devices", 16),
				simpleField("Device ID", 32),
				simpleField("Status", 8),
			},
			repeatingCount1: 2,
			repeatingStart1: 4,
			repeatingField1: 3,
			explanation:     "This PGN allows for enumeration of the lighting devices on the controller.",
		},

		{
			description: "Lighting Color Sequence",
			pgn:         130565,
			complete:    packetStatusPDFOnly,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				simpleField("Sequence Index", 8),
				simpleField("Color Count", 8),
				simpleField("Color Index", 8),
				simpleField("Red Component", 8),
				simpleField("Green Component", 8),
				simpleField("Blue Component", 8),
				simpleField("Color Temperature", 16),
				simpleField("Intensity", 8),
			},
			repeatingCount1: 5,
			repeatingStart1: 3,
			repeatingField1: 2,
			explanation:     "Sequences could be 1 to (PGN Lighting – System Configuration) Max Color Sequence Color Count colors.",
		},

		{
			description: "Lighting Program",
			pgn:         130566,
			complete:    packetStatusPDFOnly,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				simpleField("Program ID", 8),
				stringlauField("Name of Program"),
				stringlauField("Description"),
				simpleField("Program Capabilities", 4),
				reservedField(4),
			},
			explanation: "This PGN describes an available program on the controller. Can be a built in required NMEA one or a custom " +
				"vendor program.",
		},

		/* http://www.nmea.org/Assets/20130905%20amendment%20at%202000%20201309051%20watermaker%20input%20setting%20and%20status%20pgn%20130567.pdf

		   This PGN may be requested or used to command and configure a number of Watermaker controls. The Command Group Function PGN
		   126208 is used perform the following: start/stop a production, start/stop rinse or flush operation, start/stop low and high
		   pressure pump and perform an emergency stop. The Request Group Function PGN 126208 or ISO Request PGN 059904 may be used to
		   request this PGN. This PGN also provides Watermaker status and measurement information. The PGN is broadcast periodically.

		*/
		{
			description: "Watermaker Input Setting and Status",
			pgn:         130567,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Watermaker Operating State", 6, "WATERMAKER_STATE"),
				lookupField("Production Start/Stop", 2, "YES_NO"),
				lookupField("Rinse Start/Stop", 2, "YES_NO"),
				lookupField("Low Pressure Pump Status", 2, "YES_NO"),
				lookupField("High Pressure Pump Status", 2, "YES_NO"),
				lookupField("Emergency Stop", 2, "YES_NO"),
				lookupField("Product Solenoid Valve Status", 2, "OK_WARNING"),
				lookupField("Flush Mode Status", 2, "YES_NO"),
				lookupField("Salinity Status", 2, "OK_WARNING"),
				lookupField("Sensor Status", 2, "OK_WARNING"),
				lookupField("Oil Change Indicator Status", 2, "OK_WARNING"),
				lookupField("Filter Status", 2, "OK_WARNING"),
				lookupField("System Status", 2, "OK_WARNING"),
				reservedField(2),
				concentrationUint16Field("Salinity"),
				temperatureField("Product Water Temperature"),
				pressureUfix16HPAField("Pre-filter Pressure"),
				pressureUfix16HPAField("Post-filter Pressure"),
				pressureFix16KpaField("Feed Pressure"),
				pressureUfix16KpaField("System High Pressure"),
				volumetricFlowField("Product Water Flow"),
				volumetricFlowField("Brine Water Flow"),
				timeUfix32SField("Run Time", ""),
			},
			url: "http://www.nmea.org/Assets/" +
				"20130905%20amendment%20at%202000%20201309051%20watermaker%20input%20setting%20and%20status%20pgn%20130567.pdf",
		},

		{
			description: "Current Status and File",
			pgn:         130569,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Zone", 8*1, "ENTERTAINMENT_ZONE"),
				lookupField("Source", 8, "ENTERTAINMENT_SOURCE"),
				uint8DescField("Number", "Source number per type"),
				uint32DescField("ID", "Unique file ID"),
				lookupField("Play status", 8*1, "ENTERTAINMENT_PLAY_STATUS"),
				timeUfix16SField("Elapsed Track Time"),
				timeUfix16SField("Track Time"),
				lookupField("Repeat Status", 4, "ENTERTAINMENT_REPEAT_STATUS"),
				lookupField("Shuffle Status", 4, "ENTERTAINMENT_SHUFFLE_STATUS"),
				uint8DescField("Save Favorite Number", "Used to command AV to save current station as favorite"),
				uint16DescField("Play Favorite Number", "Used to command AV to play indicated favorite station"),
				lookupField("Thumbs Up/Down", 8*1, "ENTERTAINMENT_LIKE_STATUS"),
				percentageU8Field("Signal Strength"),
				radioFrequencyField("Radio Frequency", 10),
				uint8DescField("HD Frequency Multicast", "Digital sub channel"),
				uint8DescField("Delete Favorite Number", "Used to command AV to delete current station as favorite"),
				uint16Field("Total Number of Tracks"),
			},
			url: "https://www.nmea.org/Assets/20160725%20corrigenda%20pgn%20130569%20published.pdf",
		},

		{
			description: "Library Data File",
			pgn:         130570,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Source", 8, "ENTERTAINMENT_SOURCE"),
				uint8DescField("Number", "Source number per type"),
				uint32DescField("ID", "Unique file ID"),
				lookupField("Type", 8*1, "ENTERTAINMENT_TYPE"),
				stringlauField("Name"),
				uint16Field("Track"),
				uint16Field("Station"),
				uint8Field("Favorite"),
				radioFrequencyField("Radio Frequency", 10.),
				uint8Field("HD Frequency"),
				lookupField("Zone", 8*1, "ENTERTAINMENT_ZONE"),
				lookupField("In play queue", 2, "YES_NO"),
				lookupField("Locked", 2, "YES_NO"),
				reservedField(4),
				stringlauField("Artist Name"),
				stringlauField("Album Name"),
				stringlauField("Station Name"),
			},
			url: "https://www.nmea.org/Assets/20160715%20corrigenda%20entertainment%20pgns%20.pdf",
		},

		{
			description: "Library Data Group",
			pgn:         130571,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Source", 8, "ENTERTAINMENT_SOURCE"),
				uint8DescField("Number", "Source number per type"),
				lookupField("Type", 8*1, "ENTERTAINMENT_TYPE"),
				lookupField("Zone", 8*1, "ENTERTAINMENT_ZONE"),
				uint32DescField("Group ID", "Unique group ID"),
				uint16DescField("ID offset", "First ID in this PGN"),
				uint16DescField("ID count", "Number of IDs in this PGN"),
				uint16DescField("Total ID count", "Total IDs in group"),
				lookupField("ID type", 8*1, "ENTERTAINMENT_ID_TYPE"),
				uint32Field("ID"),
				stringlauField("Name"),
				stringlauField("Artist"),
			},
			repeatingField1: 7,
			repeatingCount1: 3,
			repeatingStart1: 9,
			url:             "https://www.nmea.org/Assets/20160715%20corrigenda%20entertainment%20pgns%20.pdf",
		},

		{
			description: "Library Data Search",
			pgn:         130572,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Source", 8, "ENTERTAINMENT_SOURCE"),
				uint8DescField("Number", "Source number per type"),
				uint32DescField("Group ID", "Unique group ID"),
				lookupField("Group type 1", 8*1, "ENTERTAINMENT_GROUP"),
				stringlauField("Group name 1"),
				lookupField("Group type 2", 8*1, "ENTERTAINMENT_GROUP"),
				stringlauField("Group name 2"),
				lookupField("Group type 3", 8*1, "ENTERTAINMENT_GROUP"),
				stringlauField("Group name 3"),
			},
			url: "https://www.nmea.org/Assets/20160715%20corrigenda%20entertainment%20pgns%20.pdf",
		},

		{
			description: "Supported Source Data",
			pgn:         130573,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint16DescField("ID offset", "First ID in this PGN"),
				uint16DescField("ID count", "Number of IDs in this PGN"),
				uint16DescField("Total ID count", "Total IDs in group"),
				uint8DescField("ID", "Source ID"),
				lookupField("Source", 8, "ENTERTAINMENT_SOURCE"),
				uint8DescField("Number", "Source number per type"),
				stringlauField("Name"),
				bitlookupField("Play support", 8*4, "ENTERTAINMENT_PLAY_STATUS_BITFIELD"),
				bitlookupField("Browse support", 8*2, "ENTERTAINMENT_GROUP_BITFIELD"),
				lookupField("Thumbs support", 2, "YES_NO"),
				lookupField("Connected", 2, "YES_NO"),
				bitlookupField("Repeat support", 2, "ENTERTAINMENT_REPEAT_BITFIELD"),
				bitlookupField("Shuffle support", 2, "ENTERTAINMENT_SHUFFLE_BITFIELD"),
			},
			repeatingField1: 2,
			repeatingCount1: 10,
			repeatingStart1: 4,
			url:             "https://www.nmea.org/Assets/20160715%20corrigenda%20entertainment%20pgns%20.pdf",
		},

		{
			description: "Supported Zone Data",
			pgn:         130574,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8DescField("First zone ID", "First Zone in this PGN"),
				uint8DescField("Zone count", "Number of Zones in this PGN"),
				uint8DescField("Total zone count", "Total Zones supported by this device"),
				lookupField("Zone ID", 8*1, "ENTERTAINMENT_ZONE"),
				stringlauField("Name"),
			},
			repeatingField1: 2,
			repeatingCount1: 2,
			repeatingStart1: 4,
			url:             "https://www.nmea.org/Assets/20160715%20corrigenda%20entertainment%20pgns%20.pdf",
		},

		{
			description: "Small Craft Status",
			pgn:         130576,
			complete:    packetStatusNotSeen,
			packetType:  packetTypeSingle,
			fieldList:   [33]pgnField{percentageI8Field("Port trim tab"), percentageI8Field("Starboard trim tab"), reservedField(8 * 6)},
			interval:    200,
		},

		{
			description: "Direction Data",
			pgn:         130577,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Data Mode", 4, "RESIDUAL_MODE"),
				lookupField("COG Reference", 2, "DIRECTION_REFERENCE"),
				reservedField(2),
				uint8Field("SID"),
				angleU16Field("COG", ""),
				speedU16CmField("SOG"),
				angleU16Field("Heading", ""),
				speedU16CmField("Speed through Water"),
				angleU16Field("Set", ""),
				speedU16CmField("Drift"),
			},
			interval: 1000,
		},

		{
			description: "Vessel Speed Components",
			pgn:         130578,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				speedI16MmField("Longitudinal Speed, Water-referenced"),
				speedI16MmField("Transverse Speed, Water-referenced"),
				speedI16MmField("Longitudinal Speed, Ground-referenced"),
				speedI16MmField("Transverse Speed, Ground-referenced"),
				speedI16MmField("Stern Speed, Water-referenced"),
				speedI16MmField("Stern Speed, Ground-referenced"),
			},
			interval: 250,
		},

		{
			description: "System Configuration",
			pgn:         130579,
			complete:    packetStatusFieldLengthsUnknown | packetStatusNotSeen,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				lookupField("Power", 2, "YES_NO"),
				lookupField("Default Settings", 2, "ENTERTAINMENT_DEFAULT_SETTINGS"),
				lookupField("Tuner regions", 4, "ENTERTAINMENT_REGIONS"),
				uint8Field("Max favorites"),
				lookupField("Video protocols", 4, "VIDEO_PROTOCOLS"),
				reservedField(44),
			},
		},

		{
			description: "System Configuration (deprecated)",
			pgn:         130580,
			complete:    packetStatusFieldLengthsUnknown | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Power", 2, "YES_NO"),
				lookupField("Default Settings", 2, "ENTERTAINMENT_DEFAULT_SETTINGS"),
				lookupField("Tuner regions", 4, "ENTERTAINMENT_REGIONS"),
				uint8Field("Max favorites"),
			},
		},

		{
			description: "Zone Configuration (deprecated)",
			pgn:         130581,
			complete:    packetStatusFieldLengthsUnknown | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8DescField("First zone ID", "First Zone in this PGN"),
				uint8DescField("Zone count", "Number of Zones in this PGN"),
				uint8DescField("Total zone count", "Total Zones supported by this device"),
				lookupField("Zone ID", 8*1, "ENTERTAINMENT_ZONE"),
				stringlauField("Zone name"),
			},
			repeatingField1: 2,
			repeatingCount1: 2,
			repeatingStart1: 4,
		},

		{
			description: "Zone Volume",
			pgn:         130582,
			complete:    packetStatusFieldLengthsUnknown | packetStatusNotSeen,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				lookupField("Zone ID", 8*1, "ENTERTAINMENT_ZONE"),
				percentageU8Field("Volume"),
				lookupFieldDesc("Volume change", 2, "ENTERTAINMENT_VOLUME_CONTROL", "Write only"),
				lookupField("Mute", 2, "YES_NO"),
				reservedField(4),
				lookupField("Channel", 8, "ENTERTAINMENT_CHANNEL"),
				reservedField(8 * 4),
			},
		},

		{
			description: "Available Audio EQ presets",
			pgn:         130583,
			complete:    packetStatusFieldLengthsUnknown | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8DescField("First preset", "First preset in this PGN"),
				uint8Field("Preset count"),
				uint8Field("Total preset count"),
				lookupField("Preset type", 8*1, "ENTERTAINMENT_EQ"),
				stringlauField("Preset name"),
			},
			repeatingField1: 2,
			repeatingCount1: 2,
			repeatingStart1: 4,
		},

		{
			description: "Available Bluetooth addresses",
			pgn:         130584,
			complete:    packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8DescField("First address", "First address in this PGN"),
				uint8Field("Address count"),
				uint8Field("Total address count"),
				binaryField("Bluetooth address", 8*6, ""),
				lookupField("Status", 8*1, "BLUETOOTH_STATUS"),
				stringlauField("Device name"),
				percentageU8Field("Signal strength"),
			},
			repeatingField1: 2,
			repeatingCount1: 4,
			repeatingStart1: 4,
		},

		{
			description: "Bluetooth source status",
			pgn:         130585,
			complete:    packetStatusFieldLengthsUnknown | packetStatusNotSeen,
			packetType:  packetTypeSingle,
			fieldList: [33]pgnField{
				uint8Field("Source number"),
				lookupField("Status", 4, "BLUETOOTH_SOURCE_STATUS"),
				lookupField("Forget device", 2, "YES_NO"),
				lookupField("Discovering", 2, "YES_NO"),
				binaryField("Bluetooth address", 8*6, ""),
			},
		},

		{
			description: "Zone Configuration",
			pgn:         130586,
			complete:    packetStatusFieldLengthsUnknown | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				lookupField("Zone ID", 8*1, "ENTERTAINMENT_ZONE"),
				percentageU8Field("Volume limit"),
				percentageI8Field("Fade"),
				percentageI8Field("Balance"),
				percentageU8Field("Sub volume"),
				percentageI8Field("EQ - Treble"),
				percentageI8Field("EQ - Mid range"),
				percentageI8Field("EQ - Bass"),
				lookupField("Preset type", 8*1, "ENTERTAINMENT_EQ"),
				lookupField("Audio filter", 8*1, "ENTERTAINMENT_FILTER"),
				frequencyField("High pass filter frequency", 1),
				frequencyField("Low pass filter frequency", 1),
				lookupField("Channel", 8, "ENTERTAINMENT_CHANNEL"),
			},
		},

		/* proprietary PDU2 (non addressed) fast packet PGN range 0x1FF00 to 0x1FFFF (130816 - 131071) */

		{
			description: "0x1FF00-0x1FFFF: Manufacturer Specific fast-packet non-addressed",
			pgn:         130816,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList:   [33]pgnField{binaryField("Data", 8*common.FastPacketMaxSize, "")},
			fallback:    true,
			explanation: "This definition is used for Manufacturer Specific PGNs in PDU2 (non-addressed) fast-packet PGN range 0x1FF00 to " +
				"0x1FFFF (130816 - 131071). " +
				"When this is shown during analysis it means the PGN is not reverse engineered yet.",
		},

		{
			description: "SonicHub: Init #2",
			pgn:         130816,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("275"),
				reservedField(8*1),
				matchLookupField("Proprietary ID", 8*1, "1", "SONICHUB_COMMAND"),
				lookupField("Control", 8*1, "SONICHUB_CONTROL"),
				uint16Field("A"),
				uint16Field("B"))),
		},

		{
			description: "SonicHub: AM Radio",
			pgn:         130816,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("275"),
				reservedField(8*1),
				matchLookupField("Proprietary ID", 8*1, "4", "SONICHUB_COMMAND"),
				lookupField("Control", 8*1, "SONICHUB_CONTROL"),
				lookupField("Item", 8*1, "SONICHUB_TUNING"),
				radioFrequencyField("Frequency", 1),
				simpleField("Noise level", 2),  // Not sure about this
				simpleField("Signal level", 4), // ... and this, doesn't make complete sense compared to display
				reservedField(2),
				stringlzField("Text", 8*32))),
		},

		{
			description: "SonicHub: Zone info",
			pgn:         130816,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("275"),
				reservedField(8*1),
				matchLookupField("Proprietary ID", 8*1, "5", "SONICHUB_COMMAND"),
				lookupField("Control", 8*1, "SONICHUB_CONTROL"),
				uint8Field("Zone"))),
		},

		{
			description: "SonicHub: Source",
			pgn:         130816,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("275"),
				reservedField(8*1),
				matchLookupField("Proprietary ID", 8*1, "6", "SONICHUB_COMMAND"),
				lookupField("Control", 8*1, "SONICHUB_CONTROL"),
				lookupField("Source", 8*1, "SONICHUB_SOURCE"))),
		},

		{
			description: "SonicHub: Source List",
			pgn:         130816,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("275"),
				reservedField(8*1),
				matchLookupField("Proprietary ID", 8*1, "8", "SONICHUB_COMMAND"),
				lookupField("Control", 8*1, "SONICHUB_CONTROL"),
				uint8Field("Source ID"),
				uint8Field("A"),
				stringlzField("Text", 8*32))),
		},

		{
			description: "SonicHub: Control",
			pgn:         130816,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("275"),
				reservedField(8*1),
				matchLookupField("Proprietary ID", 8*1, "9", "SONICHUB_COMMAND"),
				lookupField("Control", 8*1, "SONICHUB_CONTROL"),
				lookupField("Item", 8*1, "FUSION_MUTE_COMMAND"))),
		},

		{
			description: "SonicHub: FM Radio",
			pgn:         130816,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("275"),
				reservedField(8*1),
				matchLookupField("Proprietary ID", 8*1, "12", "SONICHUB_COMMAND"),
				lookupField("Control", 8*1, "SONICHUB_CONTROL"),
				lookupField("Item", 8*1, "SONICHUB_TUNING"),
				radioFrequencyField("Frequency", 1),
				simpleField("Noise level", 2),  // Not sure about this
				simpleField("Signal level", 4), // ... and this, doesn't make complete sense compared to display
				reservedField(2),
				stringlzField("Text", 8*32))),
		},

		{
			description: "SonicHub: Playlist",
			pgn:         130816,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("275"),
				reservedField(8*1),
				matchLookupField("Proprietary ID", 8*1, "13", "SONICHUB_COMMAND"),
				lookupField("Control", 8*1, "SONICHUB_CONTROL"),
				lookupField("Item", 8*1, "SONICHUB_PLAYLIST"),
				uint8Field("A"),
				uint32Field("Current Track"),
				uint32Field("Tracks"),
				timeUfix32MsField("Length", ""),
				timeUfix32MsField("Position in track", ""))),
		},

		{
			description: "SonicHub: Track",
			pgn:         130816,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("275"),
				reservedField(8*1),
				matchLookupField("Proprietary ID", 8*1, "14", "SONICHUB_COMMAND"),
				lookupField("Control", 8*1, "SONICHUB_CONTROL"),
				uint32Field("Item"),
				stringlzField("Text", 8*32))),
		},

		{
			description: "SonicHub: Artist",
			pgn:         130816,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("275"),
				reservedField(8*1),
				matchLookupField("Proprietary ID", 8*1, "15", "SONICHUB_COMMAND"),
				lookupField("Control", 8*1, "SONICHUB_CONTROL"),
				uint32Field("Item"),
				stringlzField("Text", 8*32))),
		},

		{
			description: "SonicHub: Album",
			pgn:         130816,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("275"),
				reservedField(8*1),
				matchLookupField("Proprietary ID", 8*1, "16", "SONICHUB_COMMAND"),
				lookupField("Control", 8*1, "SONICHUB_CONTROL"),
				uint32Field("Item"),
				stringlzField("Text", 8*32))),
		},

		{
			description: "SonicHub: Menu Item",
			pgn:         130816,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("275"),
				reservedField(8*1),
				matchLookupField("Proprietary ID", 8*1, "19", "SONICHUB_COMMAND"),
				lookupField("Control", 8*1, "SONICHUB_CONTROL"),
				uint32Field("Item"),
				uint8Field("C"),
				uint8Field("D"),
				uint8Field("E"),
				stringlzField("Text", 8*32))),
		},

		{
			description: "SonicHub: Zones",
			pgn:         130816,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("275"),
				reservedField(8*1),
				matchLookupField("Proprietary ID", 8*1, "20", "SONICHUB_COMMAND"),
				lookupField("Control", 8*1, "SONICHUB_CONTROL"),
				uint8Field("Zones"))),
		},

		{
			description: "SonicHub: Max Volume",
			pgn:         130816,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("275"),
				reservedField(8*1),
				matchLookupField("Proprietary ID", 8*1, "23", "SONICHUB_COMMAND"),
				lookupField("Control", 8*1, "SONICHUB_CONTROL"),
				uint8Field("Zone"),
				uint8Field("Level"))),
		},

		{
			description: "SonicHub: Volume",
			pgn:         130816,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("275"),
				reservedField(8*1),
				matchLookupField("Proprietary ID", 8*1, "24", "SONICHUB_COMMAND"),
				lookupField("Control", 8*1, "SONICHUB_CONTROL"),
				uint8Field("Zone"),
				uint8Field("Level"))),
		},

		{
			description: "SonicHub: Init #1",
			pgn:         130816,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("275"),
				reservedField(8*1),
				matchLookupField("Proprietary ID", 8*1, "25", "SONICHUB_COMMAND"),
				lookupField("Control", 8*1, "SONICHUB_CONTROL"))),
		},

		{
			description: "SonicHub: Position",
			pgn:         130816,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("275"),
				reservedField(8*1),
				matchLookupField("Proprietary ID", 8*1, "48", "SONICHUB_COMMAND"),
				lookupField("Control", 8*1, "SONICHUB_CONTROL"),
				timeUfix32MsField("Position", ""))),
		},

		{
			description: "SonicHub: Init #3",
			pgn:         130816,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("275"),
				reservedField(8*1),
				matchLookupField("Proprietary ID", 8*1, "50", "SONICHUB_COMMAND"),
				lookupField("Control", 8*1, "SONICHUB_CONTROL"),
				uint8Field("A"),
				uint8Field("B"))),
		},

		{
			description: "Simrad: Text Message",
			pgn:         130816,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("1857"),
				reservedField(8*1),
				matchLookupField("Proprietary ID", 8*1, "50", "SIMNET_COMMAND"),
				uint8Field("A"),
				uint8Field("B"),
				uint8Field("C"),
				uint8Field("SID"),
				uint8Field("Prio"),
				stringFixField("Text", 8*32))),
		},

		{
			description: "Navico: Product Information",
			pgn:         130817,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("275"),
				uint16Field("Product Code"),
				stringFixField("Model", 8*32),
				uint8Field("A"),
				uint8Field("B"),
				uint8Field("C"),
				stringFixField("Firmware version", 8*10),
				stringFixField("Firmware date", 8*32),
				stringFixField("Firmware time", 8*32))),
		},

		{
			description: "Lowrance: Product Information",
			pgn:         130817,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("140"),
				uint16Field("Product Code"),
				stringFixField("Model", 8*32),
				uint8Field("A"),
				uint8Field("B"),
				uint8Field("C"),
				stringFixField("Firmware version", 8*10),
				stringFixField("Firmware date", 8*32),
				stringFixField("Firmware time", 8*32))),
		},

		{
			description: "Simnet: Reprogram Data",
			pgn:         130818,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList:   varLenFieldListToFixed(append(company("1857"), uint16Field("Version"), uint16Field("Sequence"), binaryField("Data", 8*217, ""))),
		},

		{
			description: "Simnet: Request Reprogram",
			pgn:         130819,
			complete:    packetStatusFieldLengthsUnknown | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList:   varLenFieldListToFixed(company("1857")),
		},

		{
			description: "Simnet: Reprogram Status",
			pgn:         130820,
			complete:    packetStatusFieldLengthsUnknown | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList:   varLenFieldListToFixed(append(company("1857"), reservedField(8*1), uint8Field("Status"), reservedField(8*3))),
		},

		/* M/V Dirona */
		{
			description: "Furuno: Unknown 130820",
			pgn:         130820,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList:   varLenFieldListToFixed(append(company("1855"), uint8Field("A"), uint8Field("B"), uint8Field("C"), uint8Field("D"), uint8Field("E"))),
		},

		/* Fusion */
		{
			description: "Fusion: Source Name",
			pgn:         130820,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchLookupField("Message ID", 8*1, "2", "FUSION_MESSAGE_ID"),
				uint8Field("A"),
				uint8Field("Source ID"),
				uint8Field("Current Source ID"),
				uint8Field("D"),
				uint8Field("E"),
				stringlzField("Source", 8*5))),
		},

		{
			description: "Fusion: Track Info",
			pgn:         130820,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchLookupField("Message ID", 8*1, "4", "FUSION_MESSAGE_ID"),
				uint16Field("A"),
				lookupField("Transport", 4, "ENTERTAINMENT_PLAY_STATUS"),
				simpleField("X", 4),
				uint8Field("B"),
				uint16Field("Track #"),
				uint16Field("C"),
				uint16Field("Track Count"),
				uint16Field("E"),
				timeUfix24MsField("Length", ""),
				timeUfix24MsField("Position in track", ""),
				uint16Field("H"))),
		},

		{
			description: "Fusion: Track",
			pgn:         130820,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchLookupField("Message ID", 8*1, "5", "FUSION_MESSAGE_ID"),
				uint8Field("A"),
				simpleField("B", 8*5),
				stringlzField("Track", 8*10))),
		},

		{
			description: "Fusion: Artist",
			pgn:         130820,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchLookupField("Message ID", 8*1, "6", "FUSION_MESSAGE_ID"),
				uint8Field("A"),
				simpleField("B", 8*5),
				stringlzField("Artist", 8*10))),
		},

		{
			description: "Fusion: Album",
			pgn:         130820,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchLookupField("Message ID", 8*1, "7", "FUSION_MESSAGE_ID"),
				uint8Field("A"),
				simpleField("B", 8*5),
				stringlzField("Album", 8*10))),
		},

		{
			description: "Fusion: Unit Name",
			pgn:         130820,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchLookupField("Message ID", 8*1, "33", "FUSION_MESSAGE_ID"),
				uint8Field("A"),
				stringlzField("Name", 8*14))),
		},

		{
			description: "Fusion: Zone Name",
			pgn:         130820,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchLookupField("Message ID", 8*1, "45", "FUSION_MESSAGE_ID"),
				uint8Field("A"),
				uint8Field("Number"),
				stringlzField("Name", 8*13))),
		},

		{
			description: "Fusion: Play Progress",
			pgn:         130820,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchLookupField("Message ID", 8*1, "9", "FUSION_MESSAGE_ID"),
				uint8Field("A"),
				uint8Field("B"),
				timeUfix24MsField("Progress", ""))),
		},

		{
			description: "Fusion: AM/FM Station",
			pgn:         130820,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchLookupField("Message ID", 8*1, "11", "FUSION_MESSAGE_ID"),
				uint8Field("A"),
				lookupField("AM/FM", 8*1, "FUSION_RADIO_SOURCE"),
				uint8Field("B"),
				radioFrequencyField("Frequency", 1),
				uint8Field("C"),
				stringlzField("Track", 8*10))),
		},

		{
			description: "Fusion: VHF",
			pgn:         130820,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchLookupField("Message ID", 8*1, "12", "FUSION_MESSAGE_ID"),
				uint8Field("A"),
				uint8Field("B"),
				uint8Field("Channel"),
				simpleField("D", 8*3))),
		},

		{
			description: "Fusion: Squelch",
			pgn:         130820,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchLookupField("Message ID", 8*1, "13", "FUSION_MESSAGE_ID"),
				uint8Field("A"),
				uint8Field("B"),
				uint8Field("Squelch"))),
		},

		{
			description: "Fusion: Scan",
			pgn:         130820,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchLookupField("Message ID", 8*1, "14", "FUSION_MESSAGE_ID"),
				uint8Field("A"),
				uint8Field("B"),
				lookupField("Scan", 2, "YES_NO"),
				simpleField("C", 6))),
		},

		{
			description: "Fusion: Menu Item",
			pgn:         130820,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchLookupField("Message ID", 8*1, "17", "FUSION_MESSAGE_ID"),
				uint8Field("A"),
				uint8Field("B"),
				uint8Field("Line"),
				uint8Field("E"),
				uint8Field("F"),
				uint8Field("G"),
				uint8Field("H"),
				uint8Field("I"),
				stringlzField("Text", 8*5))),
		},

		{
			description: "Fusion: Replay",
			pgn:         130820,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchLookupField("Message ID", 8*1, "20", "FUSION_MESSAGE_ID"),
				uint8Field("A"),
				lookupField("Mode", 8*1, "FUSION_REPLAY_MODE"),
				simpleField("C", 8*3),
				uint8Field("D"),
				uint8Field("E"),
				lookupField("Status", 8*1, "FUSION_REPLAY_STATUS"),
				uint8Field("H"),
				uint8Field("I"),
				uint8Field("J"))),
		},

		{
			description: "Fusion: Mute",
			pgn:         130820,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchLookupField("Message ID", 8*1, "23", "FUSION_MESSAGE_ID"),
				uint8Field("A"),
				lookupField("Mute", 8*1, "FUSION_MUTE_COMMAND"))),
		},

		// Range: 0 to +24
		{
			description: "Fusion: Sub Volume",
			pgn:         130820,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchLookupField("Message ID", 8*1, "26", "FUSION_MESSAGE_ID"),
				uint8Field("A"),
				uint8Field("Zone 1"),
				uint8Field("Zone 2"),
				uint8Field("Zone 3"),
				uint8Field("Zone 4"))),
		},

		// Range: -15 to +15
		{
			description: "Fusion: Tone",
			pgn:         130820,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchLookupField("Message ID", 8*1, "27", "FUSION_MESSAGE_ID"),
				uint8Field("A"),
				uint8Field("B"),
				simpleSignedField("Bass", 8*1),
				simpleSignedField("Mid", 8*1),
				simpleSignedField("Treble", 8*1))),
		},

		{
			description: "Fusion: Volume",
			pgn:         130820,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchLookupField("Message ID", 8*1, "29", "FUSION_MESSAGE_ID"),
				uint8Field("A"),
				uint8Field("Zone 1"),
				uint8Field("Zone 2"),
				uint8Field("Zone 3"),
				uint8Field("Zone 4"))),
		},

		{
			description: "Fusion: Power State",
			pgn:         130820,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchLookupField("Message ID", 8*1, "32", "FUSION_MESSAGE_ID"),
				uint8Field("A"),
				lookupField("State", 8*1, "FUSION_POWER_STATE"))),
		},

		{
			description: "Fusion: SiriusXM Channel",
			pgn:         130820,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchLookupField("Message ID", 8*1, "36", "FUSION_MESSAGE_ID"),
				simpleField("A", 8*4),
				stringlzField("Channel", 8*12))),
		},

		{
			description: "Fusion: SiriusXM Title",
			pgn:         130820,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchLookupField("Message ID", 8*1, "37", "FUSION_MESSAGE_ID"),
				simpleField("A", 8*4),
				stringlzField("Title", 8*12))),
		},

		{
			description: "Fusion: SiriusXM Artist",
			pgn:         130820,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchLookupField("Message ID", 8*1, "38", "FUSION_MESSAGE_ID"),
				simpleField("A", 8*4),
				stringlzField("Artist", 8*12))),
		},

		{
			description: "Fusion: SiriusXM Genre",
			pgn:         130820,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("419"),
				matchLookupField("Message ID", 8*1, "40", "FUSION_MESSAGE_ID"),
				simpleField("A", 8*4),
				stringlzField("Genre", 8*12))),
		},

		// NAC-3 sends this once a second, with (decoded) data like this:
		// \r\n1720.0,3,0.0,0.1,0.0,1.8,0.00,358.0,0.00,359.9,0.36,0.09,4.1,4.0,0,1.71,0.0,0.50,0.90,51.00,17.10,4.00,-7.43,231.28,4.06,1.8,0.00,0.0,0.0,0.0,0.0,
		{
			description: "Navico: ASCII Data",
			pgn:         130821,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList:   varLenFieldListToFixed(append(company("275"), simpleField("A", 8*1), stringFixField("Message", 8*256))),
		},

		/* M/V Dirona */
		{
			description: "Furuno: Unknown 130821",
			pgn:         130821,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("1855"),
				uint8Field("SID"),
				uint8Field("A"),
				uint8Field("B"),
				uint8Field("C"),
				uint8Field("D"),
				uint8Field("E"),
				uint8Field("F"),
				uint8Field("G"),
				uint8Field("H"),
				uint8Field("I"))),
		},

		{
			description: "Navico: Unknown 1",
			pgn:         130822,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList:   varLenFieldListToFixed(append(company("275"), binaryField("Data", 8*231, ""))),
		},

		{
			description: "Maretron: Proprietary Temperature High Range",
			pgn:         130823,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("137"),
				uint8Field("SID"),
				instanceField(),
				lookupField("Source", 8*1, "TEMPERATURE_SOURCE"),
				temperatureHighField("Actual Temperature"),
				temperatureHighField("Set Temperature"))),
		},

		{
			description: "B&G: key-value data",
			pgn:         130824,
			complete:    packetStatusLookupsUnknown,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("381"),
				lookupFieldtypeField("Key", 12, "BANDG_KEY_VALUE"),
				simpleDescField("Length", 4, "Length of field 6"),
				keyValueField("Value", "Data value"))),
			repeatingField1: math.MaxUint8,
			repeatingCount1: 3,
			repeatingStart1: 4,
			interval:        1000,
			explanation:     "Contains any number of key/value pairs, sent by various B&G devices such as MFDs and Sailing Processors.",
		},

		/* M/V Dirona */
		{
			description: "Maretron: Annunciator",
			pgn:         130824,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("137"),
				uint8Field("Field 4"),
				uint8Field("Field 5"),
				uint16Field("Field 6"),
				uint8Field("Field 7"),
				uint16Field("Field 8"))),
		},

		{
			description: "Navico: Unknown 2",
			pgn:         130825,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList:   varLenFieldListToFixed(append(company("275"), binaryField("Data", 8*10, ""))),
		},

		/* Uwe Lovas has seen this from EP-70R */
		{
			description: "Lowrance: unknown",
			pgn:         130827,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("140"),
				uint8Field("A"),
				uint8Field("B"),
				uint8Field("C"),
				uint8Field("D"),
				uint16Field("E"),
				uint16Field("F"))),
		},

		{
			description: "Simnet: Set Serial Number",
			pgn:         130828,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList:   varLenFieldListToFixed(company("1857")),
		},

		{
			description: "Suzuki: Engine and Storage Device Config",
			pgn:         130831,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList:   varLenFieldListToFixed(company("586")),
		},

		{
			description: "Simnet: Fuel Used - High Resolution",
			pgn:         130832,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList:   varLenFieldListToFixed(company("1857")),
		},

		{
			description: "B&G: User and Remote rename",
			pgn:         130833,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("381"),
				lookupFieldtypeField("Data Type", 12, "BANDG_KEY_VALUE"),
				simpleDescField("Length", 4, "Length of field 8"),
				reservedField(8*1),
				lookupField("Decimals", 8, "BANDG_DECIMALS"),
				stringFixField("Short name", 8*8),
				stringFixField("Long name", 8*16))),
		},

		{
			description: "Simnet: Engine and Tank Configuration",
			pgn:         130834,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList:   varLenFieldListToFixed(company("1857")),
		},

		{
			description: "Simnet: Set Engine and Tank Configuration",
			pgn:         130835,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList:   varLenFieldListToFixed(company("1857")),
		},

		/* Seen when HDS8 configures EP65R */
		{
			description: "Simnet: Fluid Level Sensor Configuration",
			pgn:         130836,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("1857"),
				uint8Field("C"),
				uint8Field("Device"),
				instanceField(),
				simpleField("F", 1*4),
				lookupField("Tank type", 1*4, "TANK_TYPE"),
				volumeUfix32DlField("Capacity"),
				uint8Field("G"),
				simpleSignedField("H", 8*2),
				simpleSignedField("I", 8*1))),
		},

		{
			description: "Maretron: Switch Status Counter",
			pgn:         130836,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("137"),
				instanceField(),
				uint8Field("Indicator Number"),
				dateField("Start Date"),
				timeField("Start Time"),
				uint8Field("OFF Counter"),
				uint8Field("ON Counter"),
				uint8Field("ERROR Counter"),
				lookupField("Switch Status", 2, "OFF_ON"),
				reservedField(6))),
			interval: 15000,
		},

		{
			description: "Simnet: Fuel Flow Turbine Configuration",
			pgn:         130837,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList:   varLenFieldListToFixed(company("1857")),
		},

		{
			description: "Maretron: Switch Status Timer",
			pgn:         130837,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("137"),
				instanceField(),
				uint8Field("Indicator Number"),
				dateField("Start Date"),
				timeField("Start Time"),
				timeUfix32SField("Accumulated OFF Period", ""),
				timeUfix32SField("Accumulated ON Period", ""),
				timeUfix32SField("Accumulated ERROR Period", ""),
				lookupField("Switch Status", 2, "OFF_ON"),
				reservedField(6),
			)),
			interval: 15000,
		},

		{
			description: "Simnet: Fluid Level Warning",
			pgn:         130838,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList:   varLenFieldListToFixed(company("1857")),
		},

		{
			description: "Simnet: Pressure Sensor Configuration",
			pgn:         130839,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList:   varLenFieldListToFixed(company("1857")),
		},

		{
			description: "Simnet: Data User Group Configuration",
			pgn:         130840,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList:   varLenFieldListToFixed(company("1857")),
		},

		{
			description: "Simnet: AIS Class B static data (msg 24 Part A)",
			pgn:         130842,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("1857"),
				matchField("Message ID", 6, "0", "Msg 24 Part A"),
				lookupField("Repeat Indicator", 2, "REPEAT_INDICATOR"),
				uint8Field("D"),
				uint8Field("E"),
				mmsiField("User ID"),
				stringFixField("Name", 8*20))),
		},

		{
			description: "Furuno: Six Degrees Of Freedom Movement",
			pgn:         130842,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("1855"),
				simpleSignedField("A", 8*4),
				simpleSignedField("B", 8*4),
				simpleSignedField("C", 8*4),
				simpleSignedField("D", 8*1),
				simpleSignedField("E", 8*4),
				simpleSignedField("F", 8*4),
				simpleSignedField("G", 8*2),
				simpleSignedField("H", 8*2),
				simpleSignedField("I", 8*2))),
		},

		{
			description: "Simnet: AIS Class B static data (msg 24 Part B)",
			pgn:         130842,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("1857"),
				matchField("Message ID", 6, "1", "Msg 24 Part B"),
				lookupField("Repeat Indicator", 2, "REPEAT_INDICATOR"),
				uint8Field("D"),
				uint8Field("E"),
				mmsiField("User ID"),
				lookupField("Type of ship", 8*1, "SHIP_TYPE"),
				stringFixField("Vendor ID", 8*7),
				stringFixField("Callsign", 8*7),
				lengthUfix16DmField("Length"),
				lengthUfix16DmField("Beam"),
				lengthUfix16DmField("Position reference from Starboard"),
				lengthUfix16DmField("Position reference from Bow"),
				mmsiField("Mothership User ID"),
				spareField(6),
				reservedField(2))),
		},

		{
			description: "Furuno: Heel Angle, Roll Information",
			pgn:         130843,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("1855"),
				uint8Field("A"),
				uint8Field("B"),
				angleI16Field("Yaw", ""),
				angleI16Field("Pitch", ""),
				angleI16Field("Roll", ""))),
		},

		{
			description: "Simnet: Sonar Status, Frequency and DSP Voltage",
			pgn:         130843,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList:   varLenFieldListToFixed(company("1857")),
		},

		{
			description: "Furuno: Multi Sats In View Extended",
			pgn:         130845,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList:   varLenFieldListToFixed(company("1855")),
		},

		{
			description: "Simnet: Key Value",
			pgn:         130845,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("1857"),
				uint8DescField("Address", "NMEA 2000 address of commanded device"),
				lookupField("Repeat Indicator", 8*1, "REPEAT_INDICATOR"),
				lookupField("Display Group", 8*1, "SIMNET_DISPLAY_GROUP"),
				reservedField(8*1),
				lookupFieldtypeField("Key", 8*2, "SIMNET_KEY_VALUE"),
				spareField(8*1),
				simpleDescField("MinLength", 8*1, "Length of data field"),
				keyValueField("Value", "Data value"))),
			interval: math.MaxUint16,
		},

		{
			description: "Simnet: Parameter Set",
			pgn:         130846,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("1857"),
				uint8DescField("Address", "NMEA 2000 address of commanded device"),
				uint8DescField("B", "00, 01 or FF observed"),
				lookupField("Display Group", 8*1, "SIMNET_DISPLAY_GROUP"),
				uint16DescField("D", "Various values observed"),
				lookupFieldtypeField("Key", 8*2, "SIMNET_KEY_VALUE"),
				spareField(8*1),
				simpleDescField("Length", 8*1, "Length of data field"),
				keyValueField("Value", "Data value"),
			)),
			interval: math.MaxUint16,
		},

		{
			description: "Furuno: Motion Sensor Status Extended",
			pgn:         130846,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList:   varLenFieldListToFixed(company("1855")),
		},

		{
			description: "SeaTalk: Node Statistics",
			pgn:         130847,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("1851"),
				uint16Field("Product Code"),
				uint8Field("Year"),
				uint8Field("Month"),
				uint16Field("Device Number"),
				voltageU1610mvField("Node Voltage"))),
		},

		{
			description: "Simnet: AP Command",
			pgn:         130850,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("1857"),
				uint8DescField("Address", "NMEA 2000 address of commanded device"),
				reservedField(8*1),
				matchLookupField("Proprietary ID", 8*1, "255", "SIMNET_EVENT_COMMAND"),
				lookupField("AP status", 8*1, "SIMNET_AP_STATUS"),
				lookupField("AP Command", 8*1, "SIMNET_AP_EVENTS"),
				spareField(8*1),
				lookupField("Direction", 8*1, "SIMNET_DIRECTION"),
				angleU16Field("Angle", "Commanded angle change"))),
		},

		{
			description: "Simnet: Event Command: AP command",
			pgn:         130850,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("1857"),
				matchLookupField("Proprietary ID", 8*1, "2", "SIMNET_EVENT_COMMAND"),
				uint16Field("Unused A"),
				uint8Field("Controlling Device"),
				lookupField("Event", 8*1, "SIMNET_AP_EVENTS"),
				simpleField("Unused B", 8*1),
				lookupField("Direction", 8*1, "SIMNET_DIRECTION"),
				angleU16Field("Angle", ""),
				simpleField("Unused C", 8*1))),
		},

		{
			description: "Simnet: Alarm",
			pgn:         130850,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("1857"),
				uint8DescField("Address", "NMEA 2000 address of commanded device"),
				reservedField(8*1),
				matchLookupField("Proprietary ID", 8*1, "1", "SIMNET_EVENT_COMMAND"),
				reservedField(8*1),
				lookupField("Alarm", 8*2, "SIMNET_ALARM"),
				uint16Field("Message ID"),
				uint8Field("F"),
				uint8Field("G"))),
			interval:    math.MaxUint16,
			explanation: "There may follow a PGN 130856 'Simnet: Alarm Text' message with a textual explanation of the alarm",
		},

		{
			description: "Simnet: Event Reply: AP command",
			pgn:         130851,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("1857"),
				matchLookupField("Proprietary ID", 8*1, "2", "SIMNET_EVENT_COMMAND"),
				uint16Field("B"),
				uint8DescField("Address", "NMEA 2000 address of controlling device"),
				lookupField("Event", 8*1, "SIMNET_AP_EVENTS"),
				uint8Field("C"),
				lookupField("Direction", 8*1, "SIMNET_DIRECTION"),
				angleU16Field("Angle", ""),
				uint8Field("G"))),
		},

		{
			description: "Simnet: Alarm Message",
			pgn:         130856,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("1857"),
				uint16Field("Message ID"),
				uint8Field("B"),
				uint8Field("C"),
				stringFixField("Text", 8*common.FastPacketMaxSize))),
			interval:    math.MaxUint16,
			explanation: "Usually accompanied by a PGN 130850 'Simnet: Alarm' message with the same information in binary form.",
		},

		{
			description: "Simnet: AP Unknown 4",
			pgn:         130860,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("1857"),
				uint8Field("A"),
				simpleSignedField("B", 8*4),
				simpleSignedField("C", 8*4),
				uint32Field("D"),
				simpleSignedField("E", 8*4),
				uint32Field("F"))),
			interval:    1000,
			explanation: "Seen as sent by AC-42 and H5000 AP only so far.",
		},

		{
			description: "Airmar: Additional Weather Data",
			pgn:         130880,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("135"),
				uint8Field("C"),
				temperatureField("Apparent Windchill Temperature"),
				temperatureField("True Windchill Temperature"),
				temperatureField("Dewpoint"))),
			url: "http://www.airmartechnology.com/uploads/installguide/PB2000UserManual.pdf",
		},

		{
			description: "Airmar: Heater Control",
			pgn:         130881,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("135"),
				uint8Field("C"),
				temperatureField("Plate Temperature"),
				temperatureField("Air Temperature"),
				temperatureField("Dewpoint"))),
			url: "http://www.airmartechnology.com/uploads/installguide/PB2000UserManual.pdf",
		},

		{
			description: "Airmar: POST",
			pgn:         130944,
			complete:    packetStatusIncomplete | packetStatusNotSeen,
			packetType:  packetTypeFast,
			fieldList: varLenFieldListToFixed(append(company("135"),
				lookupField("Control", 1, "AIRMAR_POST_CONTROL"),
				reservedField(7),
				uint8Field("Number of ID/test result pairs to follow"),
				lookupFieldDesc("Test ID",
					8*1,
					"AIRMAR_POST_ID",
					"See Airmar docs for table of IDs and failure codes; these lookup values are for DST200"),
				uint8DescField("Test result", "Values other than 0 are failure codes"))),
			url: "http://www.airmartechnology.com/uploads/installguide/DST200UserlManual.pdf",
		},

		{
			description: "Actisense: Operating mode",
			pgn:         common.ActisenseBEM + 0x11,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				uint16Field("Model ID"),
				uint32Field("Serial ID"),
				uint32Field("Error ID"),
				uint16Field("Operating Mode"),
			},
		},

		{
			description: "Actisense: Startup status",
			pgn:         common.ActisenseBEM + 0xf0,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				uint16Field("Model ID"),
				uint32Field("Serial ID"),
				uint32Field("Error ID"),
				versionField("Firmware version"),
				uint8Field("Reset status"),
				uint8Field("A"),
			},
		},

		{
			description: "Actisense: System status",
			pgn:         common.ActisenseBEM + 0xf2,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("SID"),
				uint16Field("Model ID"),
				uint32Field("Serial ID"),
				uint32Field("Error ID"),
				uint8Field("Indi channel count"),
				uint8Field("Ch1 Rx Bandwidth"),
				uint8Field("Ch1 Rx Load"),
				uint8Field("Ch1 Rx Filtered"),
				uint8Field("Ch1 Rx Dropped"),
				uint8Field("Ch1 Tx Bandwidth"),
				uint8Field("Ch1 Tx Load"),
				uint8Field("Ch2 Rx Bandwidth"),
				uint8Field("Ch2 Rx Load"),
				uint8Field("Ch2 Rx Filtered"),
				uint8Field("Ch2 Rx Dropped"),
				uint8Field("Ch2 Tx Bandwidth"),
				uint8Field("Ch2 Tx Load"),
				uint8Field("Uni channel count"),
				uint8Field("Ch1 Bandwidth"),
				uint8Field("Ch1 Deleted"),
				uint8Field("Ch1 BufferLoading"),
				uint8Field("Ch1 PointerLoading"),
				uint8Field("Ch2 Bandwidth"),
				uint8Field("Ch2 Deleted"),
				uint8Field("Ch2 BufferLoading"),
				uint8Field("Ch2 PointerLoading"),
			},
		},

		{
			description: "Actisense: ?",
			pgn:         common.ActisenseBEM + 0xf4,
			complete:    packetStatusIncomplete,
			packetType:  packetTypeFast,
			fieldList:   [33]pgnField{uint8Field("SID"), uint16Field("Model ID"), uint32Field("Serial ID")},
		},

		{
			description: "iKonvert: Network status",
			pgn:         common.IKnovertBEM,
			complete:    packetStatusComplete,
			packetType:  packetTypeFast,
			fieldList: [33]pgnField{
				uint8Field("CAN network load"),
				uint32Field("Errors"),
				uint8Field("Device count"),
				timeField("Uptime"),
				uint8Field("Gateway address"),
				uint32Field("Rejected TX requests"),
			},
		},
	}
}

type pgnRange struct {
	pgnStart   uint32
	pgnEnd     uint32
	pgnStep    uint32
	who        string
	packetType packetType
}

var pgnRanges = []pgnRange{
	{0xe800, 0xee00, 256, "ISO 11783", packetTypeSingle},
	{0xef00, 0xef00, 256, "NMEA", packetTypeSingle},
	{0xf000, 0xfeff, 1, "NMEA", packetTypeSingle},
	{0xff00, 0xffff, 1, "Manufacturer", packetTypeSingle},
	{0x1ed00, 0x1ee00, 256, "NMEA", packetTypeFast},
	{0x1ef00, 0x1ef00, 256, "Manufacturer", packetTypeFast},
	{0x1f000, 0x1feff, 1, "NMEA", packetTypeMixed},
	{0x1ff00, 0x1ffff, 1, "Manufacturer", packetTypeFast},
}

func (ana *Analyzer) checkPGNs() error {
	var i int
	prevPRN := uint32(0)

	for i = 0; i < len(ana.pgns); i++ {
		pgnRangeIndex := 0
		prn := ana.pgns[i].pgn
		var pgn *pgnInfo

		if prn < prevPRN {
			return ana.Logger.Error("Internal error: PGN %d is not sorted correctly\n", prn)
		}

		if prn < common.ActisenseBEM {
			for prn > pgnRanges[pgnRangeIndex].pgnEnd && pgnRangeIndex < len(pgnRanges) {
				pgnRangeIndex++
			}
			if prn < pgnRanges[pgnRangeIndex].pgnStart || prn > pgnRanges[pgnRangeIndex].pgnEnd {
				return ana.Logger.Error("Internal error: PGN %d is not part of a valid PRN range\n", prn)
			}
			if pgnRanges[pgnRangeIndex].pgnStep == 256 && (prn&0xff) != 0 {
				return ana.Logger.Error("Internal error: PGN %d (0x%x) is PDU1 and must have a PGN ending in 0x00\n", prn, prn)
			}
			if !(pgnRanges[pgnRangeIndex].packetType == ana.pgns[i].packetType ||
				pgnRanges[pgnRangeIndex].packetType == packetTypeMixed ||
				ana.pgns[i].packetType == packetTypeISOTP) {
				return ana.Logger.Error("Internal error: PGN %d (0x%x) is in range 0x%x-0x%x and must have packet type %s\n",
					prn,
					prn,
					pgnRanges[pgnRangeIndex].pgnStart,
					pgnRanges[pgnRangeIndex].pgnEnd,
					pgnRanges[pgnRangeIndex].packetType)
			}
		}

		if prn == prevPRN || ana.pgns[i].fallback {
			continue
		}
		prevPRN = prn
		pgn, _ = ana.searchForPgn(prevPRN)
		if pgn != &ana.pgns[i] {
			return ana.Logger.Error("Internal error: PGN %d is not found correctly\n", prevPRN)
		}
	}

	return nil
}

/**
 * Return the first Pgn entry for which the pgn is found.
 * There can be multiple (with differing 'match' fields).
 */
func (ana *Analyzer) searchForPgn(pgn uint32) (*pgnInfo, int) {
	start := 0
	end := len(ana.pgns)
	var mid int

	for start <= end {
		mid = (start + end) / 2
		if pgn == ana.pgns[mid].pgn {
			// Return the first one, unless it is the catch-all
			for mid > 0 && pgn == ana.pgns[mid-1].pgn {
				mid--
			}
			if ana.pgns[mid].fallback {
				mid++
				if pgn != ana.pgns[mid].pgn {
					return nil, -1
				}
			}
			return &ana.pgns[mid], mid
		}
		if pgn < ana.pgns[mid].pgn {
			if mid == 0 {
				return nil, -1
			}
			end = mid - 1
		} else {
			start = mid + 1
		}
	}
	return nil, -1
}

/**
 * Return the last Pgn entry for which fallback == true && prn is smaller than requested.
 * This is slower, but is not used often.
 */
func (ana *Analyzer) searchForUnknownPgn(pgnID uint32) (*pgnInfo, error) {
	var fallback *pgnInfo

	for _, pgn := range ana.pgns {
		if pgn.fallback {
			pgnCopy := pgn
			fallback = &pgnCopy
		}
		if pgn.pgn >= pgnID {
			break
		}
	}
	if fallback == nil {
		return nil, ana.Logger.Abort("Cannot find catch-all PGN definition for PGN %d; internal definition error\n", pgnID)
	}
	ana.Logger.Debug("Found catch-all PGN %d for PGN %d\n", fallback.pgn, pgnID)
	return fallback, nil
}

func (ana *Analyzer) getField(pgnID, field uint32) *pgnField {
	pgn, _ := ana.searchForPgn(pgnID)

	if pgn == nil {
		ana.Logger.Debug("PGN %d is unknown\n", pgnID)
		return nil
	}
	if field < pgn.fieldCount {
		return &pgn.fieldList[field]
	}
	ana.Logger.Debug("PGN %d does not have field %d\n", pgnID, field)
	return nil
}

/*
 * Return the best match for this pgnId.
 * If all else fails, return an 'fallback' match-all PGN that
 * matches the fast/single frame, PDU1/PDU2 and proprietary/generic range.
 */
func (ana *Analyzer) getMatchingPgn(pgnID uint32, data []byte) (*pgnInfo, error) {
	pgn, pgnIdx := ana.searchForPgn(pgnID)

	if pgn == nil {
		var err error
		pgn, err = ana.searchForUnknownPgn(pgnID)
		if err != nil {
			return nil, err
		}
		fallbackPGN := 0
		if pgn != nil {
			fallbackPGN = int(pgn.pgn)
		}
		ana.Logger.Debug("getMatchingPgn: Unknown PGN %d . fallback %d\n", pgnID, fallbackPGN)
		return pgn, nil
	}

	if !pgn.hasMatchFields {
		ana.Logger.Debug("getMatchingPgn: PGN %d has no match fields, returning '%s'\n", pgnID, pgn.description)
		return pgn, nil
	}

	// Here if we have a PGN but it must be matched to the list of match fields.
	// This might end up without a solution, in that case return the catch-all fallback PGN.

	for prn := pgn.pgn; pgn.pgn == prn; {
		matchedFixedField := true
		hasFixedField := false

		ana.Logger.Debug("getMatchingPgn: PGN %d matching with manufacturer specific '%s'\n", prn, pgn.description)

		// Iterate over fields
		startBit := uint32(0)
		for i := uint32(0); i < pgn.fieldCount; i++ {
			field := &pgn.fieldList[i]
			bits := field.size

			if field.unit != "" && field.unit[0] == '=' {
				var value int64
				var maxValue int64

				hasFixedField = true
				//nolint:errcheck
				desiredValue, _ := strconv.ParseInt(field.unit[1:], 10, 64)
				fieldSize := int(field.size)
				if !extractNumber(field, data, int(startBit), fieldSize, &value, &maxValue, ana.Logger) || value != desiredValue {
					ana.Logger.Debug("getMatchingPgn: PGN %d field '%s' value %d does not match %d\n",
						prn,
						field.name,
						value,
						desiredValue)
					matchedFixedField = false
					break
				}
				ana.Logger.Debug(
					"getMatchingPgn: PGN %d field '%s' value %d matches %d\n", prn, field.name, value, desiredValue)
			}
			startBit += bits
		}
		if !hasFixedField {
			ana.Logger.Debug("getMatchingPgn: Cant determine prn choice, return prn=%d variation '%s'\n", prn, pgn.description)
			return pgn, nil
		}
		if matchedFixedField {
			ana.Logger.Debug("getMatchingPgn: PGN %d selected manufacturer specific '%s'\n", prn, pgn.description)
			return pgn, nil
		}

		pgnIdx++
		pgn = &ana.pgns[pgnIdx]
	}

	return ana.searchForUnknownPgn(pgnID)
}

func varLenFieldListToFixed(list []pgnField) [33]pgnField {
	var out [33]pgnField
	if len(list) > len(out) {
		panic("input list too large")
	}
	copy(out[:], list)
	return out
}

func (ana *Analyzer) camelCase(upperCamelCase bool) {
	var haveEarlierSpareOrReserved bool

	for i := 0; i < len(ana.pgns); i++ {
		ana.pgns[i].camelDescription = camelize(ana.pgns[i].description, upperCamelCase, 0)
		haveEarlierSpareOrReserved = false
		for j := 0; j < len(ana.pgns[i].fieldList) && ana.pgns[i].fieldList[j].name != ""; j++ {
			name := ana.pgns[i].fieldList[j].name

			var order int
			if haveEarlierSpareOrReserved {
				order = j + 1
			}
			ana.pgns[i].fieldList[j].camelName = camelize(name, upperCamelCase, order)
			if name == "Reserved" || name == "Spare" {
				haveEarlierSpareOrReserved = true
			}
		}
	}
}

func camelize(str string, upperCamelCase bool, order int) string {
	lastIsAlpha := !upperCamelCase

	var p bytes.Buffer
	for _, c := range str {
		if unicode.IsLetter(c) || unicode.IsDigit(c) {
			if lastIsAlpha {
				p.WriteRune(unicode.ToLower(c))
			} else {
				p.WriteRune(unicode.ToUpper(c))
				lastIsAlpha = true
			}
		} else {
			lastIsAlpha = false
		}
	}

	if order > 0 && (str == "Reserved" || str == "Spare") {
		p.WriteString(strconv.Itoa(order))
	}
	return p.String()
}
