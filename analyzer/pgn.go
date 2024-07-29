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

var (
	immutPGNs []pgnInfo
	pgnMap    map[uint32]pgnInfo
)

func initPGNs() {
	immutPGNs = createPGNList()
	pgnMap = map[uint32]pgnInfo{}
	for _, pgn := range immutPGNs {
		pgnMap[pgn.pgn] = pgn
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
			return common.Error(ana.Logger, ana.isCLI, "Internal error: PGN %d is not sorted correctly", prn)
		}

		if prn < common.ActisenseBEM {
			for prn > pgnRanges[pgnRangeIndex].pgnEnd && pgnRangeIndex < len(pgnRanges) {
				pgnRangeIndex++
			}
			if prn < pgnRanges[pgnRangeIndex].pgnStart || prn > pgnRanges[pgnRangeIndex].pgnEnd {
				return common.Error(ana.Logger, ana.isCLI, "Internal error: PGN %d is not part of a valid PRN range", prn)
			}
			if pgnRanges[pgnRangeIndex].pgnStep == 256 && (prn&0xff) != 0 {
				return common.Error(ana.Logger, ana.isCLI, "Internal error: PGN %d (0x%x) is PDU1 and must have a PGN ending in 0x00", prn, prn)
			}
			if !(pgnRanges[pgnRangeIndex].packetType == ana.pgns[i].packetType ||
				pgnRanges[pgnRangeIndex].packetType == packetTypeMixed ||
				ana.pgns[i].packetType == packetTypeISOTP) {
				return common.Error(ana.Logger, ana.isCLI, "Internal error: PGN %d (0x%x) is in range 0x%x-0x%x and must have packet type %s",
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
			return common.Error(ana.Logger, ana.isCLI, "Internal error: PGN %d is not found correctly", prevPRN)
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
		return nil, common.Abort(ana.Logger, ana.isCLI, "Cannot find catch-all PGN definition for PGN %d; internal definition error", pgnID)
	}
	ana.Logger.Debugf("Found catch-all PGN %d for PGN %d", fallback.pgn, pgnID)
	return fallback, nil
}

func (ana *Analyzer) getField(pgnID, field uint32) *pgnField {
	pgn, _ := ana.searchForPgn(pgnID)

	if pgn == nil {
		ana.Logger.Debugf("PGN %d is unknown", pgnID)
		return nil
	}
	if field < pgn.fieldCount {
		return &pgn.fieldList[field]
	}
	ana.Logger.Debugf("PGN %d does not have field %d", pgnID, field)
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
		ana.Logger.Debugf("getMatchingPgn: Unknown PGN %d . fallback %d", pgnID, fallbackPGN)
		return pgn, nil
	}

	if !pgn.hasMatchFields {
		ana.Logger.Debugf("getMatchingPgn: PGN %d has no match fields, returning '%s'", pgnID, pgn.description)
		return pgn, nil
	}

	// Here if we have a PGN but it must be matched to the list of match fields.
	// This might end up without a solution, in that case return the catch-all fallback PGN.

	for prn := pgn.pgn; pgn.pgn == prn; {
		matchedFixedField := true
		hasFixedField := false

		ana.Logger.Debugf("getMatchingPgn: PGN %d matching with manufacturer specific '%s'", prn, pgn.description)

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
					ana.Logger.Debugf("getMatchingPgn: PGN %d field '%s' value %d does not match %d",
						prn,
						field.name,
						value,
						desiredValue)
					matchedFixedField = false
					break
				}
				ana.Logger.Debugf(
					"getMatchingPgn: PGN %d field '%s' value %d matches %d", prn, field.name, value, desiredValue)
			}
			startBit += bits
		}
		if !hasFixedField {
			ana.Logger.Debugf("getMatchingPgn: Cant determine prn choice, return prn=%d variation '%s'", prn, pgn.description)
			return pgn, nil
		}
		if matchedFixedField {
			ana.Logger.Debugf("getMatchingPgn: PGN %d selected manufacturer specific '%s'", prn, pgn.description)
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
