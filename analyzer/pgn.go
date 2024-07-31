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
	"fmt"
	"math"
	"strconv"

	"go.viam.com/rdk/logging"

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

type PacketStatus byte

const (
	PacketStatusComplete             PacketStatus = 0
	PacketStatusFieldsUnknown        PacketStatus = 1
	PacketStatusFieldLengthsUnknown  PacketStatus = 2
	PacketStatusResolutionUnknown    PacketStatus = 4
	PacketStatusLookupsUnknown       PacketStatus = 8
	PacketStatusNotSeen              PacketStatus = 16
	PacketStatusIntervalUnknown      PacketStatus = 32
	PacketStatusMissingcompanyFields PacketStatus = 64
)

const (
	PacketStatusIncomplete       = (PacketStatusFieldsUnknown | PacketStatusFieldLengthsUnknown | PacketStatusResolutionUnknown)
	PacketStatusIncompleteLookup = (PacketStatusIncomplete | PacketStatusLookupsUnknown)
	PacketStatusPDFOnly          = (PacketStatusFieldLengthsUnknown |
		PacketStatusResolutionUnknown |
		PacketStatusLookupsUnknown |
		PacketStatusNotSeen)
)

type PacketType byte

const (
	PacketTypeSingle PacketType = iota
	PacketTypeFast
	PacketTypeISOTP
	PacketTypeMixed
)

func (pt PacketType) String() string {
	switch pt {
	case PacketTypeSingle:
		return "Single"
	case PacketTypeFast:
		return "Fast"
	case PacketTypeISOTP:
		return "ISO"
	case PacketTypeMixed:
		return "Mixed"
	default:
		return "UNKNOWN"
	}
}

type PGNField struct {
	Name      string
	FieldType string

	Size        uint32 /* Size in bits. All fields are contiguous in message; use 'reserved' fields to fill in empty bits. */
	Unit        string /* String containing the 'Dimension' (e.g. s, h, m/s, etc.) */
	Description string

	Offset int32 /* Only used for SAE J1939 values with sign; these are in Offset/Excess-K notation instead
	 *    of two's complement as used by NMEA 2000.
	 *    See http://en.wikipedia.org/wiki/Offset_binary
	 */
	Resolution  float64 /* Either a positive real value or zero */
	Precision   int     /* How many decimal digits after the decimal point to print; usually 0 = automatic */
	UnitOffset  float64 /* Only used for K.C conversion in non-SI print */
	Proprietary bool    /* Field is only present if earlier PGN field is in Proprietary range */
	HasSign     bool    /* Is the value signed, e.g. has both positive and negative values? */

	/* The following fields are filled by C, no need to set in initializers */
	Order uint8

	BitOffset         int // Bit offset from start of data, e.g. lower 3 bits = bit#, bit 4.. is byte offset
	CamelName         string
	Lookup            LookupInfo
	FT                *FieldType
	PGN               *PGNInfo
	RangeMin          float64
	RangeMax          float64
	MissingValueIsOne *bool // write 0s if false or 1s if true
}

type PGNInfo struct {
	Description      string
	PGN              uint32
	Complete         PacketStatus /* Either PacketStatusComplete or bit values set for various unknown items */
	PacketType       PacketType   /* Single, Fast or ISO_TP */
	FieldList        [33]PGNField /* Note fixed # of fields; increase if needed. RepeatingFields support means this is enough for now. */
	FieldCount       uint32       /* Filled by C, no need to set in initializers. */
	CamelDescription string       /* Filled by C, no need to set in initializers. */
	Fallback         bool         /* true = this is a catch-all for unknown PGNs */
	HasMatchFields   bool         /* true = there are multiple PGNs with same PRN */
	Explanation      string       /* Preferably the NMEA 2000 explanation from the NMEA PGN field list */
	URL              string       /* External URL */
	Interval         uint16       /* Milliseconds between transmissions, standard. 0 is: not known, math.MaxUint16 = never */
	RepeatingCount1  uint8        /* How many fields repeat in set 1? */
	RepeatingCount2  uint8        /* How many fields repeat in set 2? */
	RepeatingStart1  uint8        /* At which field does the first set start? */
	RepeatingStart2  uint8        /* At which field does the second set start? */
	RepeatingField1  uint8        /* Which field explains how often the repeating fields set #1 repeats? 255 = there is no field */
	RepeatingField2  uint8        /* Which field explains how often the repeating fields set #2 repeats? 255 = there is no field */
}

func lookupField(nam string, dataLen uint32, typ string) PGNField {
	return PGNField{
		Name:       nam,
		Size:       dataLen,
		Resolution: 1,
		HasSign:    false,
		Lookup: LookupInfo{
			LookupType:          LookupTypePair,
			FunctionPair:        lookupFunctionPairForTyp[typ],
			FunctionPairReverse: lookupFunctionPairReverseForTyp[typ],
			Name:                typ,
		},
		FieldType: "LOOKUP",
	}
}

func lookupFieldtypeField(nam string, dataLen uint32, typ string) PGNField {
	return PGNField{
		Name:       nam,
		Size:       dataLen,
		Resolution: 1,
		HasSign:    false,
		Lookup: LookupInfo{
			LookupType:          LookupTypeFieldType,
			FunctionPair:        lookupFunctionPairForTyp[typ],
			FunctionPairReverse: lookupFunctionPairReverseForTyp[typ],
			Name:                typ,
		},
		FieldType: "FieldType_LOOKUP",
	}
}

func lookupTripletField(nam string, dataLen uint32, typ, desc string, order uint8) PGNField {
	return PGNField{
		Name:       nam,
		Size:       dataLen,
		Resolution: 1,
		HasSign:    false,
		Lookup: LookupInfo{
			LookupType:             LookupTypeTriplet,
			FunctionTriplet:        lookupFunctionTripletForTyp[typ],
			FunctionTripletReverse: lookupFunctionTripletReverseForTyp[typ],
			Name:                   typ,
			Val1Order:              order,
		},
		FieldType:   "INDIRECT_LOOKUP",
		Description: desc,
	}
}

func lookupFieldDesc(nam string, dataLen uint32, typ, desc string) PGNField {
	return PGNField{
		Name:       nam,
		Size:       dataLen,
		Resolution: 1,
		HasSign:    false,
		Lookup: LookupInfo{
			LookupType:          LookupTypePair,
			FunctionPair:        lookupFunctionPairForTyp[typ],
			FunctionPairReverse: lookupFunctionPairReverseForTyp[typ],
			Name:                typ,
		},
		FieldType:   "LOOKUP",
		Description: desc,
	}
}

func bitlookupField(nam string, dataLen uint32, typ string) PGNField {
	return PGNField{
		Name:       nam,
		Size:       dataLen,
		Resolution: 1,
		HasSign:    false,
		Lookup: LookupInfo{
			LookupType:          LookupTypeBit,
			FunctionPair:        lookupFunctionPairForTyp[typ],
			FunctionPairReverse: lookupFunctionPairReverseForTyp[typ],
			Name:                typ,
		},
		FieldType: "BITLOOKUP",
	}
}

func FieldTypeLookup(nam string, dataLen uint32, typ string) PGNField {
	return PGNField{
		Name:       nam,
		Size:       dataLen,
		Resolution: 1,
		HasSign:    false,
		Lookup: LookupInfo{
			LookupType:          LookupTypeFieldType,
			FunctionPair:        lookupFunctionPairForTyp[typ],
			FunctionPairReverse: lookupFunctionPairReverseForTyp[typ],
			Name:                typ,
		},
		FieldType: "LOOKUP_TYPE_FieldType",
	}
}

//nolint:unused
func unknownLookupField(nam string, dataLen uint32) PGNField {
	return PGNField{
		Name:       nam,
		Size:       dataLen,
		Resolution: 1,
		HasSign:    false,
		Lookup: LookupInfo{
			LookupType: LookupTypePair,
		},
		FieldType: "LOOKUP",
	}
}

func spareNamedField(nam string, dataLen uint32) PGNField {
	return PGNField{
		Name: nam, Size: dataLen, Resolution: 1, FieldType: "SPARE",
	}
}

func spareField(dataLen uint32) PGNField {
	return spareNamedField("Spare", dataLen)
}

func reservedField(dataLen uint32) PGNField {
	return PGNField{
		Name: "Reserved", Size: dataLen, Resolution: 1, FieldType: "RESERVED",
	}
}

func reservedPropField(dataLen uint32, desc string) PGNField {
	return PGNField{
		Name: "Reserved", Size: dataLen, Resolution: 1, Description: desc, FieldType: "RESERVED", Proprietary: true,
	}
}

func binaryField(nam string, dataLen uint32, desc string) PGNField {
	return PGNField{
		Name: nam, Size: dataLen, Resolution: 1, Description: desc, FieldType: "BINARY",
	}
}

//nolint:unused
func binaryUnitField(nam string, dataLen uint32, unt, desc string, prop bool) PGNField {
	return PGNField{
		Name: nam, Size: dataLen, Resolution: 1, Unit: unt, Description: desc, Proprietary: prop, FieldType: "BINARY",
	}
}

func latitudeI32Field(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 4, Resolution: 1e-7, HasSign: true, Unit: "deg", FieldType: "GEO_FIX32",
	}
}

func latitudeI64Field(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 8, Resolution: 1e-16, HasSign: true, Unit: "deg", FieldType: "GEO_FIX64",
	}
}

func longitudeI32Field(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 4, Resolution: 1e-7, HasSign: true, Unit: "deg", FieldType: "GEO_FIX32",
	}
}

func longitudeI64Field(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 8, Resolution: 1e-16, HasSign: true, Unit: "deg", FieldType: "GEO_FIX64",
	}
}

func angleU16Field(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: resRadians, HasSign: false, Unit: "rad", Description: desc,
		FieldType: "ANGLE_UFIX16",
	}
}

func angleI16Field(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: resRadians, HasSign: true, Unit: "rad", Description: desc,
		FieldType: "ANGLE_FIX16",
	}
}

func int32Field(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 4, Resolution: 1, HasSign: true, FieldType: "INT32", Description: desc,
	}
}

// A whole bunch of different NUMBER fields, with variing resolutions

func unsignedAlmanacParameterField(nam string, dataLen uint32, res float64, unt, desc string) PGNField {
	return PGNField{
		Name: nam, Size: dataLen, Resolution: res, HasSign: false, Unit: unt, Description: desc, FieldType: "UNSIGNED_ALMANAC_PARAMETER",
	}
}

func signedAlmanacParameterField(nam string, dataLen uint32, res float64, unt, desc string) PGNField {
	return PGNField{
		Name: nam, Size: dataLen, Resolution: res, HasSign: true, Unit: unt, Description: desc, FieldType: "SIGNED_ALMANAC_PARAMETER",
	}
}

func dilutionOfPrecisionUfix16Field(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.01, FieldType: "DILUTION_OF_PRECISION_UFIX16", Description: desc,
	}
}

func dilutionOfPrecisionFix16Field(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.01, HasSign: true, FieldType: "DILUTION_OF_PRECISION_FIX16", Description: desc,
	}
}

func signaltonoiseratioUfix16Field(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.01, FieldType: "SIGNALTONOISERATIO_UFIX16", Description: desc,
	}
}

func signaltonoiseratioFix16Field(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.01, HasSign: true, FieldType: "SIGNALTONOISERATIO_FIX16", Description: desc,
	}
}

func versionField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.001, FieldType: "VERSION",
	}
}

func voltageU16VField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 1.0, Unit: "V", FieldType: "VOLTAGE_UFIX16_V",
	}
}

func voltageU1610mvField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.01, Unit: "V", FieldType: "VOLTAGE_UFIX16_10MV",
	}
}

//nolint:unused
func voltageU1650mvField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.05, Unit: "V", FieldType: "VOLTAGE_UFIX16_50MV",
	}
}

func voltageU16100mvField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.1, Unit: "V", FieldType: "VOLTAGE_UFIX16_100MV",
	}
}

func voltageUfix8200mvField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 1, Resolution: 0.2, Unit: "V", FieldType: "VOLTAGE_UFIX8_200MV",
	}
}

func voltageI1610mvField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.01, Unit: "V", HasSign: true, FieldType: "VOLTAGE_FIX16_10MV",
	}
}

func radioFrequencyField(nam string, res float64) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 4, Resolution: res, Unit: "Hz", FieldType: "RADIO_FREQUENCY_UFIX32",
	}
}

func frequencyField(nam string, res float64) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: res, Unit: "Hz", FieldType: "FREQUENCY_UFIX16",
	}
}

func speedI16MmField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.001, Unit: "m/s", HasSign: true, FieldType: "SPEED_FIX16_MM",
	}
}

func speedI16CmField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.01, Unit: "m/s", HasSign: true, FieldType: "SPEED_FIX16_CM",
	}
}

func speedU16CmField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.01, Unit: "m/s", FieldType: "SPEED_UFIX16_CM",
	}
}

func speedU16DmField(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.1, Unit: "m/s", FieldType: "SPEED_UFIX16_DM", Description: desc,
	}
}

func distanceFix16MField(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 1, HasSign: true, Unit: "m", Description: desc, FieldType: "DISTANCE_FIX16_M",
	}
}

func distanceFix16CmField(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.01, HasSign: true, Unit: "m", Description: desc, FieldType: "DISTANCE_FIX16_CM",
	}
}

func distanceFix16MmField(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.001, HasSign: true, Unit: "m", Description: desc, FieldType: "DISTANCE_FIX16_MM",
	}
}

func distanceFix32MmField(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 4, Resolution: 0.001, HasSign: true, Unit: "m", Description: desc, FieldType: "DISTANCE_FIX32_MM",
	}
}

func distanceFix32CmField(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 4, Resolution: 0.01, HasSign: true, Unit: "m", Description: desc, FieldType: "DISTANCE_FIX32_CM",
	}
}

func distanceFix64Field(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 8, Resolution: 1e-6, HasSign: true, Unit: "m", Description: desc, FieldType: "DISTANCE_FIX64",
	}
}

func lengthUfix8DamField(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8, Resolution: 10, Unit: "m", FieldType: "LENGTH_UFIX8_DAM", Description: desc,
	}
}

func lengthUfix16CmField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 16, Resolution: 0.01, Unit: "m", FieldType: "LENGTH_UFIX16_CM",
	}
}

func lengthUfix16DmField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 16, Resolution: 0.1, Unit: "m", FieldType: "LENGTH_UFIX16_DM",
	}
}

func lengthUfix32MField(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 32, Resolution: 1, Unit: "m", FieldType: "LENGTH_UFIX32_M", Description: desc,
	}
}

func lengthUfix32CmField(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 32, Resolution: 0.01, Unit: "m", FieldType: "LENGTH_UFIX32_CM", Description: desc,
	}
}

func lengthUfix32MmField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 32, Resolution: 0.001, Unit: "m", FieldType: "LENGTH_UFIX32_MM",
	}
}

func currentUfix8AField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 1, Resolution: 1, Unit: "A", FieldType: "CURRENT_UFIX8_A",
	}
}

//nolint:unparam
func currentUfix16AField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 1, Unit: "A", FieldType: "CURRENT_UFIX16_A",
	}
}

func currentUfix16DaField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.1, Unit: "A", FieldType: "CURRENT_UFIX16_DA",
	}
}

func currentFix16DaField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.1, HasSign: true, Unit: "A", FieldType: "CURRENT_FIX16_DA",
	}
}

func currentFix24CaField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 3, Resolution: 0.01, HasSign: true, Unit: "A", FieldType: "CURRENT_FIX24_CA",
	}
}

func electricChargeUfix16Ah(nam string) PGNField {
	return PGNField{
		Name: nam, FieldType: "ELECTRIC_CHARGE_UFIX16_AH",
	}
}

func peukertField(nam string) PGNField {
	return PGNField{
		Name: nam, FieldType: "PEUKERT_EXPONENT",
	}
}

// Fully defined NUMBER fields

//nolint:unparam
func pgnPGNField(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 3, Resolution: 1, FieldType: "PGN", Description: desc,
	}
}

func instanceField() PGNField {
	return PGNField{
		Name: "Instance", Size: 8 * 1, Resolution: 1, FieldType: "UINT8",
	}
}

func powerFactorU16Field() PGNField {
	return PGNField{
		Name: "Power factor", Size: 8 * 2, Resolution: 1 / 16384., Unit: "Cos Phi", FieldType: "UFIX16",
	}
}

func powerFactorU8Field() PGNField {
	return PGNField{
		Name: "Power factor", Size: 8 * 1, Resolution: 0.01, Unit: "Cos Phi", FieldType: "UFIX8",
	}
}

// End of NUMBER fields

func manufacturerField(unt, desc string, prop bool) PGNField {
	return PGNField{
		Name: "Manufacturer Code", Size: 11, Resolution: 1, Description: desc, Unit: unt,
		Lookup: LookupInfo{
			LookupType:          LookupTypePair,
			FunctionPair:        lookupFunctionPairForTyp["MANUFACTURER_CODE"],
			FunctionPairReverse: lookupFunctionPairReverseForTyp["MANUFACTURER_CODE"],
			Name:                "MANUFACTURER_CODE",
		},
		Proprietary: prop,
		FieldType:   "MANUFACTURER",
	}
}

func industryField(unt, desc string, prop bool) PGNField {
	return PGNField{
		Name: "Industry Code", Size: 3, Resolution: 1, Unit: unt, Description: desc,
		Lookup: LookupInfo{
			LookupType:          LookupTypePair,
			FunctionPair:        lookupFunctionPairForTyp["INDUSTRY_CODE"],
			FunctionPairReverse: lookupFunctionPairReverseForTyp["INDUSTRY_CODE"],
			Name:                "INDUSTRY_CODE",
		},
		Proprietary: prop,
		FieldType:   "INDUSTRY",
	}
}

func marineIndustryField() PGNField {
	return industryField("=4", "Marine", false)
}

func company(id string) []PGNField {
	return []PGNField{manufacturerField("="+id, "", false), reservedField(2), marineIndustryField()}
}

func manufacturerFields() []PGNField {
	return []PGNField{manufacturerField("", "", false), reservedField(2), industryField("", "", false)}
}

func manufacturerProprietaryFields1() PGNField {
	return manufacturerField("", "Only in PGN when Commanded PGN is Proprietary", true)
}

func manufacturerProprietaryFields2() PGNField {
	return reservedPropField(2, "Only in PGN when Commanded PGN is Proprietary")
}

func manufacturerProprietaryFields3() PGNField {
	return industryField("", "Only in PGN when Commanded PGN is Proprietary", true)
}

//nolint:unused
func integerDescField(nam string, dataLen uint32, desc string) PGNField {
	return PGNField{
		Name: nam, Size: dataLen, Resolution: 1, Description: desc,
	}
}

//nolint:unused
func integerUnitField(nam string, dataLen uint32, unt string) PGNField {
	return PGNField{
		Name: nam, Size: dataLen, Resolution: 1, Unit: unt,
	}
}

//nolint:unused
func signedIntegerUnitField(nam string, dataLen uint32, unt string) PGNField {
	return PGNField{
		Name: nam, Size: dataLen, Resolution: 1, Unit: unt, HasSign: true,
	}
}

//nolint:unused
func integerField(nam string, dataLen uint32) PGNField {
	return integerDescField(nam, dataLen, "")
}

func uint8DescField(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 1, Resolution: 1, FieldType: "UINT8", Description: desc,
	}
}

//nolint:unparam
func fieldIndex(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 1, Resolution: 1, FieldType: "FIELD_INDEX", Description: desc,
	}
}

func uint8Field(nam string) PGNField {
	return uint8DescField(nam, "")
}

func uint16DescField(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 1, FieldType: "UINT16", Description: desc,
	}
}

func uint16Field(nam string) PGNField {
	return uint16DescField(nam, "")
}

func uint32DescField(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 4, Resolution: 1, FieldType: "UINT32", Description: desc,
	}
}

func uint32Field(nam string) PGNField {
	return uint32DescField(nam, "")
}

//nolint:unparam
func matchLookupField(nam string, dataLen uint32, id, typ string) PGNField {
	return PGNField{
		Name:       nam,
		Size:       dataLen,
		Resolution: 1,
		HasSign:    false,
		Lookup: LookupInfo{
			LookupType:          LookupTypePair,
			FunctionPair:        lookupFunctionPairForTyp[typ],
			FunctionPairReverse: lookupFunctionPairReverseForTyp[typ],
			Name:                typ,
		},
		FieldType: "LOOKUP",
		Unit:      "=" + id,
	}
}

func matchField(nam string, dataLen uint32, id, desc string) PGNField {
	return PGNField{
		Name: nam, Size: dataLen, Resolution: 1, Unit: "=" + id, Description: desc, FieldType: "UNSIGNED_INTEGER",
	}
}

func simpleDescField(nam string, dataLen uint32, desc string) PGNField {
	return PGNField{
		Name: nam, Size: dataLen, Resolution: 1, Description: desc, FieldType: "UNSIGNED_INTEGER",
	}
}

func simpleField(nam string, dataLen uint32) PGNField {
	return PGNField{
		Name: nam, Size: dataLen, Resolution: 1, FieldType: "UNSIGNED_INTEGER",
	}
}

func simpleSignedField(nam string, dataLen uint32) PGNField {
	return PGNField{
		Name: nam, Size: dataLen, Resolution: 1, HasSign: true, FieldType: "INTEGER",
	}
}

func mmsiField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 4, Resolution: 1, HasSign: false, RangeMin: 2000000, RangeMax: 999999999, FieldType: "MMSI",
	}
}

//nolint:unparam
func decimalField(nam string, dataLen uint32, desc string) PGNField {
	return PGNField{
		Name: nam, Size: dataLen, Resolution: 1, Description: desc, FieldType: "DECIMAL",
	}
}

//nolint:unused
func decimalUnitField(nam string, dataLen uint32, unt string) PGNField {
	return PGNField{
		Name: nam, Size: dataLen, Resolution: 1, Unit: unt, FieldType: "DECIMAL",
	}
}

func stringlzField(nam string, dataLen uint32) PGNField {
	return PGNField{
		Name: nam, Size: dataLen, Resolution: 0, FieldType: "STRING_LZ",
	}
}

func stringFixDescField(nam string, dataLen uint32, desc string) PGNField {
	return PGNField{
		Name: nam, Size: dataLen, Resolution: 0, Description: desc, FieldType: "STRING_FIX",
	}
}

//nolint:unused
func stringvarField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: lenVariable, Resolution: 0, FieldType: "STRING_LZ",
	}
}

func stringlauField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: lenVariable, Resolution: 0, FieldType: "STRING_LAU",
	}
}

func stringFixField(nam string, dataLen uint32) PGNField {
	return stringFixDescField(nam, dataLen, "")
}

func temperatureHighField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.1, Unit: "K", FieldType: "TEMPERATURE_HIGH",
	}
}

func temperatureField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.01, Unit: "K", FieldType: "TEMPERATURE",
	}
}

//nolint:unused
func temperatureUint8OffsetField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 1, Offset: 233, Resolution: 1, Unit: "K", FieldType: "TEMPERATURE_UINT8_OFFSET",
	}
}

func temperatureU24Field(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 3, Resolution: 0.001, Unit: "K", FieldType: "TEMPERATURE_UFIX24",
	}
}

func temperatureDeltaFix16Field(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.001, Unit: "K", HasSign: true, FieldType: "FIX16", Description: desc,
	}
}

func volumetricFlowField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.1, Unit: "L/h", HasSign: true, FieldType: "VOLUMETRIC_FLOW",
	}
}

func concentrationUint16Field(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 1, Unit: "ppm", FieldType: "CONCENTRATION_UINT16_PPM",
	}
}

func volumeUfix16LField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 1, Unit: "L", FieldType: "VOLUME_UFIX16_L",
	}
}

func volumeUfix32DlField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 4, Resolution: 0.1, Unit: "L", FieldType: "VOLUME_UFIX32_DL",
	}
}

func timeUfix16SField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 1, Unit: "s", FieldType: "TIME_UFIX16_S",
	}
}

func timeFix32MsField(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 4, Resolution: 0.001, Unit: "s", HasSign: true, FieldType: "TIME_FIX32_MS", Description: desc,
	}
}

func timeUfix85msField(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 1, Resolution: 0.005, Unit: "s", HasSign: false, FieldType: "TIME_UFIX8_5MS", Description: desc,
	}
}

func timeUfix16MinField(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 60, Unit: "s", HasSign: false, FieldType: "TIME_UFIX16_MIN", Description: desc,
	}
}

func timeUfix16MsField(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.001, Unit: "s", HasSign: false, FieldType: "TIME_UFIX16_MS", Description: desc,
	}
}

func timeUfix16CsField(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.01, Unit: "s", HasSign: false, FieldType: "TIME_UFIX16_CS", Description: desc,
	}
}

func timeFix165csField(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.05, Unit: "s", HasSign: true, FieldType: "TIME_FIX16_5CS", Description: desc,
	}
}

func timeFix16MinField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 60., Unit: "s", HasSign: true, FieldType: "TIME_FIX16_MIN",
	}
}

func timeUfix24MsField(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 3, Resolution: 0.001, Unit: "s", HasSign: false, FieldType: "TIME_UFIX24_MS", Description: desc,
	}
}

//nolint:unparam
func timeUfix32SField(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 4, Resolution: 1, Unit: "s", HasSign: false, FieldType: "TIME_UFIX32_S", Description: desc,
	}
}

//nolint:unparam
func timeUfix32MsField(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 4, Resolution: 0.001, Unit: "s", HasSign: false, FieldType: "TIME_UFIX32_MS", Description: desc,
	}
}

func timeField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 4, Resolution: 0.0001, Unit: "s", HasSign: false, FieldType: "TIME",
		Description: "Seconds since midnight", RangeMin: 0, RangeMax: 86402,
	}
}

func dateField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 1, Unit: "d", HasSign: false, FieldType: "DATE",
	}
}

func variableField(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: lenVariable, Description: desc, FieldType: "VARIABLE",
	}
}

func keyValueField(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: lenVariable, Description: desc, FieldType: "KEY_VALUE",
	}
}

func energyUint32Field(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 4, Resolution: 1, Unit: "kWh", FieldType: "ENERGY_UINT32",
	}
}

//nolint:unparam
func powerI32OffsetField(nam string) PGNField {
	return PGNField{
		Name: nam, HasSign: true, FieldType: "POWER_FIX32_OFFSET",
	}
}

//nolint:unparam
func powerI32VaOffsetField(nam string) PGNField {
	return PGNField{
		Name: nam, HasSign: true, FieldType: "POWER_FIX32_VA_OFFSET",
	}
}

func powerI32VarOffsetField(nam string) PGNField {
	return PGNField{
		Name: nam, HasSign: true, FieldType: "POWER_FIX32_VAR_OFFSET",
	}
}

func powerU16Field(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 1, Unit: "W", FieldType: "POWER_UINT16",
	}
}

func powerU16VarField(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 1, Unit: "VAR", Description: desc, FieldType: "POWER_UINT16_VAR",
	}
}

func powerI32Field(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 4, Resolution: 1, HasSign: true, Unit: "W", FieldType: "POWER_INT32",
	}
}

func powerU32Field(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 4, Resolution: 1, Unit: "W", FieldType: "POWER_UINT32",
	}
}

//nolint:unused
func powerU32VaField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 4, Resolution: 1, Unit: "VA", FieldType: "POWER_UINT32_VA",
	}
}

func powerU32VarField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 4, Resolution: 1, Unit: "VAR", FieldType: "POWER_UINT32_VAR",
	}
}

func percentageU8Field(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 1, Resolution: 1, Unit: "%", FieldType: "PERCENTAGE_UINT8",
	}
}

//nolint:unused
func percentageU8HighresField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 1, Resolution: .4, Unit: "%", FieldType: "PERCENTAGE_UINT8_HIGHRES",
	}
}

func percentageI8Field(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 1, Resolution: 1, HasSign: true, Unit: "%", FieldType: "PERCENTAGE_INT8",
	}
}

func percentageI16Field(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: resPercentage, HasSign: true, Unit: "%", FieldType: "PERCENTAGE_FIX16",
	}
}

func rotationFix16Field(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: (1e-3 / 32.0), HasSign: true, Unit: "rad/s", FieldType: "ROTATION_FIX16",
	}
}

func rotationUfix16RPMField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.25, HasSign: false, Unit: "rpm", FieldType: "ROTATION_UFIX16_RPM",
	}
}

//nolint:unused
func rotationUfix16RpmHighresField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.125, HasSign: false, Unit: "rpm", FieldType: "ROTATION_UFIX16_RPM_HIGHRES",
	}
}

func rotationFix32Field(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 4, Resolution: (1e-6 / 32.0), HasSign: true, Unit: "rad/s", FieldType: "ROTATION_FIX32",
	}
}

func pressureUfix16HPAField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 100, Unit: "Pa", FieldType: "PRESSURE_UFIX16_HPA",
	}
}

//nolint:unused
func pressureUint8KpaField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 1, Resolution: 500, Unit: "Pa", FieldType: "PRESSURE_UINT8_KPA",
	}
}

//nolint:unused
func pressureUint82kpaField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 1, Resolution: 2000, Unit: "Pa", FieldType: "PRESSURE_UINT8_2KPA",
	}
}

func pressureUfix16KpaField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 1000, HasSign: false, Unit: "Pa", FieldType: "PRESSURE_UFIX16_KPA",
	}
}

func pressureRateFix16PaField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 1, HasSign: true, Unit: "Pa/hr", FieldType: "PRESSURE_RATE_FIX16_PA",
	}
}

func pressureFix16KpaField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 1000, HasSign: true, Unit: "Pa", FieldType: "PRESSURE_FIX16_KPA",
	}
}

func pressureFix32DpaField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 4, Resolution: 0.1, HasSign: true, Unit: "Pa", FieldType: "PRESSURE_FIX32_DPA",
	}
}

func pressureUfix32DpaField(nam string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 4, Resolution: 0.1, HasSign: false, Unit: "Pa", FieldType: "PRESSURE_UFIX32_DPA",
	}
}

func gainField(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.01, HasSign: true, FieldType: "GAIN_FIX16", Description: desc,
	}
}

func magneticFix16Field(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.01, HasSign: true, Unit: "T", FieldType: "MAGNETIC_FIELD_FIX16",
		Description: desc,
	}
}

func angleFix16DdegField(nam, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 2, Resolution: 0.1, HasSign: true, Unit: "deg", FieldType: "ANGLE_FIX16_DDEG",
		Description: desc,
	}
}

func floatField(nam, unt, desc string) PGNField {
	return PGNField{
		Name: nam, Size: 8 * 4, HasSign: true, Unit: unt, FieldType: "FLOAT", Description: desc,
		Resolution: 1, RangeMin: -1 * math.MaxFloat32, RangeMax: math.MaxFloat32,
	}
}

var (
	immutPGNs []PGNInfo
	pgnMap    map[uint32]PGNInfo
)

func initPGNs() {
	immutPGNs = createPGNList()
	pgnMap = map[uint32]PGNInfo{}
	for _, pgn := range immutPGNs {
		pgnMap[pgn.PGN] = pgn
	}
}

type pgnRange struct {
	PGNStart   uint32
	PGNEnd     uint32
	PGNStep    uint32
	Who        string
	PacketType PacketType
}

var pgnRanges = []pgnRange{
	{0xe800, 0xee00, 256, "ISO 11783", PacketTypeSingle},
	{0xef00, 0xef00, 256, "NMEA", PacketTypeSingle},
	{0xf000, 0xfeff, 1, "NMEA", PacketTypeSingle},
	{0xff00, 0xffff, 1, "Manufacturer", PacketTypeSingle},
	{0x1ed00, 0x1ee00, 256, "NMEA", PacketTypeFast},
	{0x1ef00, 0x1ef00, 256, "Manufacturer", PacketTypeFast},
	{0x1f000, 0x1feff, 1, "NMEA", PacketTypeMixed},
	{0x1ff00, 0x1ffff, 1, "Manufacturer", PacketTypeFast},
}

func checkPGNs() error {
	var i int
	prevPRN := uint32(0)

	for i = 0; i < len(immutPGNs); i++ {
		pgnRangeIndex := 0
		prn := immutPGNs[i].PGN
		var pgn *PGNInfo

		if prn < prevPRN {
			return fmt.Errorf("Internal error: PGN %d is not sorted correctly", prn)
		}

		if prn < common.ActisenseBEM {
			for prn > pgnRanges[pgnRangeIndex].PGNEnd && pgnRangeIndex < len(pgnRanges) {
				pgnRangeIndex++
			}
			if prn < pgnRanges[pgnRangeIndex].PGNStart || prn > pgnRanges[pgnRangeIndex].PGNEnd {
				return fmt.Errorf("Internal error: PGN %d is not part of a valid PRN range", prn)
			}
			if pgnRanges[pgnRangeIndex].PGNStep == 256 && (prn&0xff) != 0 {
				return fmt.Errorf("Internal error: PGN %d (0x%x) is PDU1 and must have a PGN ending in 0x00", prn, prn)
			}
			if !(pgnRanges[pgnRangeIndex].PacketType == immutPGNs[i].PacketType ||
				pgnRanges[pgnRangeIndex].PacketType == PacketTypeMixed ||
				immutPGNs[i].PacketType == PacketTypeISOTP) {
				return fmt.Errorf("Internal error: PGN %d (0x%x) is in range 0x%x-0x%x and must have packet type %s",
					prn,
					prn,
					pgnRanges[pgnRangeIndex].PGNStart,
					pgnRanges[pgnRangeIndex].PGNEnd,
					pgnRanges[pgnRangeIndex].PacketType)
			}
		}

		if prn == prevPRN || immutPGNs[i].Fallback {
			continue
		}
		prevPRN = prn
		pgn, _ = SearchForPgn(prevPRN)
		if pgn != &immutPGNs[i] {
			return fmt.Errorf("Internal error: PGN %d is not found correctly", prevPRN)
		}
	}

	return nil
}

/**
 * Return the first Pgn entry for which the pgn is found.
 * There can be multiple (with differing 'match' fields).
 */
func SearchForPgn(pgn uint32) (*PGNInfo, int) {
	start := 0
	end := len(immutPGNs)
	var mid int

	for start <= end {
		mid = (start + end) / 2
		if pgn == immutPGNs[mid].PGN {
			// Return the first one, unless it is the catch-all
			for mid > 0 && pgn == immutPGNs[mid-1].PGN {
				mid--
			}
			if immutPGNs[mid].Fallback {
				mid++
				if pgn != immutPGNs[mid].PGN {
					return nil, -1
				}
			}
			return &immutPGNs[mid], mid
		}
		if pgn < immutPGNs[mid].PGN {
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
func SearchForUnknownPgn(pgnID uint32, logger logging.Logger) (*PGNInfo, error) {
	var fallback *PGNInfo

	for _, pgn := range immutPGNs {
		if pgn.Fallback {
			pgnCopy := pgn
			fallback = &pgnCopy
		}
		if pgn.PGN >= pgnID {
			break
		}
	}
	if fallback == nil {
		return nil, fmt.Errorf("Cannot find catch-all PGN definition for PGN %d; internal definition error", pgnID)
	}
	logger.Debugf("Found catch-all PGN %d for PGN %d", fallback.PGN, pgnID)
	return fallback, nil
}

func GetField(pgnID, field uint32, logger logging.Logger) *PGNField {
	pgn, _ := SearchForPgn(pgnID)

	if pgn == nil {
		logger.Debugf("PGN %d is unknown", pgnID)
		return nil
	}
	if field < pgn.FieldCount {
		return &pgn.FieldList[field]
	}
	logger.Debugf("PGN %d does not have field %d", pgnID, field)
	return nil
}

/*
 * Return the best match for this pgnId.
 * If all else fails, return an 'Fallback' match-all PGN that
 * matches the fast/single frame, PDU1/PDU2 and Proprietary/generic range.
 */
func GetMatchingPgn(pgnID uint32, data []byte, logger logging.Logger) (*PGNInfo, error) {
	pgn, pgnIdx := SearchForPgn(pgnID)

	if pgn == nil {
		var err error
		pgn, err = SearchForUnknownPgn(pgnID, logger)
		if err != nil {
			return nil, err
		}
		FallbackPGN := 0
		if pgn != nil {
			FallbackPGN = int(pgn.PGN)
		}
		logger.Debugf("GetMatchingPgn: Unknown PGN %d . Fallback %d", pgnID, FallbackPGN)
		return pgn, nil
	}

	if !pgn.HasMatchFields {
		logger.Debugf("GetMatchingPgn: PGN %d has no match fields, returning '%s'", pgnID, pgn.Description)
		return pgn, nil
	}

	// Here if we have a PGN but it must be matched to the list of match fields.
	// This might end up without a solution, in that case return the catch-all Fallback PGN.

	for prn := pgn.PGN; pgn.PGN == prn; {
		matchedFixedField := true
		hasFixedField := false

		logger.Debugf("GetMatchingPgn: PGN %d matching with manufacturer specific '%s'", prn, pgn.Description)

		// Iterate over fields
		startBit := uint32(0)
		for i := uint32(0); i < pgn.FieldCount; i++ {
			field := &pgn.FieldList[i]
			bits := field.Size

			if field.Unit != "" && field.Unit[0] == '=' {
				var value int64
				var maxValue int64

				hasFixedField = true
				//nolint:errcheck
				desiredValue, _ := strconv.ParseInt(field.Unit[1:], 10, 64)
				fieldSize := int(field.Size)
				if !ExtractNumber(field, data, int(startBit), fieldSize, &value, &maxValue, logger) || value != desiredValue {
					logger.Debugf("GetMatchingPgn: PGN %d field '%s' value %d does not match %d",
						prn,
						field.Name,
						value,
						desiredValue)
					matchedFixedField = false
					break
				}
				logger.Debugf(
					"GetMatchingPgn: PGN %d field '%s' value %d matches %d", prn, field.Name, value, desiredValue)
			}
			startBit += bits
		}
		if !hasFixedField {
			logger.Debugf("GetMatchingPgn: Cant determine prn choice, return prn=%d variation '%s'", prn, pgn.Description)
			return pgn, nil
		}
		if matchedFixedField {
			logger.Debugf("GetMatchingPgn: PGN %d selected manufacturer specific '%s'", prn, pgn.Description)
			return pgn, nil
		}

		pgnIdx++
		pgn = &immutPGNs[pgnIdx]
	}

	return SearchForUnknownPgn(pgnID, logger)
}

func varLenFieldListToFixed(list []PGNField) [33]PGNField {
	var out [33]PGNField
	if len(list) > len(out) {
		panic("input list too large")
	}
	copy(out[:], list)
	return out
}

/*
 * Return the best match for this pgnId.
 * If all else fails, return an 'Fallback' match-all PGN that
 * matches the fast/single frame, PDU1/PDU2 and Proprietary/generic range.
 */
func GetMatchingPgnWithFields(pgnID uint32, fields map[string]interface{}, logger logging.Logger) (*PGNInfo, error) {
	pgn, pgnIdx := SearchForPgn(pgnID)

	if pgn == nil {
		var err error
		pgn, err = SearchForUnknownPgn(pgnID, logger)
		if err != nil {
			return nil, err
		}
		FallbackPGN := 0
		if pgn != nil {
			FallbackPGN = int(pgn.PGN)
		}
		logger.Debugf("GetMatchingPgnWithFields: Unknown PGN %d . Fallback %d", pgnID, FallbackPGN)
		return pgn, nil
	}

	if !pgn.HasMatchFields {
		logger.Debugf("GetMatchingPgnWithFields: PGN %d has no match fields, returning '%s'", pgnID, pgn.Description)
		return pgn, nil
	}

	// Here if we have a PGN but it must be matched to the list of match fields.
	// This might end up without a solution, in that case return the catch-all Fallback PGN.

	for prn := pgn.PGN; pgn.PGN == prn; {
		matchedFixedField := true
		hasFixedField := false

		logger.Debugf("GetMatchingPgnWithFields: PGN %d matching with manufacturer specific '%s'", prn, pgn.Description)

		// Iterate over fields
		for i := uint32(0); i < pgn.FieldCount; i++ {
			field := &pgn.FieldList[i]

			if field.Unit != "" && field.Unit[0] == '=' {
				value, hasFieldValue := fields[field.Name]
				valueStr, isValueStr := value.(string)

				hasFixedField = true
				//nolint:errcheck
				desiredValue, _ := strconv.ParseInt(field.Unit[1:], 10, 64)

				if !isValueStr || !hasFieldValue ||
					field.Lookup.FunctionPairReverse == nil ||
					field.Lookup.FunctionPairReverse(valueStr) != int(desiredValue) {
					logger.Debugf("GetMatchingPgnWithFields: PGN %d field '%s' value %d does not match %d",
						prn,
						field.Name,
						value,
						desiredValue)
					matchedFixedField = false
					break
				}
				logger.Debugf(
					"GetMatchingPgnWithFields: PGN %d field '%s' value %d matches %d", prn, field.Name, value, desiredValue)
			}
		}
		if !hasFixedField {
			logger.Debugf("GetMatchingPgnWithFields: Cant determine prn choice, return prn=%d variation '%s'", prn, pgn.Description)
			return pgn, nil
		}
		if matchedFixedField {
			logger.Debugf("GetMatchingPgnWithFields: PGN %d selected manufacturer specific '%s'", prn, pgn.Description)
			return pgn, nil
		}

		pgnIdx++
		pgn = &immutPGNs[pgnIdx]
	}

	return SearchForUnknownPgn(pgnID, logger)
}
