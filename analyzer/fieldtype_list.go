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

import "math"

var (
	trueValue  = true
	falseValue = false
)

var immutFieldTypes []FieldType

//nolint:lll
func initFieldTypes() {
	// Numeric types
	immutFieldTypes = []FieldType{
		{
			Name:        "NUMBER",
			Description: "Number",
			EncodingDescription: "Binary numbers are little endian. Number fields that use two or three bits use one special encoding, for the maximum " +
				"value.  When present, this means that the field is not present. Number fields that use four bits or more use two special " +
				"encodings. The maximum positive value means that the field is not present. The maximum positive value minus 1 means that " +
				"the field has an error. For instance, a broken sensor. For signed numbers the maximum values are the maximum positive " +
				"value and that minus 1, not the all-ones bit encoding which is the maximum negative value.",
			URL:    "https://en.wikipedia.org/wiki/Binary_number",
			V1Type: "Number",
			CF:     convertFieldNumber,
			PF:     Printer.PrintFieldNumber,
		},

		{
			Name:          "INTEGER",
			Description:   "Signed integral number",
			HasSign:       &trueValue,
			BaseFieldType: "NUMBER",
			URL:           "https://en.wikipedia.org/wiki/Integer_%28computer_science%29",
			V1Type:        "Integer",
		},

		{
			Name:          "UNSIGNED_INTEGER",
			Description:   "Unsigned integral number",
			HasSign:       &falseValue,
			BaseFieldType: "NUMBER",
			URL:           "https://en.wikipedia.org/wiki/Integer_%28computer_science%29",
			V1Type:        "Integer",
		},

		{Name: "INT8", Description: "8 bit signed integer", Size: 8, HasSign: &trueValue, BaseFieldType: "INTEGER"},

		{Name: "UINT8", Description: "8 bit unsigned integer", Size: 8, HasSign: &falseValue, BaseFieldType: "UNSIGNED_INTEGER"},

		{Name: "INT16", Description: "16 bit signed integer", Size: 16, HasSign: &trueValue, BaseFieldType: "INTEGER"},

		{Name: "UINT16", Description: "16 bit unsigned integer", Size: 16, HasSign: &falseValue, BaseFieldType: "UNSIGNED_INTEGER"},

		{Name: "UINT24", Description: "24 bit unsigned integer", Size: 24, HasSign: &falseValue, BaseFieldType: "UNSIGNED_INTEGER"},

		{Name: "INT32", Description: "32 bit signed integer", Size: 32, HasSign: &trueValue, BaseFieldType: "INTEGER"},

		{Name: "UINT32", Description: "32 bit unsigned integer", Size: 32, HasSign: &falseValue, BaseFieldType: "UNSIGNED_INTEGER"},

		{Name: "INT64", Description: "64 bit signed integer", Size: 64, HasSign: &trueValue, BaseFieldType: "INTEGER"},

		{Name: "UINT64", Description: "64 bit unsigned integer", Size: 64, HasSign: &falseValue, BaseFieldType: "UNSIGNED_INTEGER"},

		{
			Name:        "UNSIGNED_FIXED_POINT_NUMBER",
			Description: "An unsigned numeric value where the Least Significant Bit does not encode the integer value 1",
			EncodingDescription: "The `Resolution` attribute indicates what the raw value 1 should represent. The `Signed` and `BitLength` attributes are " +
				"always present. Together, this gives sufficient information to represent a fixed point number in a particular range where " +
				"non-integral values can be encoded without requiring four or eight bytes for a floating point number.",
			HasSign:       &falseValue,
			URL:           "https://en.wikipedia.org/wiki/Fixed-point_arithmetic",
			BaseFieldType: "NUMBER",
		},

		{
			Name:        "SIGNED_FIXED_POINT_NUMBER",
			Description: "A signed numeric value where the Least Significant Bit does not encode the integer value 1",
			EncodingDescription: "The `Resolution` attribute indicates what the raw value 1 should represent. The `Signed` and `BitLength` attributes are " +
				"always present. Together, this gives sufficient information to represent a fixed point number in a particular range where " +
				"non-integral values can be encoded without requiring four or eight bytes for a floating point number.",
			HasSign:       &trueValue,
			URL:           "https://en.wikipedia.org/wiki/Fixed-point_arithmetic",
			BaseFieldType: "NUMBER",
		},

		{Name: "FIX8", Description: "8 bit signed fixed point number", Size: 8, BaseFieldType: "SIGNED_FIXED_POINT_NUMBER"},

		{
			Name:          "UFIX8",
			Description:   "8 bit unsigned fixed point number",
			Size:          8,
			BaseFieldType: "UNSIGNED_FIXED_POINT_NUMBER",
		},

		{Name: "FIX16", Description: "16 bit signed fixed point number", Size: 16, BaseFieldType: "SIGNED_FIXED_POINT_NUMBER"},

		{
			Name:          "UFIX16",
			Description:   "16 bit unsigned fixed point number",
			Size:          16,
			BaseFieldType: "UNSIGNED_FIXED_POINT_NUMBER",
		},

		{Name: "FIX24", Description: "24 bit signed fixed point number", Size: 24, BaseFieldType: "SIGNED_FIXED_POINT_NUMBER"},

		{
			Name:          "UFIX24",
			Description:   "24 bit unsigned fixed point number",
			Size:          24,
			BaseFieldType: "UNSIGNED_FIXED_POINT_NUMBER",
		},

		{Name: "FIX32", Description: "32 bit signed fixed point number", Size: 32, BaseFieldType: "SIGNED_FIXED_POINT_NUMBER"},

		{
			Name:          "UFIX32",
			Description:   "32 bit unsigned fixed point number",
			Size:          32,
			BaseFieldType: "UNSIGNED_FIXED_POINT_NUMBER",
		},

		{Name: "FIX64", Description: "64 bit signed fixed point number", Size: 64, BaseFieldType: "SIGNED_FIXED_POINT_NUMBER"},

		{
			Name:          "UFIX64",
			Description:   "64 bit unsigned fixed point number",
			Size:          64,
			BaseFieldType: "UNSIGNED_FIXED_POINT_NUMBER",
		},

		{
			Name:        "FLOAT",
			Description: "32 bit IEEE-754 floating point number",
			Size:        32,
			HasSign:     &trueValue,
			URL:         "https://en.wikipedia.org/wiki/IEEE_754",
			CF:          convertFieldFloat,
			PF:          Printer.PrintFieldFloat,
		},

		{
			Name:        "DECIMAL",
			Description: "A unsigned numeric value represented with 2 decimal digits per byte",
			EncodingDescription: "Each byte represent 2 digits, so 1234 is represented by 2 bytes containing 0x12 and 0x34. A number " +
				"with an odd number of digits will have 0 as the first digit in the first byte.",
			HasSign: &falseValue,
			URL:     "https://en.wikipedia.org/wiki/Binary-coded_decimal",
			CF:      convertFieldDecimal,
			PF:      Printer.PrintFieldDecimal,
		},

		{
			Name:                "LOOKUP",
			Description:         "Number value where each value encodes for a distinct meaning",
			EncodingDescription: "Each lookup has a LookupEnumeration defining what the possible values mean",
			Comment: "For almost all lookups the list of values is known with some precision, but it is quite possible that a value " +
				"occurs that has no corresponding textual explanation.",
			HasSign: &falseValue,
			CF:      convertFieldLookup,
			PF:      Printer.PrintFieldLookup,
			V1Type:  "Lookup table",
		},

		{
			Name:                "INDIRECT_LOOKUP",
			Description:         "Number value where each value encodes for a distinct meaning but the meaning also depends on the value in another field",
			EncodingDescription: "Each lookup has a LookupIndirectEnumeration defining what the possible values mean",
			Comment: "For almost all lookups the list of values is known with some precision, but it is quite possible that a value " +
				"occurs that has no corresponding textual explanation.",
			HasSign: &falseValue,
			CF:      convertFieldLookup,
			PF:      Printer.PrintFieldLookup,
			V1Type:  "Integer",
		},

		{
			Name:        "BITLOOKUP",
			Description: "Number value where each bit value encodes for a distinct meaning",
			EncodingDescription: "Each LookupBit has a LookupBitEnumeration defining what the possible values mean. A bitfield can have " +
				"any combination of bits set.",
			Comment: "For almost all lookups the list of values is known with some precision, but it is quite possible that a value " +
				"occurs that has no corresponding textual explanation.",
			CF:     convertFieldBitLookup,
			PF:     Printer.PrintFieldBitLookup,
			V1Type: "Bitfield",
		},

		{
			Name:                "FieldType_LOOKUP",
			Description:         "Number value where each value encodes for a distinct meaning including a FieldType of the next variable field",
			EncodingDescription: "Each lookup has a LookupFieldTypeEnumeration defining what the possible values mean",
			Comment: "These values have been determined by reverse engineering, given the known values it is anticipated that there are " +
				"unknown enumeration values and some known values have incorrect datatypes",
			HasSign: &falseValue,
			CF:      convertFieldLookup,
			PF:      Printer.PrintFieldLookup,
		},

		{
			Name:          "MANUFACTURER",
			Description:   "Manufacturer",
			Size:          11,
			CF:            convertFieldLookup,
			PF:            Printer.PrintFieldLookup,
			BaseFieldType: "LOOKUP",
			V1Type:        "Manufacturer code",
		},

		{
			Name:          "INDUSTRY",
			Description:   "Industry",
			Size:          3,
			CF:            convertFieldLookup,
			PF:            Printer.PrintFieldLookup,
			BaseFieldType: "LOOKUP",
		},

		{Name: "VERSION", Description: "Version", Resolution: 0.001, BaseFieldType: "UFIX16"},

		// Specific typed numeric fields

		{Name: "FIX16_1", Description: "Fixed point signed with 1 digit Resolution", Resolution: 0.1, BaseFieldType: "FIX16"},

		{Name: "FIX32_2", Description: "Fixed point signed with 2 digits Resolution", Resolution: 0.01, BaseFieldType: "FIX32"},

		{
			Name:          "UFIX32_2",
			Description:   "Fixed point unsigned with 2 digits Resolution",
			Resolution:    0.001,
			BaseFieldType: "UFIX32",
		},

		{
			Name:          "UFIX16_3",
			Description:   "Fixed point unsigned with 3 digits Resolution",
			Resolution:    0.001,
			BaseFieldType: "UFIX16",
		},

		{
			Name:          "DILUTION_OF_PRECISION_FIX16",
			Description:   "Dilution of precision",
			URL:           "https://en.wikipedia.org/wiki/Dilution_of_precision_(navigation)",
			Resolution:    0.01,
			BaseFieldType: "FIX16",
		},

		{
			Name:          "DILUTION_OF_PRECISION_UFIX16",
			Description:   "Dilution of precision",
			URL:           "https://en.wikipedia.org/wiki/Dilution_of_precision_(navigation)",
			Resolution:    0.01,
			BaseFieldType: "UFIX16",
		},

		{
			Name:          "SIGNALTONOISERATIO_FIX16",
			Description:   "Signal-to-noise ratio",
			URL:           "https://en.wikipedia.org/wiki/Signal-to-noise_ratio",
			Resolution:    0.01,
			Physical:      &signalToNoiseRatioQuantity,
			BaseFieldType: "FIX16",
		},

		{
			Name:          "SIGNALTONOISERATIO_UFIX16",
			Description:   "Signal-to-noise ratio",
			URL:           "https://en.wikipedia.org/wiki/Signal-to-noise_ratio",
			Resolution:    0.01,
			Physical:      &signalToNoiseRatioQuantity,
			BaseFieldType: "UFIX16",
		},

		{Name: "ANGLE_FIX16", Description: "Angle", Resolution: 0.0001, Physical: &angleQuantity, BaseFieldType: "FIX16"},

		{
			Name:          "ANGLE_FIX16_DDEG",
			Description:   "Angle",
			Resolution:    0.1,
			Unit:          "deg",
			Physical:      &angleQuantity,
			BaseFieldType: "FIX16",
		},

		{Name: "ANGLE_UFIX16", Description: "Angle", Resolution: 0.0001, Physical: &angleQuantity, BaseFieldType: "UFIX16"},

		{
			Name:        "GEO_FIX32",
			Description: "Geographical latitude or longitude",
			EncodingDescription: "The `Resolution` for this field is 1.0e-7, so the Resolution is 1/10 millionth of a degree, or about 1 " +
				"cm when we refer to an Earth position",
			Resolution:    1.0e-7,
			Physical:      &geoCoordinateQuantity,
			CF:            convertFieldLatLon,
			PF:            Printer.PrintFieldLatLon,
			BaseFieldType: "FIX32",
			V1Type:        "Lat/Lon",
		},

		{
			Name:        "GEO_FIX64",
			Description: "Geographical latitude or longitude, high Resolution",
			EncodingDescription: "The `Resolution` for this field is 1.0e-16, so the Resolution is about 0.01 nm (nanometer) when we " +
				"refer to an Earth position",
			Resolution:    1.0e-16,
			Physical:      &geoCoordinateQuantity,
			CF:            convertFieldLatLon,
			PF:            Printer.PrintFieldLatLon,
			BaseFieldType: "FIX64",
			V1Type:        "Lat/Lon",
		},

		{
			Name:          "LENGTH_UFIX8_DAM",
			Description:   "Length, in decameter Resolution",
			Resolution:    10,
			Physical:      &lengthQuantity,
			BaseFieldType: "UFIX8",
		},

		{
			Name:          "LENGTH_UFIX16_DM",
			Description:   "Length, in decimeter Resolution",
			Resolution:    0.1,
			Physical:      &lengthQuantity,
			BaseFieldType: "UFIX16",
		},

		{
			Name:          "LENGTH_UFIX32_CM",
			Description:   "Length, in centimeter Resolution",
			Resolution:    0.01,
			Physical:      &lengthQuantity,
			BaseFieldType: "UFIX32",
		},

		{
			Name:          "LENGTH_UFIX32_M",
			Description:   "Length, in meter Resolution",
			Resolution:    1,
			Physical:      &lengthQuantity,
			BaseFieldType: "UFIX32",
		},

		{
			Name:          "LENGTH_UFIX32_CM",
			Description:   "Length, in centimeter Resolution",
			Resolution:    0.01,
			Physical:      &lengthQuantity,
			BaseFieldType: "UFIX32",
		},

		{
			Name:          "LENGTH_UFIX32_MM",
			Description:   "Length, in millimeter Resolution",
			Resolution:    0.001,
			Physical:      &lengthQuantity,
			BaseFieldType: "UFIX32",
		},

		{
			Name:          "LENGTH_UFIX8_DAM",
			Description:   "Length, byte, unsigned decameters",
			Resolution:    10.,
			Physical:      &lengthQuantity,
			BaseFieldType: "UFIX8",
		},

		{
			Name:          "LENGTH_UFIX16_CM",
			Description:   "Length, unsigned centimeters",
			Resolution:    0.01,
			Physical:      &lengthQuantity,
			BaseFieldType: "UFIX16",
		},

		{
			Name:          "LENGTH_UFIX16_DM",
			Description:   "Length, unsigned decimeters",
			Resolution:    0.1,
			Physical:      &lengthQuantity,
			BaseFieldType: "UFIX16",
		},

		{
			Name:          "LENGTH_UFIX32_MM",
			Description:   "Length, high range, unsigned millimeters",
			Resolution:    0.001,
			Physical:      &lengthQuantity,
			BaseFieldType: "UFIX32",
		},

		{
			Name:          "LENGTH_UFIX32_CM",
			Description:   "Length, high range, unsigned centimeters",
			Resolution:    0.01,
			Physical:      &lengthQuantity,
			BaseFieldType: "UFIX32",
		},

		{
			Name:          "LENGTH_UFIX32_M",
			Description:   "Length, high range, meters",
			Resolution:    1.,
			Physical:      &lengthQuantity,
			BaseFieldType: "UFIX32",
		},

		{
			Name:          "TEMPERATURE",
			Description:   "Temperature",
			Resolution:    0.01,
			Physical:      &temperatureQuantity,
			BaseFieldType: "UFIX16",
			V1Type:        "Temperature",
		},

		{
			Name:          "TEMPERATURE_UINT8_OFFSET", /* used by PGN 65262 & 65270 */
			Description:   "Temperature",
			Offset:        233, /* offset to degrees Kelvin */
			Resolution:    1,
			Physical:      &temperatureQuantity,
			BaseFieldType: "UINT8",
			V1Type:        "Temperature",
		},

		{
			Name:                "TEMPERATURE_HIGH",
			Description:         "Temperature, high range",
			EncodingDescription: "This has a higher range but lower Resolution than TEMPERATURE",
			Resolution:          0.1,
			Physical:            &temperatureQuantity,
			BaseFieldType:       "UFIX16",
			V1Type:              "Temperature",
		},

		{
			Name:                "TEMPERATURE_UFIX24",
			Description:         "Temperature, high Resolution",
			EncodingDescription: "This has a higher range and higher Resolution than TEMPERATURE (but uses three bytes)",
			Resolution:          0.001,
			Physical:            &temperatureQuantity,
			BaseFieldType:       "UFIX24",
			V1Type:              "Temperature",
		},

		{
			Name:          "TEMPERATURE_DELTA_FIX16",
			Description:   "Temperature difference",
			Resolution:    0.001,
			Physical:      &temperatureQuantity,
			BaseFieldType: "FIX16",
		},

		{
			Name:          "VOLUMETRIC_FLOW",
			Description:   "Volumetric flow",
			Resolution:    0.1,
			Physical:      &volumetricFlowQuantity,
			BaseFieldType: "FIX16",
		},

		{
			Name:                "CONCENTRATION_UINT16_PPM",
			Description:         "Concentration of one substance in another, in this context usually the amount of salts in water",
			EncodingDescription: "Expressed in parts per million",
			Resolution:          1,
			Physical:            &concentrationQuantity,
			BaseFieldType:       "UINT16",
		},

		{Name: "VOLUME_UFIX16_L", Description: "Volume", Resolution: 1, Physical: &volumeQuantity, BaseFieldType: "UFIX16"},

		{Name: "VOLUME_UFIX32_DL", Description: "Volume", Resolution: 0.1, Physical: &volumeQuantity, BaseFieldType: "UFIX32"},

		{
			Name:        "TIME",
			Description: "Time",
			Physical:    &timeQuantity,
			CF:          convertFieldTime,
			PF:          Printer.PrintFieldTime,
			V1Type:      "Time",
		},

		{
			Name:                "TIME_UFIX32",
			Description:         "Time",
			EncodingDescription: "When indicating a wall clock time, this is the amount of time passed since midnight",
			Size:                32,
			HasSign:             &falseValue,
			Resolution:          0.0001,
			BaseFieldType:       "TIME",
		},

		{
			Name:          "TIME_UFIX16_S",
			Description:   "Time delta, 16 bits with 1 second Resolution",
			Resolution:    1,
			Size:          16,
			HasSign:       &falseValue,
			BaseFieldType: "TIME",
		},

		{
			Name:          "TIME_UFIX8_5MS",
			Description:   "Time delta, 8 bits with 5 millisecond Resolution",
			Resolution:    0.005,
			Size:          8,
			HasSign:       &falseValue,
			BaseFieldType: "TIME",
		},

		{
			Name:          "TIME_UFIX8_P12S",
			Description:   "Time delta, 8 bits with 2^12 second Resolution",
			Resolution:    math.Pow(2, 12),
			Size:          8,
			HasSign:       &falseValue,
			BaseFieldType: "TIME",
		},

		{
			Name:          "TIME_UFIX16_MS",
			Description:   "Time delta, 16 bits with millisecond Resolution",
			Resolution:    0.001,
			Size:          16,
			HasSign:       &falseValue,
			BaseFieldType: "TIME",
		},

		{
			Name:          "TIME_UFIX16_CS",
			Description:   "Time delta, 16 bits with centisecond Resolution",
			Resolution:    0.01,
			Size:          16,
			HasSign:       &falseValue,
			BaseFieldType: "TIME",
		},

		{
			Name:          "TIME_UFIX16_MIN",
			Description:   "Time delta, 16 bits with minute Resolution",
			Resolution:    60,
			Size:          16,
			HasSign:       &falseValue,
			BaseFieldType: "TIME",
		},

		{
			Name:          "TIME_UFIX24_MS",
			Description:   "Time delta, 24 bits with millisecond Resolution",
			Resolution:    0.001,
			Size:          24,
			HasSign:       &falseValue,
			BaseFieldType: "TIME",
		},

		{
			Name:          "TIME_UFIX32_S",
			Description:   "Time delta, 32 bits with second Resolution",
			Resolution:    1,
			Size:          32,
			HasSign:       &falseValue,
			BaseFieldType: "TIME",
		},

		{
			Name:          "TIME_UFIX32_MS",
			Description:   "Time delta, 32 bits with millisecond Resolution",
			Resolution:    0.001,
			Size:          32,
			HasSign:       &falseValue,
			BaseFieldType: "TIME",
		},

		{
			Name:          "TIME_FIX32_MS",
			Description:   "Time delta",
			Resolution:    0.001,
			Size:          32,
			HasSign:       &trueValue,
			BaseFieldType: "TIME",
		},

		{
			Name:          "TIME_FIX16_5CS",
			Description:   "Time delta, 5 centisecond Resolution",
			Resolution:    0.05,
			Size:          16,
			HasSign:       &trueValue,
			BaseFieldType: "TIME",
		},

		{
			Name:          "TIME_FIX16_MIN",
			Description:   "Time delta, minute Resolution",
			Resolution:    60,
			Size:          16,
			HasSign:       &trueValue,
			BaseFieldType: "TIME",
			V1Type:        "Integer",
		},

		{
			Name:                "DATE",
			Description:         "Date",
			EncodingDescription: "The date, in days since 1 January 1970.",
			Physical:            &dateQuantity,
			Size:                16,
			HasSign:             &falseValue,
			CF:                  convertFieldDate,
			PF:                  Printer.PrintFieldDate,
			V1Type:              "Date",
		},

		{
			Name:          "VOLTAGE_UFIX16_10MV",
			Description:   "Voltage",
			Resolution:    0.01,
			Physical:      &potentialDifferenceQuantity,
			BaseFieldType: "UFIX16",
		},

		{
			Name:          "VOLTAGE_UFIX16_50MV",
			Description:   "Voltage",
			Resolution:    0.05,
			Physical:      &potentialDifferenceQuantity,
			BaseFieldType: "UFIX16",
		},

		{
			Name:          "VOLTAGE_UFIX16_100MV",
			Description:   "Voltage",
			Resolution:    0.1,
			Physical:      &potentialDifferenceQuantity,
			BaseFieldType: "UFIX16",
		},

		{
			Name:          "VOLTAGE_UFIX8_200MV",
			Description:   "Voltage",
			Resolution:    0.2,
			Physical:      &potentialDifferenceQuantity,
			BaseFieldType: "UFIX8",
		},

		{
			Name:          "VOLTAGE_UFIX16_V",
			Description:   "Voltage",
			Resolution:    1,
			Physical:      &potentialDifferenceQuantity,
			BaseFieldType: "UFIX16",
		},

		{
			Name:          "VOLTAGE_FIX16_10MV",
			Description:   "Voltage, signed",
			Resolution:    0.01,
			Physical:      &potentialDifferenceQuantity,
			BaseFieldType: "FIX16",
		},

		{
			Name:          "CURRENT",
			Description:   "Electrical current",
			HasSign:       &falseValue,
			Physical:      &electricalCurrentQuantity,
			BaseFieldType: "UNSIGNED_FIXED_POINT_NUMBER",
		},

		{
			Name:          "CURRENT_UFIX8_A",
			Description:   "Electrical current",
			Resolution:    1,
			Physical:      &electricalCurrentQuantity,
			BaseFieldType: "UFIX8",
		},

		{
			Name:          "CURRENT_UFIX16_A",
			Description:   "Electrical current",
			Resolution:    1,
			Physical:      &electricalCurrentQuantity,
			BaseFieldType: "UFIX16",
		},

		{
			Name:          "CURRENT_UFIX16_DA",
			Description:   "Electrical current",
			Resolution:    .1,
			Physical:      &electricalCurrentQuantity,
			BaseFieldType: "UFIX16",
		},

		{
			Name:          "CURRENT_FIX16_DA",
			Description:   "Electrical current",
			Resolution:    .1,
			Physical:      &electricalCurrentQuantity,
			BaseFieldType: "FIX16",
		},

		{
			Name:          "CURRENT_FIX24_CA",
			Description:   "Electrical current",
			Resolution:    .01,
			Physical:      &electricalCurrentQuantity,
			BaseFieldType: "FIX24",
		},

		{
			Name:          "ELECTRIC_CHARGE_UFIX16_AH",
			Description:   "Electrical charge",
			Resolution:    1,
			Unit:          "Ah",
			Physical:      &electricalChargeQuantity,
			BaseFieldType: "UFIX16",
		},

		{
			Name:          "PEUKERT_EXPONENT",
			Description:   "Effect of discharge rate on usable battery capacity",
			Resolution:    0.002,
			Offset:        500, // = 1 / Resolution
			URL:           "https://en.wikipedia.org/wiki/Peukert's_law",
			BaseFieldType: "UFIX8",
		},

		{
			Name:          "CURRENT_SIGNED",
			Description:   "Electrical current, signed",
			Physical:      &electricalChargeQuantity,
			BaseFieldType: "SIGNED_FIXED_POINT_NUMBER",
		},

		{Name: "ENERGY_UINT32", Description: "Electrical energy", Physical: &electricalEnergyQuantity, BaseFieldType: "UINT32"},

		{
			Name:                "POWER_FIX32_OFFSET",
			Description:         "Electrical power",
			EncodingDescription: "This uses an offset, so 0 encodes the maximum negative value -2000000000, and 0 is represented by 2000000000.",
			Resolution:          1,
			Offset:              -2000000000,
			Physical:            &electricalPowerQuantity,
			BaseFieldType:       "FIX32",
		},

		{
			Name:                "POWER_FIX32_OFFSET",
			Description:         "Electrical power",
			EncodingDescription: "This uses an offset, so 0 encodes the maximum negative value -2000000000, and 0 is represented by 2000000000.",
			Resolution:          1,
			Offset:              -2000000000,
			Physical:            &electricalPowerQuantity,
			BaseFieldType:       "FIX32",
		},

		{
			Name:        "POWER_FIX32_VA_OFFSET",
			Description: "Electrical power, AC apparent power",
			EncodingDescription: "This uses an offset, so 0 encodes the maximum negative value -2000000000, and 0 is represented by 2000000000. Depending on " +
				"the field it represents either real power in W, active power in VA or reactive power in VAR.",
			Resolution:    1,
			Offset:        -2000000000,
			Physical:      &electricalApparentPowerQuantity,
			BaseFieldType: "FIX32",
		},

		{
			Name:        "POWER_FIX32_VAR_OFFSET",
			Description: "Electrical power, AC reactive power",
			EncodingDescription: "This uses an offset, so 0 encodes the maximum negative value -2000000000, and 0 is represented by 2000000000. Depending on " +
				"the field it represents either real power in W, active power in VA or reactive power in VAR.",
			Resolution:    1,
			Offset:        -2000000000,
			Physical:      &electricalReactivePowerQuantity,
			BaseFieldType: "FIX32",
		},

		{
			Name:          "POWER_UINT16",
			Description:   "Electrical power, either DC or AC Real power, in Watts",
			Physical:      &electricalPowerQuantity,
			Resolution:    1,
			BaseFieldType: "UINT16",
		},

		{
			Name:          "POWER_UINT16_VAR",
			Description:   "Electrical power, AC reactive",
			Physical:      &electricalReactivePowerQuantity,
			Unit:          "VAR",
			Resolution:    1,
			BaseFieldType: "UINT16",
		},

		{
			Name:          "POWER_INT32",
			Description:   "Electrical power, either DC or AC Real power, in Watts",
			Physical:      &electricalPowerQuantity,
			Resolution:    1,
			BaseFieldType: "INT32",
		},

		{
			Name:          "POWER_UINT32",
			Description:   "Electrical power, DC or AC Real power, in Watts",
			Physical:      &electricalPowerQuantity,
			Resolution:    1,
			BaseFieldType: "UINT32",
		},

		{
			Name:          "POWER_UINT32_VA",
			Description:   "Electrical power, AC apparent power in VA.",
			Unit:          "VA",
			Resolution:    1,
			Physical:      &electricalApparentPowerQuantity,
			BaseFieldType: "UINT32",
		},

		{
			Name:          "POWER_UINT32_VAR",
			Description:   "Electrical power, AC reactive power in VAR.",
			Unit:          "VAR",
			Resolution:    1,
			Physical:      &electricalReactivePowerQuantity,
			BaseFieldType: "UINT32",
		},

		{Name: "PERCENTAGE_UINT8", Description: "Percentage, unsigned", Unit: "%", BaseFieldType: "UINT8"},

		{Name: "PERCENTAGE_UINT8_HIGHRES", Description: "Percentage, unsigned", Unit: "%", BaseFieldType: "UINT8"},

		{Name: "PERCENTAGE_INT8", Description: "Percentage", Unit: "%", BaseFieldType: "INT8"},

		{
			Name:          "PERCENTAGE_FIX16",
			Description:   "Percentage, high precision",
			Unit:          "%",
			Resolution:    resPercentage,
			BaseFieldType: "FIX16",
		},

		{
			Name:                "PERCENTAGE_FIX16_D",
			Description:         "Percentage, promille range",
			EncodingDescription: "Percentage in promille (1/10 %)",
			Resolution:          0.1,
			Unit:                "%",
			BaseFieldType:       "FIX16",
		},

		{
			Name:                "ROTATION_FIX16",
			Description:         "Rotational speed",
			EncodingDescription: "Angular rotation in rad/s, in 1/32th of a thousandth radian",
			Comment:             "Whoever came up with 1/32th of 1/1000 of a radian?",
			Resolution:          (1e-3 / 32.0),
			Physical:            &angularVelocityQuantity,
			BaseFieldType:       "FIX16",
		},

		{
			Name:                "ROTATION_FIX32",
			Description:         "Rotational speed, high Resolution",
			EncodingDescription: "Angular rotation in rad/s, in 1/32th of a millionth radian",
			Comment:             "Whoever came up with 1/32th of 1e-6 of a radian?",
			Resolution:          (1e-6 / 32.0),
			Physical:            &angularVelocityQuantity,
			BaseFieldType:       "FIX32",
		},

		{
			Name:                "ROTATION_UFIX16_RPM",
			Description:         "Rotational speed, RPM",
			EncodingDescription: "Angular rotation in 0.25 rpm",
			Resolution:          0.25,
			Unit:                "rpm",
			Physical:            &angularVelocityQuantity,
			BaseFieldType:       "UFIX16",
		},

		{
			Name:                "ROTATION_UFIX16_RPM_HIGHRES",
			Description:         "Rotational speed, RPM",
			EncodingDescription: "Angular rotation in 0.125 rpm",
			Resolution:          0.125,
			Unit:                "rpm",
			Physical:            &angularVelocityQuantity,
			BaseFieldType:       "UFIX16",
		},

		{
			Name:          "PRESSURE_UFIX16_HPA",
			Description:   "Pressure, 16 bit unsigned in hectopascal Resolution",
			Resolution:    100,
			Physical:      &pressureQuantity,
			BaseFieldType: "UFIX16",
		},

		{
			Name:          "PRESSURE_UINT8_2KPA",
			Description:   "Pressure, 8 bit unsigned in 2 kilopascal Resolution",
			Resolution:    2000,
			Physical:      &pressureQuantity,
			BaseFieldType: "UINT8",
		},

		{
			Name:          "PRESSURE_UINT8_KPA",
			Description:   "Pressure, 8 bit unsigned in .5 kilopascal Resolution",
			Resolution:    500,
			Physical:      &pressureQuantity,
			BaseFieldType: "UINT8",
		},

		{
			Name:          "PRESSURE_UFIX16_KPA",
			Description:   "Pressure, 16 bit unsigned in kilopascal Resolution.",
			Resolution:    1000,
			Physical:      &pressureQuantity,
			BaseFieldType: "UFIX16",
		},

		{
			Name:          "PRESSURE_RATE_FIX16_PA",
			Description:   "Pressure change rate, 16 bit signed in pascal Resolution.",
			Resolution:    1,
			Physical:      &pressureRateQuantity,
			BaseFieldType: "FIX16",
		},

		{
			Name:          "PRESSURE_FIX16_KPA",
			Description:   "Pressure, 16 bit signed in kilopascal Resolution.",
			Resolution:    1000,
			Physical:      &pressureQuantity,
			BaseFieldType: "FIX16",
		},

		{
			Name:          "PRESSURE_UFIX32_DPA",
			Description:   "Pressure, 32 bit unsigned in decipascal Resolution.",
			Resolution:    0.1,
			Physical:      &pressureQuantity,
			BaseFieldType: "UFIX32",
		},

		{
			Name:          "PRESSURE_FIX32_DPA",
			Description:   "Pressure, 32 bit signed in decipascal Resolution.",
			Resolution:    0.1,
			Physical:      &pressureQuantity,
			BaseFieldType: "FIX32",
		},

		{Name: "RADIO_FREQUENCY_UFIX32", Description: "Radio frequency", Physical: &frequencyQuantity, BaseFieldType: "UFIX32"},

		{
			Name:                "FREQUENCY_UFIX16",
			Description:         "frequency",
			EncodingDescription: "Various Resolutions are used, ranging from 0.01 Hz to 1 Hz",
			Physical:            &frequencyQuantity,
			BaseFieldType:       "UFIX16",
		},

		{
			Name:          "SPEED_FIX16_MM",
			Description:   "Speed, with millimeter Resolution",
			Resolution:    0.001,
			Physical:      &speedQuantity,
			BaseFieldType: "FIX16",
		},

		{
			Name:          "SPEED_FIX16_CM",
			Description:   "Speed, with centimeter Resolution",
			Resolution:    0.01,
			Physical:      &speedQuantity,
			BaseFieldType: "FIX16",
		},

		{
			Name:          "SPEED_UFIX16_CM",
			Description:   "Speed, unsigned, with centimeter Resolution",
			Resolution:    0.01,
			Physical:      &speedQuantity,
			BaseFieldType: "UFIX16",
		},

		{
			Name:          "SPEED_UFIX16_DM",
			Description:   "Speed, unsigned, with decimeter Resolution",
			Resolution:    0.1,
			Physical:      &speedQuantity,
			BaseFieldType: "UFIX16",
		},

		{
			Name:          "DISTANCE_FIX16_M",
			Description:   "Distance, with meter Resolution",
			Resolution:    1,
			Physical:      &distanceQuantity,
			BaseFieldType: "FIX16",
		},

		{
			Name:          "DISTANCE_FIX16_CM",
			Description:   "Distance, with centimeter Resolution",
			Resolution:    0.01,
			Physical:      &distanceQuantity,
			BaseFieldType: "FIX16",
		},

		{
			Name:          "DISTANCE_FIX16_MM",
			Description:   "Distance, with millimeter Resolution",
			Resolution:    0.001,
			Physical:      &distanceQuantity,
			BaseFieldType: "FIX16",
		},

		{
			Name:          "DISTANCE_FIX32_MM",
			Description:   "Distance, high range, with millimeter Resolution",
			Resolution:    0.001,
			Physical:      &distanceQuantity,
			BaseFieldType: "FIX32",
		},

		{
			Name:          "DISTANCE_FIX32_CM",
			Description:   "Distance, high range, with centimeter Resolution",
			Resolution:    0.01,
			Physical:      &distanceQuantity,
			BaseFieldType: "FIX32",
		},

		{Name: "DISTANCE_FIX64", Description: "Distance", Resolution: 1e-6, Physical: &distanceQuantity, BaseFieldType: "FIX64"},

		{Name: "GAIN_FIX16", Description: "Gain", Resolution: 0.01, BaseFieldType: "FIX16"},

		{
			Name:          "MAGNETIC_FIELD_FIX16",
			Description:   "Magnetic field",
			Resolution:    0.01,
			Physical:      &magneticFieldQuantity,
			BaseFieldType: "FIX16",
		},

		{
			Name:          "INSTANCE",
			Description:   "Instance",
			Comment:       "Devices that support multiple sensors TODO",
			BaseFieldType: "UINT8",
		},

		{Name: "PGN", Description: "PRN number", Resolution: 1, BaseFieldType: "UINT24"},

		{
			Name:          "POWER_FACTOR_UFIX16",
			Description:   "Power Factor",
			Resolution:    1 / 16384.,
			Physical:      &powerFactorQuantity,
			BaseFieldType: "UFIX16",
		},

		{
			Name:          "POWER_FACTOR_UFIX8",
			Description:   "Power Factor",
			Resolution:    0.01,
			Physical:      &powerFactorQuantity,
			BaseFieldType: "UFIX8",
		},

		{
			Name:        "SIGNED_ALMANAC_PARAMETER",
			Description: "Almanac parameter, signed",
			EncodingDescription: "These encode various almanac parameters consisting of differing sizes and sign. They are all using an " +
				"interesting Resolution/scale, which is always a number of bits that the value is shifted left or " +
				"right. This is reflected by Resolution field containing some factor of 2^n or 2^-n.",
			URL:           "https://www.gps.gov/technical/icwg/IS-GPS-200N.pdf",
			BaseFieldType: "SIGNED_FIXED_POINT_NUMBER",
		},

		{
			Name:        "UNSIGNED_ALMANAC_PARAMETER",
			Description: "Almanac parameter, unsigned",
			EncodingDescription: "These encode various almanac parameters consisting of differing sizes and sign. They are all using an " +
				"interesting Resolution/scale, which is always a number of bits that the value is shifted left or " +
				"right. This is reflected by Resolution field containing some factor of 2^n or 2^-n.",
			URL:           "https://www.gps.gov/technical/icwg/IS-GPS-200N.pdf",
			BaseFieldType: "UNSIGNED_FIXED_POINT_NUMBER",
		},

		// Stringy types
		{
			Name:        "STRING_FIX",
			Description: "A fixed length string containing single byte codepoints.",
			EncodingDescription: "The length of the string is determined by the PGN field definition. Trailing bytes have been observed " +
				"as '@', ' ', 0x0 or 0xff.",
			Comment: "It is unclear what character sets are allowed/supported. Possibly UTF-8 but it could also be that only ASCII values " +
				"are supported.",
			CF:     convertFieldStringFix,
			PF:     Printer.PrintFieldStringFix,
			V1Type: "ASCII text",
		},

		{
			Name:        "STRING_LZ",
			Description: "A varying length string containing single byte codepoints encoded with a length byte and terminating zero.",
			EncodingDescription: "The length of the string is determined by a starting length byte. It also contains a terminating " +
				"zero byte. The length byte includes the zero byte but not itself.",
			Comment: "It is unclear what character sets are allowed/supported. Possibly UTF-8 but it could also be that only ASCII values " +
				"are supported.",
			VariableSize: true,
			CF:           convertFieldStringLZ,
			PF:           Printer.PrintFieldStringLZ,
			V1Type:       "ASCII string starting with length byte",
		},

		{
			Name:                "STRING_LAU",
			Description:         "A varying length string containing double or single byte codepoints encoded with a length byte and terminating zero.",
			EncodingDescription: "The length of the string is determined by a starting length byte. The 2nd byte contains 0 for UNICODE or 1 for ASCII.",
			Comment: "It is unclear what character sets are allowed/supported. For single byte, assume ASCII. For UNICODE, assume UTF-16, " +
				"but this has not been seen in the wild yet.",
			VariableSize: true,
			CF:           convertFieldStringLAU,
			PF:           Printer.PrintFieldStringLAU,
			V1Type:       "ASCII or UNICODE string starting with length and control byte",
		},

		// Others
		{
			Name:                "BINARY",
			Description:         "Binary field",
			EncodingDescription: "Unspecified content consisting of any number of bits.",
			CF:                  convertFieldBinary,
			PF:                  Printer.PrintFieldBinary,
			V1Type:              "Binary data",
		},

		{
			Name:                "RESERVED",
			Description:         "Reserved field",
			EncodingDescription: "All reserved bits shall be 1",
			Comment:             "NMEA reserved for future expansion and/or to align next data on byte boundary",
			CF:                  convertFieldReserved,
			PF:                  Printer.PrintFieldReserved,
		},

		{
			Name:                "SPARE",
			Description:         "Spare field",
			EncodingDescription: "All spare bits shall be 0",
			Comment: "This is like a reserved field but originates from other sources where unused fields shall be 0, like the AIS " +
				"ITU-1371 standard.",
			CF: convertFieldSpare,
			PF: Printer.PrintFieldSpare,
		},

		{
			Name:        "MMSI",
			Description: "MMSI",
			Resolution:  1,
			Size:        32,
			HasSign:     &falseValue,
			RangeMin:    2000000, // Minimal valid MMSI is coastal station (00) MID (2xx)
			RangeMax:    999999999,
			EncodingDescription: "The MMSI is encoded as a 32 bit number, but is always printed as a 9 digit number and should be considered as a string. " +
				"The first three or four digits are special, see the USCG link for a detailed explanation.",
			URL: "https://navcen.uscg.gov/maritime-mobile-service-identity",
			CF:  convertFieldMMSI,
			PF:  Printer.PrintFieldMMSI,
		},

		{
			Name:                "VARIABLE",
			Description:         "Variable",
			EncodingDescription: "The definition of the field is that of the reference PGN and reference field, this is totally variable.",
			CF:                  convertFieldVariable,
			PF:                  Printer.PrintFieldVariable,
			PFIsPrintVariable:   true,
		},

		{
			Name:        "KEY_VALUE",
			Description: "Key/value",
			EncodingDescription: "The type definition of the field is defined by an earlier LookupFieldTypeEnumeration field. The length is defined by " +
				"the preceding length field.",
			CF: convertFieldKeyValue,
			PF: Printer.PrintFieldKeyValue,
		},

		{
			Name:                "FIELD_INDEX",
			Description:         "Field Index",
			Resolution:          1,
			Size:                8,
			HasSign:             &falseValue,
			RangeMin:            1, // Minimum field index (.Order)
			RangeMax:            253,
			EncodingDescription: "Index of the specified field in the PGN referenced.",
			CF:                  convertFieldNumber,
			PF:                  Printer.PrintFieldNumber,
		},
	}
}
