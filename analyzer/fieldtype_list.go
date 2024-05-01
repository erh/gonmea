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

var immutFieldTypes []fieldType

//nolint:lll
func initFieldTypes() {
	// Numeric types
	immutFieldTypes = []fieldType{
		{
			name:        "NUMBER",
			description: "Number",
			encodingDescription: "Binary numbers are little endian. Number fields that use two or three bits use one special encoding, for the maximum " +
				"value.  When present, this means that the field is not present. Number fields that use four bits or more use two special " +
				"encodings. The maximum positive value means that the field is not present. The maximum positive value minus 1 means that " +
				"the field has an error. For instance, a broken sensor. For signed numbers the maximum values are the maximum positive " +
				"value and that minus 1, not the all-ones bit encoding which is the maximum negative value.",
			url:    "https://en.wikipedia.org/wiki/Binary_number",
			v1Type: "Number",
			cf:     convertFieldNumber,
			pf:     fieldPrintNumber,
		},

		{
			name:          "INTEGER",
			description:   "Signed integral number",
			hasSign:       &trueValue,
			baseFieldType: "NUMBER",
			url:           "https://en.wikipedia.org/wiki/Integer_%28computer_science%29",
			v1Type:        "Integer",
		},

		{
			name:          "UNSIGNED_INTEGER",
			description:   "Unsigned integral number",
			hasSign:       &falseValue,
			baseFieldType: "NUMBER",
			url:           "https://en.wikipedia.org/wiki/Integer_%28computer_science%29",
			v1Type:        "Integer",
		},

		{name: "INT8", description: "8 bit signed integer", size: 8, hasSign: &trueValue, baseFieldType: "INTEGER"},

		{name: "UINT8", description: "8 bit unsigned integer", size: 8, hasSign: &falseValue, baseFieldType: "UNSIGNED_INTEGER"},

		{name: "INT16", description: "16 bit signed integer", size: 16, hasSign: &trueValue, baseFieldType: "INTEGER"},

		{name: "UINT16", description: "16 bit unsigned integer", size: 16, hasSign: &falseValue, baseFieldType: "UNSIGNED_INTEGER"},

		{name: "UINT24", description: "24 bit unsigned integer", size: 24, hasSign: &falseValue, baseFieldType: "UNSIGNED_INTEGER"},

		{name: "INT32", description: "32 bit signed integer", size: 32, hasSign: &trueValue, baseFieldType: "INTEGER"},

		{name: "UINT32", description: "32 bit unsigned integer", size: 32, hasSign: &falseValue, baseFieldType: "UNSIGNED_INTEGER"},

		{name: "INT64", description: "64 bit signed integer", size: 64, hasSign: &trueValue, baseFieldType: "INTEGER"},

		{name: "UINT64", description: "64 bit unsigned integer", size: 64, hasSign: &falseValue, baseFieldType: "UNSIGNED_INTEGER"},

		{
			name:        "UNSIGNED_FIXED_POINT_NUMBER",
			description: "An unsigned numeric value where the Least Significant Bit does not encode the integer value 1",
			encodingDescription: "The `Resolution` attribute indicates what the raw value 1 should represent. The `Signed` and `BitLength` attributes are " +
				"always present. Together, this gives sufficient information to represent a fixed point number in a particular range where " +
				"non-integral values can be encoded without requiring four or eight bytes for a floating point number.",
			hasSign:       &falseValue,
			url:           "https://en.wikipedia.org/wiki/Fixed-point_arithmetic",
			baseFieldType: "NUMBER",
		},

		{
			name:        "SIGNED_FIXED_POINT_NUMBER",
			description: "A signed numeric value where the Least Significant Bit does not encode the integer value 1",
			encodingDescription: "The `Resolution` attribute indicates what the raw value 1 should represent. The `Signed` and `BitLength` attributes are " +
				"always present. Together, this gives sufficient information to represent a fixed point number in a particular range where " +
				"non-integral values can be encoded without requiring four or eight bytes for a floating point number.",
			hasSign:       &trueValue,
			url:           "https://en.wikipedia.org/wiki/Fixed-point_arithmetic",
			baseFieldType: "NUMBER",
		},

		{name: "FIX8", description: "8 bit signed fixed point number", size: 8, baseFieldType: "SIGNED_FIXED_POINT_NUMBER"},

		{
			name:          "UFIX8",
			description:   "8 bit unsigned fixed point number",
			size:          8,
			baseFieldType: "UNSIGNED_FIXED_POINT_NUMBER",
		},

		{name: "FIX16", description: "16 bit signed fixed point number", size: 16, baseFieldType: "SIGNED_FIXED_POINT_NUMBER"},

		{
			name:          "UFIX16",
			description:   "16 bit unsigned fixed point number",
			size:          16,
			baseFieldType: "UNSIGNED_FIXED_POINT_NUMBER",
		},

		{name: "FIX24", description: "24 bit signed fixed point number", size: 24, baseFieldType: "SIGNED_FIXED_POINT_NUMBER"},

		{
			name:          "UFIX24",
			description:   "24 bit unsigned fixed point number",
			size:          24,
			baseFieldType: "UNSIGNED_FIXED_POINT_NUMBER",
		},

		{name: "FIX32", description: "32 bit signed fixed point number", size: 32, baseFieldType: "SIGNED_FIXED_POINT_NUMBER"},

		{
			name:          "UFIX32",
			description:   "32 bit unsigned fixed point number",
			size:          32,
			baseFieldType: "UNSIGNED_FIXED_POINT_NUMBER",
		},

		{name: "FIX64", description: "64 bit signed fixed point number", size: 64, baseFieldType: "SIGNED_FIXED_POINT_NUMBER"},

		{
			name:          "UFIX64",
			description:   "64 bit unsigned fixed point number",
			size:          64,
			baseFieldType: "UNSIGNED_FIXED_POINT_NUMBER",
		},

		{
			name:        "FLOAT",
			description: "32 bit IEEE-754 floating point number",
			size:        32,
			hasSign:     &trueValue,
			url:         "https://en.wikipedia.org/wiki/IEEE_754",
			cf:          convertFieldFloat,
			pf:          fieldPrintFloat,
		},

		{
			name:        "DECIMAL",
			description: "A unsigned numeric value represented with 2 decimal digits per byte",
			encodingDescription: "Each byte represent 2 digits, so 1234 is represented by 2 bytes containing 0x12 and 0x34. A number " +
				"with an odd number of digits will have 0 as the first digit in the first byte.",
			hasSign: &falseValue,
			url:     "https://en.wikipedia.org/wiki/Binary-coded_decimal",
			cf:      convertFieldDecimal,
			pf:      fieldPrintDecimal,
		},

		{
			name:                "LOOKUP",
			description:         "Number value where each value encodes for a distinct meaning",
			encodingDescription: "Each lookup has a LookupEnumeration defining what the possible values mean",
			comment: "For almost all lookups the list of values is known with some precision, but it is quite possible that a value " +
				"occurs that has no corresponding textual explanation.",
			hasSign: &falseValue,
			cf:      convertFieldLookup,
			pf:      fieldPrintLookup,
			v1Type:  "Lookup table",
		},

		{
			name:                "INDIRECT_LOOKUP",
			description:         "Number value where each value encodes for a distinct meaning but the meaning also depends on the value in another field",
			encodingDescription: "Each lookup has a LookupIndirectEnumeration defining what the possible values mean",
			comment: "For almost all lookups the list of values is known with some precision, but it is quite possible that a value " +
				"occurs that has no corresponding textual explanation.",
			hasSign: &falseValue,
			cf:      convertFieldLookup,
			pf:      fieldPrintLookup,
			v1Type:  "Integer",
		},

		{
			name:        "BITLOOKUP",
			description: "Number value where each bit value encodes for a distinct meaning",
			encodingDescription: "Each LookupBit has a LookupBitEnumeration defining what the possible values mean. A bitfield can have " +
				"any combination of bits set.",
			comment: "For almost all lookups the list of values is known with some precision, but it is quite possible that a value " +
				"occurs that has no corresponding textual explanation.",
			cf:     convertFieldBitLookup,
			pf:     fieldPrintBitLookup,
			v1Type: "Bitfield",
		},

		{
			name:                "FIELDTYPE_LOOKUP",
			description:         "Number value where each value encodes for a distinct meaning including a fieldtype of the next variable field",
			encodingDescription: "Each lookup has a LookupFieldTypeEnumeration defining what the possible values mean",
			comment: "These values have been determined by reverse engineering, given the known values it is anticipated that there are " +
				"unknown enumeration values and some known values have incorrect datatypes",
			hasSign: &falseValue,
			cf:      convertFieldLookup,
			pf:      fieldPrintLookup,
		},

		{
			name:          "MANUFACTURER",
			description:   "Manufacturer",
			size:          11,
			cf:            convertFieldLookup,
			pf:            fieldPrintLookup,
			baseFieldType: "LOOKUP",
			v1Type:        "Manufacturer code",
		},

		{
			name:          "INDUSTRY",
			description:   "Industry",
			size:          3,
			cf:            convertFieldLookup,
			pf:            fieldPrintLookup,
			baseFieldType: "LOOKUP",
		},

		{name: "VERSION", description: "Version", resolution: 0.001, baseFieldType: "UFIX16"},

		// Specific typed numeric fields

		{name: "FIX16_1", description: "Fixed point signed with 1 digit resolution", resolution: 0.1, baseFieldType: "FIX16"},

		{name: "FIX32_2", description: "Fixed point signed with 2 digits resolution", resolution: 0.01, baseFieldType: "FIX32"},

		{
			name:          "UFIX32_2",
			description:   "Fixed point unsigned with 2 digits resolution",
			resolution:    0.001,
			baseFieldType: "UFIX32",
		},

		{
			name:          "UFIX16_3",
			description:   "Fixed point unsigned with 3 digits resolution",
			resolution:    0.001,
			baseFieldType: "UFIX16",
		},

		{
			name:          "DILUTION_OF_PRECISION_FIX16",
			description:   "Dilution of precision",
			url:           "https://en.wikipedia.org/wiki/Dilution_of_precision_(navigation)",
			resolution:    0.01,
			baseFieldType: "FIX16",
		},

		{
			name:          "DILUTION_OF_PRECISION_UFIX16",
			description:   "Dilution of precision",
			url:           "https://en.wikipedia.org/wiki/Dilution_of_precision_(navigation)",
			resolution:    0.01,
			baseFieldType: "UFIX16",
		},

		{
			name:          "SIGNALTONOISERATIO_FIX16",
			description:   "Signal-to-noise ratio",
			url:           "https://en.wikipedia.org/wiki/Signal-to-noise_ratio",
			resolution:    0.01,
			physical:      &signalToNoiseRatioQuantity,
			baseFieldType: "FIX16",
		},

		{
			name:          "SIGNALTONOISERATIO_UFIX16",
			description:   "Signal-to-noise ratio",
			url:           "https://en.wikipedia.org/wiki/Signal-to-noise_ratio",
			resolution:    0.01,
			physical:      &signalToNoiseRatioQuantity,
			baseFieldType: "UFIX16",
		},

		{name: "ANGLE_FIX16", description: "Angle", resolution: 0.0001, physical: &angleQuantity, baseFieldType: "FIX16"},

		{
			name:          "ANGLE_FIX16_DDEG",
			description:   "Angle",
			resolution:    0.1,
			unit:          "deg",
			physical:      &angleQuantity,
			baseFieldType: "FIX16",
		},

		{name: "ANGLE_UFIX16", description: "Angle", resolution: 0.0001, physical: &angleQuantity, baseFieldType: "UFIX16"},

		{
			name:        "GEO_FIX32",
			description: "Geographical latitude or longitude",
			encodingDescription: "The `Resolution` for this field is 1.0e-7, so the resolution is 1/10 millionth of a degree, or about 1 " +
				"cm when we refer to an Earth position",
			resolution:    1.0e-7,
			physical:      &geoCoordinateQuantity,
			cf:            convertFieldLatLon,
			pf:            fieldPrintLatLon,
			baseFieldType: "FIX32",
			v1Type:        "Lat/Lon",
		},

		{
			name:        "GEO_FIX64",
			description: "Geographical latitude or longitude, high resolution",
			encodingDescription: "The `Resolution` for this field is 1.0e-16, so the resolution is about 0.01 nm (nanometer) when we " +
				"refer to an Earth position",
			resolution:    1.0e-16,
			physical:      &geoCoordinateQuantity,
			cf:            convertFieldLatLon,
			pf:            fieldPrintLatLon,
			baseFieldType: "FIX64",
			v1Type:        "Lat/Lon",
		},

		{
			name:          "LENGTH_UFIX8_DAM",
			description:   "Length, in decameter resolution",
			resolution:    10,
			physical:      &lengthQuantity,
			baseFieldType: "UFIX8",
		},

		{
			name:          "LENGTH_UFIX16_DM",
			description:   "Length, in decimeter resolution",
			resolution:    0.1,
			physical:      &lengthQuantity,
			baseFieldType: "UFIX16",
		},

		{
			name:          "LENGTH_UFIX32_CM",
			description:   "Length, in centimeter resolution",
			resolution:    0.01,
			physical:      &lengthQuantity,
			baseFieldType: "UFIX32",
		},

		{
			name:          "LENGTH_UFIX32_M",
			description:   "Length, in meter resolution",
			resolution:    1,
			physical:      &lengthQuantity,
			baseFieldType: "UFIX32",
		},

		{
			name:          "LENGTH_UFIX32_CM",
			description:   "Length, in centimeter resolution",
			resolution:    0.01,
			physical:      &lengthQuantity,
			baseFieldType: "UFIX32",
		},

		{
			name:          "LENGTH_UFIX32_MM",
			description:   "Length, in millimeter resolution",
			resolution:    0.001,
			physical:      &lengthQuantity,
			baseFieldType: "UFIX32",
		},

		{
			name:          "LENGTH_UFIX8_DAM",
			description:   "Length, byte, unsigned decameters",
			resolution:    10.,
			physical:      &lengthQuantity,
			baseFieldType: "UFIX8",
		},

		{
			name:          "LENGTH_UFIX16_CM",
			description:   "Length, unsigned centimeters",
			resolution:    0.01,
			physical:      &lengthQuantity,
			baseFieldType: "UFIX16",
		},

		{
			name:          "LENGTH_UFIX16_DM",
			description:   "Length, unsigned decimeters",
			resolution:    0.1,
			physical:      &lengthQuantity,
			baseFieldType: "UFIX16",
		},

		{
			name:          "LENGTH_UFIX32_MM",
			description:   "Length, high range, unsigned millimeters",
			resolution:    0.001,
			physical:      &lengthQuantity,
			baseFieldType: "UFIX32",
		},

		{
			name:          "LENGTH_UFIX32_CM",
			description:   "Length, high range, unsigned centimeters",
			resolution:    0.01,
			physical:      &lengthQuantity,
			baseFieldType: "UFIX32",
		},

		{
			name:          "LENGTH_UFIX32_M",
			description:   "Length, high range, meters",
			resolution:    1.,
			physical:      &lengthQuantity,
			baseFieldType: "UFIX32",
		},

		{
			name:          "TEMPERATURE",
			description:   "Temperature",
			resolution:    0.01,
			physical:      &temperatureQuantity,
			baseFieldType: "UFIX16",
			v1Type:        "Temperature",
		},

		{
			name:          "TEMPERATURE_UINT8_OFFSET", /* used by PGN 65262 & 65270 */
			description:   "Temperature",
			offset:        233, /* offset to degrees Kelvin */
			resolution:    1,
			physical:      &temperatureQuantity,
			baseFieldType: "UINT8",
			v1Type:        "Temperature",
		},

		{
			name:                "TEMPERATURE_HIGH",
			description:         "Temperature, high range",
			encodingDescription: "This has a higher range but lower resolution than TEMPERATURE",
			resolution:          0.1,
			physical:            &temperatureQuantity,
			baseFieldType:       "UFIX16",
			v1Type:              "Temperature",
		},

		{
			name:                "TEMPERATURE_UFIX24",
			description:         "Temperature, high resolution",
			encodingDescription: "This has a higher range and higher resolution than TEMPERATURE (but uses three bytes)",
			resolution:          0.001,
			physical:            &temperatureQuantity,
			baseFieldType:       "UFIX24",
			v1Type:              "Temperature",
		},

		{
			name:          "TEMPERATURE_DELTA_FIX16",
			description:   "Temperature difference",
			resolution:    0.001,
			physical:      &temperatureQuantity,
			baseFieldType: "FIX16",
		},

		{
			name:          "VOLUMETRIC_FLOW",
			description:   "Volumetric flow",
			resolution:    0.1,
			physical:      &volumetricFlowQuantity,
			baseFieldType: "FIX16",
		},

		{
			name:                "CONCENTRATION_UINT16_PPM",
			description:         "Concentration of one substance in another, in this context usually the amount of salts in water",
			encodingDescription: "Expressed in parts per million",
			resolution:          1,
			physical:            &concentrationQuantity,
			baseFieldType:       "UINT16",
		},

		{name: "VOLUME_UFIX16_L", description: "Volume", resolution: 1, physical: &volumeQuantity, baseFieldType: "UFIX16"},

		{name: "VOLUME_UFIX32_DL", description: "Volume", resolution: 0.1, physical: &volumeQuantity, baseFieldType: "UFIX32"},

		{
			name:        "TIME",
			description: "Time",
			physical:    &timeQuantity,
			cf:          convertFieldTime,
			pf:          fieldPrintTime,
			v1Type:      "Time",
		},

		{
			name:                "TIME_UFIX32",
			description:         "Time",
			encodingDescription: "When indicating a wall clock time, this is the amount of time passed since midnight",
			size:                32,
			hasSign:             &falseValue,
			resolution:          0.0001,
			baseFieldType:       "TIME",
		},

		{
			name:          "TIME_UFIX16_S",
			description:   "Time delta, 16 bits with 1 second resolution",
			resolution:    1,
			size:          16,
			hasSign:       &falseValue,
			baseFieldType: "TIME",
		},

		{
			name:          "TIME_UFIX8_5MS",
			description:   "Time delta, 8 bits with 5 millisecond resolution",
			resolution:    0.005,
			size:          8,
			hasSign:       &falseValue,
			baseFieldType: "TIME",
		},

		{
			name:          "TIME_UFIX8_P12S",
			description:   "Time delta, 8 bits with 2^12 second resolution",
			resolution:    math.Pow(2, 12),
			size:          8,
			hasSign:       &falseValue,
			baseFieldType: "TIME",
		},

		{
			name:          "TIME_UFIX16_MS",
			description:   "Time delta, 16 bits with millisecond resolution",
			resolution:    0.001,
			size:          16,
			hasSign:       &falseValue,
			baseFieldType: "TIME",
		},

		{
			name:          "TIME_UFIX16_CS",
			description:   "Time delta, 16 bits with centisecond resolution",
			resolution:    0.01,
			size:          16,
			hasSign:       &falseValue,
			baseFieldType: "TIME",
		},

		{
			name:          "TIME_UFIX16_MIN",
			description:   "Time delta, 16 bits with minute resolution",
			resolution:    60,
			size:          16,
			hasSign:       &falseValue,
			baseFieldType: "TIME",
		},

		{
			name:          "TIME_UFIX24_MS",
			description:   "Time delta, 24 bits with millisecond resolution",
			resolution:    0.001,
			size:          24,
			hasSign:       &falseValue,
			baseFieldType: "TIME",
		},

		{
			name:          "TIME_UFIX32_S",
			description:   "Time delta, 32 bits with second resolution",
			resolution:    1,
			size:          32,
			hasSign:       &falseValue,
			baseFieldType: "TIME",
		},

		{
			name:          "TIME_UFIX32_MS",
			description:   "Time delta, 32 bits with millisecond resolution",
			resolution:    0.001,
			size:          32,
			hasSign:       &falseValue,
			baseFieldType: "TIME",
		},

		{
			name:          "TIME_FIX32_MS",
			description:   "Time delta",
			resolution:    0.001,
			size:          32,
			hasSign:       &trueValue,
			baseFieldType: "TIME",
		},

		{
			name:          "TIME_FIX16_5CS",
			description:   "Time delta, 5 centisecond resolution",
			resolution:    0.05,
			size:          16,
			hasSign:       &trueValue,
			baseFieldType: "TIME",
		},

		{
			name:          "TIME_FIX16_MIN",
			description:   "Time delta, minute resolution",
			resolution:    60,
			size:          16,
			hasSign:       &trueValue,
			baseFieldType: "TIME",
			v1Type:        "Integer",
		},

		{
			name:                "DATE",
			description:         "Date",
			encodingDescription: "The date, in days since 1 January 1970.",
			physical:            &dateQuantity,
			size:                16,
			hasSign:             &falseValue,
			cf:                  convertFieldDate,
			pf:                  fieldPrintDate,
			v1Type:              "Date",
		},

		{
			name:          "VOLTAGE_UFIX16_10MV",
			description:   "Voltage",
			resolution:    0.01,
			physical:      &potentialDifferenceQuantity,
			baseFieldType: "UFIX16",
		},

		{
			name:          "VOLTAGE_UFIX16_50MV",
			description:   "Voltage",
			resolution:    0.05,
			physical:      &potentialDifferenceQuantity,
			baseFieldType: "UFIX16",
		},

		{
			name:          "VOLTAGE_UFIX16_100MV",
			description:   "Voltage",
			resolution:    0.1,
			physical:      &potentialDifferenceQuantity,
			baseFieldType: "UFIX16",
		},

		{
			name:          "VOLTAGE_UFIX8_200MV",
			description:   "Voltage",
			resolution:    0.2,
			physical:      &potentialDifferenceQuantity,
			baseFieldType: "UFIX8",
		},

		{
			name:          "VOLTAGE_UFIX16_V",
			description:   "Voltage",
			resolution:    1,
			physical:      &potentialDifferenceQuantity,
			baseFieldType: "UFIX16",
		},

		{
			name:          "VOLTAGE_FIX16_10MV",
			description:   "Voltage, signed",
			resolution:    0.01,
			physical:      &potentialDifferenceQuantity,
			baseFieldType: "FIX16",
		},

		{
			name:          "CURRENT",
			description:   "Electrical current",
			hasSign:       &falseValue,
			physical:      &electricalCurrentQuantity,
			baseFieldType: "UNSIGNED_FIXED_POINT_NUMBER",
		},

		{
			name:          "CURRENT_UFIX8_A",
			description:   "Electrical current",
			resolution:    1,
			physical:      &electricalCurrentQuantity,
			baseFieldType: "UFIX8",
		},

		{
			name:          "CURRENT_UFIX16_A",
			description:   "Electrical current",
			resolution:    1,
			physical:      &electricalCurrentQuantity,
			baseFieldType: "UFIX16",
		},

		{
			name:          "CURRENT_UFIX16_DA",
			description:   "Electrical current",
			resolution:    .1,
			physical:      &electricalCurrentQuantity,
			baseFieldType: "UFIX16",
		},

		{
			name:          "CURRENT_FIX16_DA",
			description:   "Electrical current",
			resolution:    .1,
			physical:      &electricalCurrentQuantity,
			baseFieldType: "FIX16",
		},

		{
			name:          "CURRENT_FIX24_CA",
			description:   "Electrical current",
			resolution:    .01,
			physical:      &electricalCurrentQuantity,
			baseFieldType: "FIX24",
		},

		{
			name:          "ELECTRIC_CHARGE_UFIX16_AH",
			description:   "Electrical charge",
			resolution:    1,
			unit:          "Ah",
			physical:      &electricalChargeQuantity,
			baseFieldType: "UFIX16",
		},

		{
			name:          "PEUKERT_EXPONENT",
			description:   "Effect of discharge rate on usable battery capacity",
			resolution:    0.002,
			offset:        500, // = 1 / resolution
			url:           "https://en.wikipedia.org/wiki/Peukert's_law",
			baseFieldType: "UFIX8",
		},

		{
			name:          "CURRENT_SIGNED",
			description:   "Electrical current, signed",
			physical:      &electricalChargeQuantity,
			baseFieldType: "SIGNED_FIXED_POINT_NUMBER",
		},

		{name: "ENERGY_UINT32", description: "Electrical energy", physical: &electricalEnergyQuantity, baseFieldType: "UINT32"},

		{
			name:                "POWER_FIX32_OFFSET",
			description:         "Electrical power",
			encodingDescription: "This uses an offset, so 0 encodes the maximum negative value -2000000000, and 0 is represented by 2000000000.",
			resolution:          1,
			offset:              -2000000000,
			physical:            &electricalPowerQuantity,
			baseFieldType:       "FIX32",
		},

		{
			name:                "POWER_FIX32_OFFSET",
			description:         "Electrical power",
			encodingDescription: "This uses an offset, so 0 encodes the maximum negative value -2000000000, and 0 is represented by 2000000000.",
			resolution:          1,
			offset:              -2000000000,
			physical:            &electricalPowerQuantity,
			baseFieldType:       "FIX32",
		},

		{
			name:        "POWER_FIX32_VA_OFFSET",
			description: "Electrical power, AC apparent power",
			encodingDescription: "This uses an offset, so 0 encodes the maximum negative value -2000000000, and 0 is represented by 2000000000. Depending on " +
				"the field it represents either real power in W, active power in VA or reactive power in VAR.",
			resolution:    1,
			offset:        -2000000000,
			physical:      &electricalApparentPowerQuantity,
			baseFieldType: "FIX32",
		},

		{
			name:        "POWER_FIX32_VAR_OFFSET",
			description: "Electrical power, AC reactive power",
			encodingDescription: "This uses an offset, so 0 encodes the maximum negative value -2000000000, and 0 is represented by 2000000000. Depending on " +
				"the field it represents either real power in W, active power in VA or reactive power in VAR.",
			resolution:    1,
			offset:        -2000000000,
			physical:      &electricalReactivePowerQuantity,
			baseFieldType: "FIX32",
		},

		{
			name:          "POWER_UINT16",
			description:   "Electrical power, either DC or AC Real power, in Watts",
			physical:      &electricalPowerQuantity,
			resolution:    1,
			baseFieldType: "UINT16",
		},

		{
			name:          "POWER_UINT16_VAR",
			description:   "Electrical power, AC reactive",
			physical:      &electricalReactivePowerQuantity,
			unit:          "VAR",
			resolution:    1,
			baseFieldType: "UINT16",
		},

		{
			name:          "POWER_INT32",
			description:   "Electrical power, either DC or AC Real power, in Watts",
			physical:      &electricalPowerQuantity,
			resolution:    1,
			baseFieldType: "INT32",
		},

		{
			name:          "POWER_UINT32",
			description:   "Electrical power, DC or AC Real power, in Watts",
			physical:      &electricalPowerQuantity,
			resolution:    1,
			baseFieldType: "UINT32",
		},

		{
			name:          "POWER_UINT32_VA",
			description:   "Electrical power, AC apparent power in VA.",
			unit:          "VA",
			resolution:    1,
			physical:      &electricalApparentPowerQuantity,
			baseFieldType: "UINT32",
		},

		{
			name:          "POWER_UINT32_VAR",
			description:   "Electrical power, AC reactive power in VAR.",
			unit:          "VAR",
			resolution:    1,
			physical:      &electricalReactivePowerQuantity,
			baseFieldType: "UINT32",
		},

		{name: "PERCENTAGE_UINT8", description: "Percentage, unsigned", unit: "%", baseFieldType: "UINT8"},

		{name: "PERCENTAGE_UINT8_HIGHRES", description: "Percentage, unsigned", unit: "%", baseFieldType: "UINT8"},

		{name: "PERCENTAGE_INT8", description: "Percentage", unit: "%", baseFieldType: "INT8"},

		{
			name:          "PERCENTAGE_FIX16",
			description:   "Percentage, high precision",
			unit:          "%",
			resolution:    resPercentage,
			baseFieldType: "FIX16",
		},

		{
			name:                "PERCENTAGE_FIX16_D",
			description:         "Percentage, promille range",
			encodingDescription: "Percentage in promille (1/10 %)",
			resolution:          0.1,
			unit:                "%",
			baseFieldType:       "FIX16",
		},

		{
			name:                "ROTATION_FIX16",
			description:         "Rotational speed",
			encodingDescription: "Angular rotation in rad/s, in 1/32th of a thousandth radian",
			comment:             "Whoever came up with 1/32th of 1/1000 of a radian?",
			resolution:          (1e-3 / 32.0),
			physical:            &angularVelocityQuantity,
			baseFieldType:       "FIX16",
		},

		{
			name:                "ROTATION_FIX32",
			description:         "Rotational speed, high resolution",
			encodingDescription: "Angular rotation in rad/s, in 1/32th of a millionth radian",
			comment:             "Whoever came up with 1/32th of 1e-6 of a radian?",
			resolution:          (1e-6 / 32.0),
			physical:            &angularVelocityQuantity,
			baseFieldType:       "FIX32",
		},

		{
			name:                "ROTATION_UFIX16_RPM",
			description:         "Rotational speed, RPM",
			encodingDescription: "Angular rotation in 0.25 rpm",
			resolution:          0.25,
			unit:                "rpm",
			physical:            &angularVelocityQuantity,
			baseFieldType:       "UFIX16",
		},

		{
			name:                "ROTATION_UFIX16_RPM_HIGHRES",
			description:         "Rotational speed, RPM",
			encodingDescription: "Angular rotation in 0.125 rpm",
			resolution:          0.125,
			unit:                "rpm",
			physical:            &angularVelocityQuantity,
			baseFieldType:       "UFIX16",
		},

		{
			name:          "PRESSURE_UFIX16_HPA",
			description:   "Pressure, 16 bit unsigned in hectopascal resolution",
			resolution:    100,
			physical:      &pressureQuantity,
			baseFieldType: "UFIX16",
		},

		{
			name:          "PRESSURE_UINT8_2KPA",
			description:   "Pressure, 8 bit unsigned in 2 kilopascal resolution",
			resolution:    2000,
			physical:      &pressureQuantity,
			baseFieldType: "UINT8",
		},

		{
			name:          "PRESSURE_UINT8_KPA",
			description:   "Pressure, 8 bit unsigned in .5 kilopascal resolution",
			resolution:    500,
			physical:      &pressureQuantity,
			baseFieldType: "UINT8",
		},

		{
			name:          "PRESSURE_UFIX16_KPA",
			description:   "Pressure, 16 bit unsigned in kilopascal resolution.",
			resolution:    1000,
			physical:      &pressureQuantity,
			baseFieldType: "UFIX16",
		},

		{
			name:          "PRESSURE_RATE_FIX16_PA",
			description:   "Pressure change rate, 16 bit signed in pascal resolution.",
			resolution:    1,
			physical:      &pressureRateQuantity,
			baseFieldType: "FIX16",
		},

		{
			name:          "PRESSURE_FIX16_KPA",
			description:   "Pressure, 16 bit signed in kilopascal resolution.",
			resolution:    1000,
			physical:      &pressureQuantity,
			baseFieldType: "FIX16",
		},

		{
			name:          "PRESSURE_UFIX32_DPA",
			description:   "Pressure, 32 bit unsigned in decipascal resolution.",
			resolution:    0.1,
			physical:      &pressureQuantity,
			baseFieldType: "UFIX32",
		},

		{
			name:          "PRESSURE_FIX32_DPA",
			description:   "Pressure, 32 bit signed in decipascal resolution.",
			resolution:    0.1,
			physical:      &pressureQuantity,
			baseFieldType: "FIX32",
		},

		{name: "RADIO_FREQUENCY_UFIX32", description: "Radio frequency", physical: &frequencyQuantity, baseFieldType: "UFIX32"},

		{
			name:                "FREQUENCY_UFIX16",
			description:         "frequency",
			encodingDescription: "Various resolutions are used, ranging from 0.01 Hz to 1 Hz",
			physical:            &frequencyQuantity,
			baseFieldType:       "UFIX16",
		},

		{
			name:          "SPEED_FIX16_MM",
			description:   "Speed, with millimeter resolution",
			resolution:    0.001,
			physical:      &speedQuantity,
			baseFieldType: "FIX16",
		},

		{
			name:          "SPEED_FIX16_CM",
			description:   "Speed, with centimeter resolution",
			resolution:    0.01,
			physical:      &speedQuantity,
			baseFieldType: "FIX16",
		},

		{
			name:          "SPEED_UFIX16_CM",
			description:   "Speed, unsigned, with centimeter resolution",
			resolution:    0.01,
			physical:      &speedQuantity,
			baseFieldType: "UFIX16",
		},

		{
			name:          "SPEED_UFIX16_DM",
			description:   "Speed, unsigned, with decimeter resolution",
			resolution:    0.1,
			physical:      &speedQuantity,
			baseFieldType: "UFIX16",
		},

		{
			name:          "DISTANCE_FIX16_M",
			description:   "Distance, with meter resolution",
			resolution:    1,
			physical:      &distanceQuantity,
			baseFieldType: "FIX16",
		},

		{
			name:          "DISTANCE_FIX16_CM",
			description:   "Distance, with centimeter resolution",
			resolution:    0.01,
			physical:      &distanceQuantity,
			baseFieldType: "FIX16",
		},

		{
			name:          "DISTANCE_FIX16_MM",
			description:   "Distance, with millimeter resolution",
			resolution:    0.001,
			physical:      &distanceQuantity,
			baseFieldType: "FIX16",
		},

		{
			name:          "DISTANCE_FIX32_MM",
			description:   "Distance, high range, with millimeter resolution",
			resolution:    0.001,
			physical:      &distanceQuantity,
			baseFieldType: "FIX32",
		},

		{
			name:          "DISTANCE_FIX32_CM",
			description:   "Distance, high range, with centimeter resolution",
			resolution:    0.01,
			physical:      &distanceQuantity,
			baseFieldType: "FIX32",
		},

		{name: "DISTANCE_FIX64", description: "Distance", resolution: 1e-6, physical: &distanceQuantity, baseFieldType: "FIX64"},

		{name: "GAIN_FIX16", description: "Gain", resolution: 0.01, baseFieldType: "FIX16"},

		{
			name:          "MAGNETIC_FIELD_FIX16",
			description:   "Magnetic field",
			resolution:    0.01,
			physical:      &magneticFieldQuantity,
			baseFieldType: "FIX16",
		},

		{
			name:          "INSTANCE",
			description:   "Instance",
			comment:       "Devices that support multiple sensors TODO",
			baseFieldType: "UINT8",
		},

		{name: "PGN", description: "PRN number", resolution: 1, baseFieldType: "UINT24"},

		{
			name:          "POWER_FACTOR_UFIX16",
			description:   "Power Factor",
			resolution:    1 / 16384.,
			physical:      &powerFactorQuantity,
			baseFieldType: "UFIX16",
		},

		{
			name:          "POWER_FACTOR_UFIX8",
			description:   "Power Factor",
			resolution:    0.01,
			physical:      &powerFactorQuantity,
			baseFieldType: "UFIX8",
		},

		{
			name:        "SIGNED_ALMANAC_PARAMETER",
			description: "Almanac parameter, signed",
			encodingDescription: "These encode various almanac parameters consisting of differing sizes and sign. They are all using an " +
				"interesting resolution/scale, which is always a number of bits that the value is shifted left or " +
				"right. This is reflected by resolution field containing some factor of 2^n or 2^-n.",
			url:           "https://www.gps.gov/technical/icwg/IS-GPS-200N.pdf",
			baseFieldType: "SIGNED_FIXED_POINT_NUMBER",
		},

		{
			name:        "UNSIGNED_ALMANAC_PARAMETER",
			description: "Almanac parameter, unsigned",
			encodingDescription: "These encode various almanac parameters consisting of differing sizes and sign. They are all using an " +
				"interesting resolution/scale, which is always a number of bits that the value is shifted left or " +
				"right. This is reflected by resolution field containing some factor of 2^n or 2^-n.",
			url:           "https://www.gps.gov/technical/icwg/IS-GPS-200N.pdf",
			baseFieldType: "UNSIGNED_FIXED_POINT_NUMBER",
		},

		// Stringy types
		{
			name:        "STRING_FIX",
			description: "A fixed length string containing single byte codepoints.",
			encodingDescription: "The length of the string is determined by the PGN field definition. Trailing bytes have been observed " +
				"as '@', ' ', 0x0 or 0xff.",
			comment: "It is unclear what character sets are allowed/supported. Possibly UTF-8 but it could also be that only ASCII values " +
				"are supported.",
			cf:     convertFieldStringFix,
			pf:     fieldPrintStringFix,
			v1Type: "ASCII text",
		},

		{
			name:        "STRING_LZ",
			description: "A varying length string containing single byte codepoints encoded with a length byte and terminating zero.",
			encodingDescription: "The length of the string is determined by a starting length byte. It also contains a terminating " +
				"zero byte. The length byte includes the zero byte but not itself.",
			comment: "It is unclear what character sets are allowed/supported. Possibly UTF-8 but it could also be that only ASCII values " +
				"are supported.",
			variableSize: true,
			cf:           convertFieldStringLZ,
			pf:           fieldPrintStringLZ,
			v1Type:       "ASCII string starting with length byte",
		},

		{
			name:                "STRING_LAU",
			description:         "A varying length string containing double or single byte codepoints encoded with a length byte and terminating zero.",
			encodingDescription: "The length of the string is determined by a starting length byte. The 2nd byte contains 0 for UNICODE or 1 for ASCII.",
			comment: "It is unclear what character sets are allowed/supported. For single byte, assume ASCII. For UNICODE, assume UTF-16, " +
				"but this has not been seen in the wild yet.",
			variableSize: true,
			cf:           convertFieldStringLAU,
			pf:           fieldPrintStringLAU,
			v1Type:       "ASCII or UNICODE string starting with length and control byte",
		},

		// Others
		{
			name:                "BINARY",
			description:         "Binary field",
			encodingDescription: "Unspecified content consisting of any number of bits.",
			cf:                  convertFieldBinary,
			pf:                  fieldPrintBinary,
			v1Type:              "Binary data",
		},

		{
			name:                "RESERVED",
			description:         "Reserved field",
			encodingDescription: "All reserved bits shall be 1",
			comment:             "NMEA reserved for future expansion and/or to align next data on byte boundary",
			cf:                  convertFieldReserved,
			pf:                  fieldPrintReserved,
		},

		{
			name:                "SPARE",
			description:         "Spare field",
			encodingDescription: "All spare bits shall be 0",
			comment: "This is like a reserved field but originates from other sources where unused fields shall be 0, like the AIS " +
				"ITU-1371 standard.",
			cf: convertFieldSpare,
			pf: fieldPrintSpare,
		},

		{
			name:        "MMSI",
			description: "MMSI",
			resolution:  1,
			size:        32,
			hasSign:     &falseValue,
			rangeMin:    2000000, // Minimal valid MMSI is coastal station (00) MID (2xx)
			rangeMax:    999999999,
			encodingDescription: "The MMSI is encoded as a 32 bit number, but is always printed as a 9 digit number and should be considered as a string. " +
				"The first three or four digits are special, see the USCG link for a detailed explanation.",
			url: "https://navcen.uscg.gov/maritime-mobile-service-identity",
			cf:  convertFieldMMSI,
			pf:  fieldPrintMMSI,
		},

		{
			name:                "VARIABLE",
			description:         "Variable",
			encodingDescription: "The definition of the field is that of the reference PGN and reference field, this is totally variable.",
			cf:                  convertFieldVariable,
			pf:                  fieldPrintVariable,
			pfIsPrintVariable:   true,
		},

		{
			name:        "KEY_VALUE",
			description: "Key/value",
			encodingDescription: "The type definition of the field is defined by an earlier LookupFieldTypeEnumeration field. The length is defined by " +
				"the preceding length field.",
			cf: convertFieldKeyValue,
			pf: fieldPrintKeyValue,
		},

		{
			name:                "FIELD_INDEX",
			description:         "Field Index",
			resolution:          1,
			size:                8,
			hasSign:             &falseValue,
			rangeMin:            1, // Minimum field index (.Order)
			rangeMax:            253,
			encodingDescription: "Index of the specified field in the PGN referenced.",
			cf:                  convertFieldNumber,
			pf:                  fieldPrintNumber,
		},
	}
}
