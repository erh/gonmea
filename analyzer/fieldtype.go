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
	"math"

	"github.com/erh/gonmea/common"
)

type physicalQuantity struct {
	name         string // Name, UPPERCASE_WITH_UNDERSCORE
	description  string // English description, shortish
	comment      string // Other observations
	abbreviation string
	unit         string
	url          string // Website explaining this
}

type fieldPrintFunctionType func(
	ana *Analyzer,
	field *pgnField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error)

type convertFieldFunctionType func(
	ana *Analyzer,
	field *pgnField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (interface{}, bool, error)

type fieldType struct {
	name                string // Name, UPPERCASE_WITH_UNDERSCORE
	description         string // English description, shortish
	encodingDescription string // How the value is encoded
	comment             string // Other observations
	url                 string // Website explaining this
	size                uint32 // Size in bits
	variableSize        bool   // True if size varies per instance of PGN
	baseFieldType       string // Some field types are variations of others
	v1Type              string // Type as printed in v1 xml/json

	// The following are only set for numbers
	unit       string  // String containing the 'Dimension' (e.g. s, h, m/s, etc.)
	offset     int32   // For numbers with excess-K offset
	resolution float64 // A positive real value, or 1 for integral values
	hasSign    *bool   // Is the value signed, e.g. has both positive and negative values?

	// These are derived from size, variableSize, resolution and hasSign
	rangeMin float64
	rangeMax float64

	// How to print this field
	pf                fieldPrintFunctionType
	cf                convertFieldFunctionType
	pfIsPrintVariable bool
	physical          *physicalQuantity

	// Filled by initializer
	baseFieldTypePtr *fieldType
}

func (ana *Analyzer) fillFieldType(doUnitFixup bool) error {
	// Percolate fields from physical quantity to fieldtype
	for i := 0; i < len(ana.fieldTypes); i++ {
		ft := &ana.fieldTypes[i]

		if ft.physical != nil {
			if !isphysicalQuantityListed(ft.physical) {
				return ana.Logger.Abort("FieldType '%s' contains an unlisted physical quantity '%s'\n", ft.name, ft.physical.name)
			}
			if ft.unit == "" {
				ft.unit = ft.physical.abbreviation
				ana.Logger.Debug("Fieldtype '%s' inherits unit '%s' from physical type '%s'\n", ft.name, ft.unit, ft.physical.name)
			}
			if ft.url == "" {
				ft.url = ft.physical.url
			}
		}
	}

	// Percolate fields from base to derived field
	for ftIDx := 0; ftIDx < len(ana.fieldTypes); ftIDx++ {
		ft := &ana.fieldTypes[ftIDx]

		ana.Logger.Debug("filling '%s'\n", ft.name)

		if ft.baseFieldType != "" {
			base, baseIdx := ana.getFieldType(ft.baseFieldType)

			if base == nil {
				return ana.Logger.Abort("invalid baseFieldType '%s' found in FieldType '%s'\n", ft.baseFieldType, ft.name)
			}
			if baseIdx > ftIDx {
				return ana.Logger.Abort("invalid baseFieldType '%s' must be ordered before FieldType '%s'\n", ft.baseFieldType, ft.name)
			}
			ft.baseFieldTypePtr = base

			// Inherit parent fields
			if ft.physical == nil {
				ft.physical = base.physical
			}
			if ft.hasSign == nil && base.hasSign != nil {
				ft.hasSign = base.hasSign
			}
			if ft.unit == "" && base.unit != "" {
				ft.unit = base.unit
				ana.Logger.Debug("Fieldtype '%s' inherits unit '%s' from base type '%s'\n", ft.name, ft.unit, base.name)
			}
			if ft.size == 0 && base.size != 0 {
				ft.size = base.size
				ana.Logger.Debug("Fieldtype '%s' inherits size %d from base type '%s'\n", ft.name, ft.size, base.name)
			}
			if ft.resolution == 0.0 && base.resolution != 0.0 {
				ft.resolution = base.resolution
				ana.Logger.Debug("Fieldtype '%s' inherits resolution %g from base type '%s'\n", ft.name, ft.resolution, base.name)
			} else if ft.resolution != 0.0 && base.resolution != 0.0 && ft.resolution != base.resolution {
				return ana.Logger.Abort("Cannot overrule resolution %g in '%s' with %g in '%s'\n", base.resolution, base.name, ft.resolution, ft.name)
			}
			if ft.pf == nil {
				ft.pf = base.pf
			}
			if ft.cf == nil {
				ft.cf = base.cf
			}
		}

		if ft.pf == nil {
			return ana.Logger.Abort("FieldType '%s' has no print function\n", ft.name)
		}
		if ft.cf == nil {
			return ana.Logger.Abort("FieldType '%s' has no convert function\n", ft.name)
		}

		// Set the field range
		if ft.size != 0 && ft.resolution != 0.0 && ft.hasSign != nil && ft.rangeMax == 0.0 {
			ft.rangeMin = getMinRange(ft.name, ft.size, ft.resolution, ft.hasSign == &trueValue, ft.offset, ana.Logger)
			ft.rangeMax = getMaxRange(ft.name, ft.size, ft.resolution, ft.hasSign == &trueValue, ft.offset, ana.Logger)
		} else {
			ft.rangeMin = math.NaN()
			ft.rangeMax = math.NaN()
		}
	}

	for i := 0; i < len(ana.pgns); i++ {
		pgn := ana.pgns[i].pgn
		pname := ana.pgns[i].description

		var j int
		for j = 0; j < len(ana.pgns[i].fieldList) && ana.pgns[i].fieldList[j].name != ""; j++ {
			f := &ana.pgns[i].fieldList[j]

			if f.fieldType == "" {
				return ana.Logger.Abort("PGN %d '%s' field '%s' contains nil fieldType\n", pgn, pname, f.name)
			}
			ft, _ := ana.getFieldType(f.fieldType)
			if ft == nil {
				return ana.Logger.Abort("PGN %d '%s' field '%s' contains invalid fieldType '%s'\n", pgn, pname, f.name, f.fieldType)
			}
			f.ft = ft

			if (ft.hasSign == &trueValue && !f.hasSign) || (ft.hasSign == &falseValue && f.hasSign) {
				return ana.Logger.Abort(
					"PGN %d '%s' field '%s' contains different sign attribute than fieldType '%s'\n", pgn, pname, f.name, f.fieldType)
			}

			if f.resolution == 0.0 {
				f.resolution = ft.resolution
			}
			if ft.resolution != 0.0 && ft.resolution != f.resolution {
				return ana.Logger.Abort("Cannot overrule resolution %g in '%s' with %g in PGN %d field '%s'\n",
					ft.resolution,
					ft.name,
					f.resolution,
					ana.pgns[i].pgn,
					f.name)
			}

			if ft.size != 0 && f.size == 0 {
				f.size = ft.size
			}
			if ft.size != 0 && ft.size != f.size {
				return ana.Logger.Abort(
					"Cannot overrule size %d in '%s' with %d in PGN %d field '%s'\n", ft.size, ft.name, f.size, ana.pgns[i].pgn, f.name)
			}

			if ft.offset != 0 && f.offset == 0 {
				f.offset = ft.offset
			}
			if ft.offset != f.offset {
				return ana.Logger.Abort("Cannot overrule offset %d in '%s' with %d in PGN %d field '%s'\n",
					ft.offset,
					ft.name,
					f.offset,
					ana.pgns[i].pgn,
					f.name)
			}

			if ft.unit != "" && f.unit == "" {
				f.unit = ft.unit
			}
			if f.unit != "" && ft.unit != "" && f.unit != ft.unit && !(f.unit == "deg" && ft.unit == "rad") {
				return ana.Logger.Abort("PGN %d '%s' field '%s' contains different unit attribute ('%s') than fieldType '%s' ('%s')\n",
					pgn,
					pname,
					f.name,
					f.unit,
					f.fieldType,
					ft.unit)
			}

			if math.IsNaN(f.rangeMax) || f.rangeMax == 0.0 {
				f.rangeMin = ft.rangeMin
				f.rangeMax = ft.rangeMax
			}
			if doUnitFixup && f.unit != "" && f.resolution != 0.0 {
				ana.fixupUnit(f)
			}
			if f.unit != "" && f.unit[0] == '=' { // Is a match field
				ana.pgns[i].hasMatchFields = true
			}

			ana.Logger.Debug("%s size=%d res=%g sign=%v rangeMax=%g\n", f.name, f.size, f.resolution, ft.hasSign, f.rangeMax)

			if f.size != 0 && f.resolution != 0.0 && ft.hasSign != nil && math.IsNaN(f.rangeMax) {
				f.rangeMin = getMinRange(f.name, f.size, f.resolution, f.hasSign, f.offset, ana.Logger)
				f.rangeMax = getMaxRange(f.name, f.size, f.resolution, f.hasSign, f.offset, ana.Logger)
			}

			f.pgn = &ana.pgns[i]
			f.order = uint8(j + 1)
		}
		if ana.pgns[i].packetType == packetTypeFast && !common.AllowPGNFastPacket(pgn) {
			return ana.Logger.Abort("PGN %d '%s' is outside fast-packet range\n", pgn, ana.pgns[i].description)
		}
		if ana.pgns[i].packetType != packetTypeFast && !common.AllowPGNSingleFrame(pgn) {
			//nolint:errcheck
			ana.Logger.Error("PGN %d '%s' is outside single-frame range\n", pgn, ana.pgns[i].description)
		}
		if ana.pgns[i].repeatingCount1 != 0 && ana.pgns[i].repeatingStart1 == 0 {
			return ana.Logger.Abort("PGN %d '%s' has no way to determine repeating field set 1\n", pgn, ana.pgns[i].description)
		}
		if ana.pgns[i].repeatingCount2 != 0 && ana.pgns[i].repeatingStart2 == 0 {
			return ana.Logger.Abort("PGN %d '%s' has no way to determine repeating field set 2\n", pgn, ana.pgns[i].description)
		}

		if ana.pgns[i].interval == 0 {
			ana.pgns[i].complete |= packetStatusIntervalUnknown
		}

		if j == 0 && ana.pgns[i].complete == packetStatusComplete {
			return ana.Logger.Error("Internal error: PGN %d '%s' does not have fields.\n", ana.pgns[i].pgn, ana.pgns[i].description)
		}
		ana.pgns[i].fieldCount = uint32(j)
		ana.Logger.Debug("PGN %d '%s' has %d fields\n", ana.pgns[i].pgn, pname, j)
	}

	ana.Logger.Debug("Filled all fieldtypes\n")
	return nil
}

func (ana *Analyzer) getFieldType(name string) (*fieldType, int) {
	for i := 0; i < len(ana.fieldTypes); i++ {
		if name == ana.fieldTypes[i].name {
			return &ana.fieldTypes[i], i
		}
	}
	//nolint:errcheck
	ana.Logger.Error("fieldType '%s' not found\n", name)
	return nil, 0
}

const radianToDegree = (360.0 / 2 / math.Pi)

func (ana *Analyzer) fixupUnit(f *pgnField) {
	if ana.showSI {
		if f.unit == "kWh" {
			f.resolution *= 3.6e6 // 1 kWh = 3.6 MJ.
			f.rangeMin *= 3.6e6
			f.rangeMax *= 3.6e6
			f.unit = "J"
		} else if f.unit == "Ah" {
			f.resolution *= 3600.0 // 1 Ah = 3600 C.
			f.rangeMin *= 3600.0
			f.rangeMax *= 3600.0
			f.unit = "C"
		}

		// Many more to follow, but pgn.h is not yet complete enough...
	} else { // NOT SI
		switch f.unit {
		case "C":
			f.resolution /= 3600.0 // 3600 C = 1 Ah
			f.rangeMin /= 3600.0
			f.rangeMax /= 3600.0
			f.unit = "Ah"
			ana.Logger.Debug("fixup <%s> to '%s'\n", f.name, f.unit)
		case "Pa":
			f.resolution /= 100000.0
			f.rangeMin /= 100000.0
			f.rangeMax /= 100000.0
			f.precision = 3
			f.unit = "bar"
			ana.Logger.Debug("fixup <%s> to '%s'\n", f.name, f.unit)
		case "K":
			f.unitOffset = -273.15
			f.rangeMin += -273.15
			f.rangeMax += -275.15
			f.precision = 2
			f.unit = "C"
			ana.Logger.Debug("fixup <%s> to '%s'\n", f.name, f.unit)
		case "rad":
			f.resolution *= radianToDegree
			f.rangeMin *= radianToDegree
			f.rangeMax *= radianToDegree
			f.unit = "deg"
			f.precision = 1
			ana.Logger.Debug("fixup <%s> to '%s'\n", f.name, f.unit)
		case "rad/s":
			f.resolution *= radianToDegree
			f.rangeMin *= radianToDegree
			f.rangeMax *= radianToDegree
			f.unit = "deg/s"
			ana.Logger.Debug("fixup <%s> to '%s'\n", f.name, f.unit)
		}
	}
}

func getMinRange(name string, size uint32, resolution float64, sign bool, offset int32, logger *common.Logger) float64 {
	highbit := size
	if sign && offset == 0 {
		highbit = (size - 1)
	}
	var minValue int64
	var r float64

	if !sign || offset != 0 {
		minValue = int64(0) + int64(offset)
		r = float64(minValue) * resolution
	} else {
		minValue = int64((uint64(1) << highbit) - 1)
		r = float64(minValue) * resolution * -1.0
	}
	logger.Debug(
		"%s bits=%d sign=%t minValue=%d res=%g offset=%d . rangeMin %g\n", name, highbit, sign, minValue, resolution, offset, r)
	return r
}

func getMaxRange(
	name string,
	size uint32,
	resolution float64,
	sign bool,
	offset int32,
	logger *common.Logger,
) float64 {
	specialvalues := uint64(0)
	if size >= 4 {
		specialvalues = 2
	} else if size >= 2 {
		specialvalues = 1
	}
	highbit := size
	if sign && offset == 0 {
		highbit = size - 1
	}

	maxValue := (uint64(1) << highbit) - 1 - specialvalues
	if offset != 0 {
		maxValue += uint64(offset)
	}

	r := float64(maxValue) * resolution
	logger.Debug(
		"%s bits=%d sign=%t maxValue=%d res=%g offset=%d . rangeMax %g\n", name, highbit, sign, maxValue, resolution, offset, r)
	return r
}

func isphysicalQuantityListed(pq *physicalQuantity) bool {
	for i := 0; i < len(physicalQuantityList); i++ {
		if physicalQuantityList[i] == pq {
			return true
		}
	}
	return false
}

var (
	electricalCurrentQuantity = physicalQuantity{
		name:         "ELECTRICAL_CURRENT",
		description:  "Electrical current",
		abbreviation: "A",
		unit:         "Ampere",
		url:          "https://en.wikipedia.org/wiki/Electric_current",
	}

	electricalChargeQuantity = physicalQuantity{
		name:         "ELECTRICAL_CHARGE",
		description:  "Electrical charge",
		abbreviation: "C",
		unit:         "Coulomb",
		url:          "https://en.wikipedia.org/wiki/Electric_charge",
	}

	electricalEnergyQuantity = physicalQuantity{
		name:        "ELECTRICAL_ENERGY",
		description: "Electrical energy",
		comment: "The amount of electricity used or stored. The base unit used in NMEA 2000 is the Kilo Watt Hour (kWh) which is " +
			"equivalent to 3.6e6 J (Joules).",
		unit:         "Kilo Watt Hour",
		abbreviation: "kWh",
		url:          "https://en.wikipedia.org/wiki/Electrical_energy",
	}

	electricalPowerQuantity = physicalQuantity{
		name:         "ELECTRICAL_POWER",
		description:  "Electrical power",
		comment:      "The amount of energy transferred or converted per unit time.",
		unit:         "Watt",
		abbreviation: "W",
		url:          "https://en.wikipedia.org/wiki/Electrical_power",
	}

	electricalApparentPowerQuantity = physicalQuantity{
		name:         "ELECTRICAL_APPARENT_POWER",
		description:  "AC apparent power",
		comment:      "The amount of power transferred where the current and voltage are in phase.",
		unit:         "Volt Ampere",
		abbreviation: "VA",
		url:          "https://en.wikipedia.org/wiki/Volt-ampere",
	}

	electricalReactivePowerQuantity = physicalQuantity{
		name:         "ELECTRICAL_REACTIVE_POWER",
		description:  "AC reactive power",
		comment:      "The amount of power transferred where the current and voltage are not in phase.",
		unit:         "Volt Ampere Reactive",
		abbreviation: "VAR",
		url:          "https://en.wikipedia.org/wiki/Volt-ampere#Reactive",
	}

	potentialDifferenceQuantity = physicalQuantity{
		name:         "POTENTIAL_DIFFERENCE",
		description:  "Potential difference",
		abbreviation: "V",
		unit:         "Volt",
		url:          "https://en.wikipedia.org/wiki/Voltage",
	}

	powerFactorQuantity = physicalQuantity{
		name:        "POWER_FACTOR",
		description: "Power Factor",
		comment: "Used in AC circuits only, the ratio of the real power absorbed by the load to the apparent power flowing in the " +
			"circuit. If less than one, the voltage and current are not in phase.",
		unit:         "Cos(Phi)",
		abbreviation: "Cos Phi",
		url:          "https://en.wikipedia.org/wiki/Power_factor",
	}

	lengthQuantity = physicalQuantity{
		name:         "LENGTH",
		description:  "Length",
		comment:      "The physical size in one dimension of an object.",
		unit:         "Meter",
		abbreviation: "m",
		url:          "https://en.wikipedia.org/wiki/Length",
	}

	distanceQuantity = physicalQuantity{
		name:         "DISTANCE",
		description:  "Distance",
		comment:      "The amount of separation between two objects.",
		unit:         "meter",
		abbreviation: "m",
		url:          "https://en.wikipedia.org/wiki/Distance",
	}

	speedQuantity = physicalQuantity{
		name:         "SPEED",
		description:  "Speed",
		comment:      "The velocity, or length per unit of time.",
		abbreviation: "m/s",
		unit:         "meter per second",
		url:          "https://en.wikipedia.org/wiki/Speed",
	}

	angleQuantity = physicalQuantity{
		name:         "ANGLE",
		description:  "Angle",
		comment:      "All standardized PGNs seen so far all use radians, but some manufacturer specific PGNs use degrees (deg).",
		url:          "https://en.wikipedia.org/wiki/Angle",
		abbreviation: "rad",
		unit:         "radian",
	}

	angleDegQuantity = physicalQuantity{
		name:         "ANGLE_DEG",
		description:  "Angle",
		url:          "https://en.wikipedia.org/wiki/Angle",
		abbreviation: "deg",
		unit:         "degree",
	}

	angularVelocityQuantity = physicalQuantity{
		name:         "ANGULAR_VELOCITY",
		description:  "Angular velocity",
		comment:      "The speed at which a measured angle changes",
		url:          "https://en.wikipedia.org/wiki/Angular_velocity",
		abbreviation: "rad/s",
		unit:         "radians per second",
	}

	volumeQuantity = physicalQuantity{
		name:         "VOLUME",
		description:  "Volume",
		comment:      "A measure of occupied three-dimensional space.",
		url:          "https://en.wikipedia.org/wiki/Volume",
		abbreviation: "L",
		unit:         "liter",
	}

	volumetricFlowQuantity = physicalQuantity{
		name:         "VOLUMETRIC_FLOW",
		description:  "Volumetric flow",
		comment:      "The volume of fluid which passes per unit time.",
		abbreviation: "L/h",
		unit:         "liter per hour",
		url:          "https://en.wikipedia.org/wiki/Volumetric_flow_rate",
	}

	frequencyQuantity = physicalQuantity{
		name:         "FREQUENCY",
		description:  "Frequency",
		abbreviation: "Hz",
		unit:         "Hertz",
		url:          "https://en.wikipedia.org/wiki/Radio_frequency",
	}

	dateQuantity = physicalQuantity{
		name:        "DATE",
		description: "Date",
		comment: "A calendar date is a reference to a particular day in time, in NMEA 2000 " +
			"expressed as the number of days since 1970-01-01 (UNIX epoch).",
		abbreviation: "d",
		unit:         "days",
		url:          "https://en.wikipedia.org/wiki/Calendar_date",
	}

	timeQuantity = physicalQuantity{
		name:        "TIME",
		description: "Time",
		comment: "Time is what clocks measure. We use time to place events in sequence one after the other, and we use time to compare how " +
			"long events last. Absolute times in NMEA2000 are expressed as seconds since midnight(in an undefined timezone)",
		url:          "https://en.wikipedia.org/wiki/Time",
		abbreviation: "s",
		unit:         "Second",
	}

	magneticFieldQuantity = physicalQuantity{
		name:         "MAGNETIC_FIELD",
		description:  "Magnetic field",
		unit:         "Tesla",
		abbreviation: "T",
		url:          "https://en.wikipedia.org/wiki/Magnetic_field",
	}

	geoCoordinateQuantity = physicalQuantity{
		name:         "GEOGRAPHICAL_COORDINATE",
		description:  "Geographical coordinate",
		comment:      "Latitude or longitude. Combined they form a unique point on earth, when height is disregarded.",
		abbreviation: "deg",
		unit:         "degree",
		url:          "https://en.wikipedia.org/wiki/Geographic_coordinate_system",
	}

	temperatureQuantity = physicalQuantity{
		name:         "TEMPERATURE",
		description:  "Temperature",
		unit:         "Kelvin",
		abbreviation: "K",
		url:          "https://en.wikipedia.org/wiki/Temperature",
	}

	pressureQuantity = physicalQuantity{
		name:         "PRESSURE",
		description:  "Pressure",
		abbreviation: "Pa",
		unit:         "Pascal",
		url:          "https://en.wikipedia.org/wiki/Pressure",
	}

	pressureRateQuantity = physicalQuantity{
		name:         "PRESSURE_RATE",
		description:  "Pressure rate",
		comment:      "How the pressure changes over time.",
		abbreviation: "Pa/hr",
		unit:         "Pascal per hour",
		url:          "https://en.wikipedia.org/wiki/Pressure",
	}

	concentrationQuantity = physicalQuantity{
		name:         "CONCENTRATION",
		description:  "Concentration of one substance in another, in this marine context usually the amount of salts in water",
		url:          "https://www.engineeringtoolbox.com/water-salinity-d_1251.html",
		unit:         "parts per million",
		abbreviation: "ppm",
	}

	signalToNoiseRatioQuantity = physicalQuantity{
		name:         "SIGNAL_TO_NOISE_RATIO",
		description:  "Signal-to-noise ratio",
		url:          "https://en.wikipedia.org/wiki/Signal-to-noise_ratio",
		abbreviation: "dB",
		unit:         "decibel",
	}
)

var physicalQuantityList = []*physicalQuantity{
	&electricalCurrentQuantity,
	&electricalChargeQuantity,
	&electricalEnergyQuantity,
	&electricalPowerQuantity,
	&electricalApparentPowerQuantity,
	&electricalReactivePowerQuantity,
	&potentialDifferenceQuantity,
	&powerFactorQuantity,
	&lengthQuantity,
	&distanceQuantity,
	&speedQuantity,
	&angleQuantity,
	&angleDegQuantity,
	&angularVelocityQuantity,
	&volumeQuantity,
	&volumetricFlowQuantity,
	&magneticFieldQuantity,
	&frequencyQuantity,
	&dateQuantity,
	&timeQuantity,
	&geoCoordinateQuantity,
	&temperatureQuantity,
	&pressureQuantity,
	&pressureRateQuantity,
	&concentrationQuantity,
	&signalToNoiseRatioQuantity,
}

func (ana *Analyzer) fillFieldTypeLookupField(
	f *pgnField,
	lookup string,
	key int,
	str string,
	ft string,
) error {
	f.ft, _ = ana.getFieldType(ft)
	if f.ft == nil {
		return ana.Logger.Abort("LookupFieldType %s(%d) contains an invalid fieldtype '%s'\n", lookup, key, ft)
	}
	f.unit = f.ft.unit
	f.resolution = f.ft.resolution
	f.hasSign = f.ft.hasSign == &trueValue
	if f.size == 0 {
		f.size = f.ft.size
	}
	f.name = str
	if f.unit != "" {
		ana.fixupUnit(f)
	}

	unitStr := f.unit
	if unitStr == "" {
		unitStr = "NULL"
	}
	ana.Logger.Debug("fillFieldTypeLookupField(Field, lookup='%s', key=%d, str='%s', ft='%s' unit='%s' bits=%d\n",
		lookup,
		key,
		str,
		ft,
		unitStr,
		f.size)
	return nil
}
