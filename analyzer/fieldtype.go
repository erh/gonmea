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

	"go.viam.com/rdk/logging"

	"github.com/erh/gonmea/common"
)

type PhysicalQuantity struct {
	Name         string // Name, UPPERCASE_WITH_UNDERSCORE
	Description  string // English Description, shortish
	Comment      string // Other observations
	Abbreviation string
	Unit         string
	URL          string // Website explaining this
}

type fieldPrintFunctionType func(
	p Printer,
	field *PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error)

type convertFieldFunctionType func(
	ana *analyzerImpl,
	field *PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (interface{}, bool, error)

type FieldType struct {
	Name                string // Name, UPPERCASE_WITH_UNDERSCORE
	Description         string // English description, shortish
	EncodingDescription string // How the value is encoded
	Comment             string // Other observations
	URL                 string // Website explaining this
	Size                uint32 // Size in bits
	VariableSize        bool   // True if size varies per instance of PGN
	BaseFieldType       string // Some field types are variations of others
	V1Type              string // Type as printed in v1 xml/json

	// The following are only set for numbers
	Unit       string  // String containing the 'Dimension' (e.g. s, h, m/s, etc.)
	Offset     int32   // For numbers with excess-K Offset
	Resolution float64 // A positive real value, or 1 for integral values
	HasSign    *bool   // Is the value signed, e.g. has both positive and negative values?

	// These are derived from size, variableSize, Resolution and HasSign
	RangeMin float64
	RangeMax float64

	// How to print this field
	PF                fieldPrintFunctionType
	CF                convertFieldFunctionType
	PFIsPrintVariable bool
	Physical          *PhysicalQuantity

	// Filled by initializer
	BaseFieldTypePtr *FieldType
}

func (ana *analyzerImpl) fillFieldType(doUnitFixup bool) error {
	// Percolate fields from Physical quantity to Fieldtype
	for i := 0; i < len(ana.state.FieldTypes); i++ {
		ft := &ana.state.FieldTypes[i]

		if ft.Physical != nil {
			if !isPhysicalQuantityListed(ft.Physical) {
				return fmt.Errorf("FieldType '%s' contains an unlisted Physical quantity '%s'", ft.Name, ft.Physical.Name)
			}
			if ft.Unit == "" {
				ft.Unit = ft.Physical.Abbreviation
				ana.Logger.Debugf("Fieldtype '%s' inherits Unit '%s' from Physical type '%s'", ft.Name, ft.Unit, ft.Physical.Name)
			}
			if ft.URL == "" {
				ft.URL = ft.Physical.URL
			}
		}
	}

	// Percolate fields from base to derived field
	for ftIDx := 0; ftIDx < len(ana.state.FieldTypes); ftIDx++ {
		ft := &ana.state.FieldTypes[ftIDx]

		ana.Logger.Debugf("filling '%s'", ft.Name)

		if ft.BaseFieldType != "" {
			base, baseIdx := ana.GetFieldType(ft.BaseFieldType)

			if base == nil {
				return fmt.Errorf("invalid BaseFieldType '%s' found in FieldType '%s'", ft.BaseFieldType, ft.Name)
			}
			if baseIdx > ftIDx {
				return fmt.Errorf("invalid BaseFieldType '%s' must be ordered before FieldType '%s'", ft.BaseFieldType, ft.Name)
			}
			ft.BaseFieldTypePtr = base

			// Inherit parent fields
			if ft.Physical == nil {
				ft.Physical = base.Physical
			}
			if ft.HasSign == nil && base.HasSign != nil {
				ft.HasSign = base.HasSign
			}
			if ft.Unit == "" && base.Unit != "" {
				ft.Unit = base.Unit
				ana.Logger.Debugf("Fieldtype '%s' inherits Unit '%s' from base type '%s'", ft.Name, ft.Unit, base.Name)
			}
			if ft.Size == 0 && base.Size != 0 {
				ft.Size = base.Size
				ana.Logger.Debugf("Fieldtype '%s' inherits size %d from base type '%s'", ft.Name, ft.Size, base.Name)
			}
			if ft.Resolution == 0.0 && base.Resolution != 0.0 {
				ft.Resolution = base.Resolution
				ana.Logger.Debugf("Fieldtype '%s' inherits Resolution %g from base type '%s'", ft.Name, ft.Resolution, base.Name)
			} else if ft.Resolution != 0.0 && base.Resolution != 0.0 && ft.Resolution != base.Resolution {
				return fmt.Errorf("Cannot overrule Resolution %g in '%s' with %g in '%s'", base.Resolution, base.Name, ft.Resolution, ft.Name)
			}
			if ft.PF == nil {
				ft.PF = base.PF
			}
			if ft.CF == nil {
				ft.CF = base.CF
			}
		}

		if ft.PF == nil {
			return fmt.Errorf("FieldType '%s' has no print function", ft.Name)
		}
		if ft.CF == nil {
			return fmt.Errorf("FieldType '%s' has no convert function", ft.Name)
		}

		// Set the field range
		if ft.Size != 0 && ft.Resolution != 0.0 && ft.HasSign != nil && ft.RangeMax == 0.0 {
			ft.RangeMin = getMinRange(ft.Name, ft.Size, ft.Resolution, ft.HasSign == &trueValue, ft.Offset, ana.Logger)
			ft.RangeMax = getMaxRange(ft.Name, ft.Size, ft.Resolution, ft.HasSign == &trueValue, ft.Offset, ana.Logger)
		} else {
			ft.RangeMin = math.NaN()
			ft.RangeMax = math.NaN()
		}
	}

	for i := 0; i < len(ana.state.PGNs); i++ {
		pgn := ana.state.PGNs[i].PGN
		pName := ana.state.PGNs[i].Description

		var j int
		for j = 0; j < len(ana.state.PGNs[i].FieldList) && ana.state.PGNs[i].FieldList[j].Name != ""; j++ {
			f := &ana.state.PGNs[i].FieldList[j]

			if f.FieldType == "" {
				return fmt.Errorf("PGN %d '%s' field '%s' contains nil FieldType", pgn, pName, f.Name)
			}
			ft, _ := ana.GetFieldType(f.FieldType)
			if ft == nil {
				return fmt.Errorf("PGN %d '%s' field '%s' contains invalid FieldType '%s'", pgn, pName, f.Name, f.FieldType)
			}
			f.FT = ft

			if (ft.HasSign == &trueValue && !f.HasSign) || (ft.HasSign == &falseValue && f.HasSign) {
				return fmt.Errorf("PGN %d '%s' field '%s' contains different sign attribute than FieldType '%s'", pgn, pName, f.Name, f.FieldType)
			}

			if f.Resolution == 0.0 {
				f.Resolution = ft.Resolution
			}
			if ft.Resolution != 0.0 && ft.Resolution != f.Resolution {
				return fmt.Errorf("Cannot overrule Resolution %g in '%s' with %g in PGN %d field '%s'",
					ft.Resolution,
					ft.Name,
					f.Resolution,
					ana.state.PGNs[i].PGN,
					f.Name)
			}

			if ft.Size != 0 && f.Size == 0 {
				f.Size = ft.Size
			}
			if ft.Size != 0 && ft.Size != f.Size {
				return fmt.Errorf("Cannot overrule size %d in '%s' with %d in PGN %d field '%s'", ft.Size, ft.Name, f.Size, ana.state.PGNs[i].PGN, f.Name)
			}

			if ft.Offset != 0 && f.Offset == 0 {
				f.Offset = ft.Offset
			}
			if ft.Offset != f.Offset {
				return fmt.Errorf("Cannot overrule Offset %d in '%s' with %d in PGN %d field '%s'",
					ft.Offset,
					ft.Name,
					f.Offset,
					ana.state.PGNs[i].PGN,
					f.Name)
			}

			if ft.Unit != "" && f.Unit == "" {
				f.Unit = ft.Unit
			}
			if f.Unit != "" && ft.Unit != "" && f.Unit != ft.Unit && !(f.Unit == "deg" && ft.Unit == "rad") {
				return fmt.Errorf("PGN %d '%s' field '%s' contains different Unit attribute ('%s') than FieldType '%s' ('%s')",
					pgn,
					pName,
					f.Name,
					f.Unit,
					f.FieldType,
					ft.Unit)
			}

			if math.IsNaN(f.RangeMax) || f.RangeMax == 0.0 {
				f.RangeMin = ft.RangeMin
				f.RangeMax = ft.RangeMax
			}
			if doUnitFixup && f.Unit != "" && f.Resolution != 0.0 {
				ana.fixupUnit(f)
			}
			if f.Unit != "" && f.Unit[0] == '=' { // Is a match field
				ana.state.PGNs[i].HasMatchFields = true
			}

			ana.Logger.Debugf("%s size=%d res=%g sign=%v RangeMax=%g", f.Name, f.Size, f.Resolution, ft.HasSign, f.RangeMax)

			if f.Size != 0 && f.Resolution != 0.0 && ft.HasSign != nil && math.IsNaN(f.RangeMax) {
				f.RangeMin = getMinRange(f.Name, f.Size, f.Resolution, f.HasSign, f.Offset, ana.Logger)
				f.RangeMax = getMaxRange(f.Name, f.Size, f.Resolution, f.HasSign, f.Offset, ana.Logger)
			}

			f.PGN = &ana.state.PGNs[i]
			f.Order = uint8(j + 1)
		}
		if ana.state.PGNs[i].PacketType == PacketTypeFast && !common.AllowPGNFastPacket(pgn) {
			return fmt.Errorf("PGN %d '%s' is outside fast-packet range", pgn, ana.state.PGNs[i].Description)
		}
		if ana.state.PGNs[i].PacketType != PacketTypeFast && !common.AllowPGNSingleFrame(pgn) {
			ana.Logger.Errorf("PGN %d '%s' is outside single-frame range", pgn, ana.state.PGNs[i].Description)
		}
		if ana.state.PGNs[i].RepeatingCount1 != 0 && ana.state.PGNs[i].RepeatingStart1 == 0 {
			return fmt.Errorf("PGN %d '%s' has no way to determine repeating field set 1", pgn, ana.state.PGNs[i].Description)
		}
		if ana.state.PGNs[i].RepeatingCount2 != 0 && ana.state.PGNs[i].RepeatingStart2 == 0 {
			return fmt.Errorf("PGN %d '%s' has no way to determine repeating field set 2", pgn, ana.state.PGNs[i].Description)
		}

		if ana.state.PGNs[i].Interval == 0 {
			ana.state.PGNs[i].Complete |= PacketStatusIntervalUnknown
		}

		if j == 0 && ana.state.PGNs[i].Complete == PacketStatusComplete {
			return fmt.Errorf("Internal error: PGN %d '%s' does not have fields.", ana.state.PGNs[i].PGN, ana.state.PGNs[i].Description)
		}
		ana.state.PGNs[i].FieldCount = uint32(j)
		ana.Logger.Debugf("PGN %d '%s' has %d fields", ana.state.PGNs[i].PGN, pName, j)
	}

	ana.Logger.Debug("Filled all Fieldtypes")
	return nil
}

func (ana *analyzerImpl) GetFieldType(name string) (*FieldType, int) {
	for i := 0; i < len(ana.state.FieldTypes); i++ {
		if name == ana.state.FieldTypes[i].Name {
			return &ana.state.FieldTypes[i], i
		}
	}
	ana.Logger.Errorf("FieldType '%s' not found", name)
	return nil, 0
}

const radianToDegree = (360.0 / 2 / math.Pi)

func (ana *analyzerImpl) fixupUnit(f *PGNField) {
	if ana.UseSI {
		if f.Unit == "kWh" {
			f.Resolution *= 3.6e6 // 1 kWh = 3.6 MJ.
			f.RangeMin *= 3.6e6
			f.RangeMax *= 3.6e6
			f.Unit = "J"
		} else if f.Unit == "Ah" {
			f.Resolution *= 3600.0 // 1 Ah = 3600 C.
			f.RangeMin *= 3600.0
			f.RangeMax *= 3600.0
			f.Unit = "C"
		}

		// Many more to follow, but pgn.h is not yet Complete enough...
	} else { // NOT SI
		switch f.Unit {
		case "C":
			f.Resolution /= 3600.0 // 3600 C = 1 Ah
			f.RangeMin /= 3600.0
			f.RangeMax /= 3600.0
			f.Unit = "Ah"
			ana.Logger.Debugf("fixup <%s> to '%s'", f.Name, f.Unit)
		case "Pa":
			f.Resolution /= 100000.0
			f.RangeMin /= 100000.0
			f.RangeMax /= 100000.0
			f.Precision = 3
			f.Unit = "bar"
			ana.Logger.Debugf("fixup <%s> to '%s'", f.Name, f.Unit)
		case "K":
			f.UnitOffset = -273.15
			f.RangeMin += -273.15
			f.RangeMax += -275.15
			f.Precision = 2
			f.Unit = "C"
			ana.Logger.Debugf("fixup <%s> to '%s'", f.Name, f.Unit)
		case "rad":
			f.Resolution *= radianToDegree
			f.RangeMin *= radianToDegree
			f.RangeMax *= radianToDegree
			f.Unit = "deg"
			f.Precision = 1
			ana.Logger.Debugf("fixup <%s> to '%s'", f.Name, f.Unit)
		case "rad/s":
			f.Resolution *= radianToDegree
			f.RangeMin *= radianToDegree
			f.RangeMax *= radianToDegree
			f.Unit = "deg/s"
			ana.Logger.Debugf("fixup <%s> to '%s'", f.Name, f.Unit)
		}
	}
}

func getMinRange(name string, size uint32, resolution float64, sign bool, offset int32, logger logging.Logger) float64 {
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
	logger.Debugf(
		"%s bits=%d sign=%t minValue=%d res=%g offset=%d . rangeMin %g", name, highbit, sign, minValue, resolution, offset, r)
	return r
}

func getMaxRange(
	name string,
	size uint32,
	resolution float64,
	sign bool,
	offset int32,
	logger logging.Logger,
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
	logger.Debugf(
		"%s bits=%d sign=%t maxValue=%d res=%g offset=%d . rangeMax %g", name, highbit, sign, maxValue, resolution, offset, r)
	return r
}

func isPhysicalQuantityListed(pq *PhysicalQuantity) bool {
	for i := 0; i < len(PhysicalQuantityList); i++ {
		if PhysicalQuantityList[i] == pq {
			return true
		}
	}
	return false
}

var (
	electricalCurrentQuantity = PhysicalQuantity{
		Name:         "ELECTRICAL_CURRENT",
		Description:  "Electrical current",
		Abbreviation: "A",
		Unit:         "Ampere",
		URL:          "https://en.wikipedia.org/wiki/Electric_current",
	}

	electricalChargeQuantity = PhysicalQuantity{
		Name:         "ELECTRICAL_CHARGE",
		Description:  "Electrical charge",
		Abbreviation: "C",
		Unit:         "Coulomb",
		URL:          "https://en.wikipedia.org/wiki/Electric_charge",
	}

	electricalEnergyQuantity = PhysicalQuantity{
		Name:        "ELECTRICAL_ENERGY",
		Description: "Electrical energy",
		Comment: "The amount of electricity used or stored. The base Unit used in NMEA 2000 is the Kilo Watt Hour (kWh) which is " +
			"equivalent to 3.6e6 J (Joules).",
		Unit:         "Kilo Watt Hour",
		Abbreviation: "kWh",
		URL:          "https://en.wikipedia.org/wiki/Electrical_energy",
	}

	electricalPowerQuantity = PhysicalQuantity{
		Name:         "ELECTRICAL_POWER",
		Description:  "Electrical power",
		Comment:      "The amount of energy transferred or converted per Unit time.",
		Unit:         "Watt",
		Abbreviation: "W",
		URL:          "https://en.wikipedia.org/wiki/Electrical_power",
	}

	electricalApparentPowerQuantity = PhysicalQuantity{
		Name:         "ELECTRICAL_APPARENT_POWER",
		Description:  "AC apparent power",
		Comment:      "The amount of power transferred where the current and voltage are in phase.",
		Unit:         "Volt Ampere",
		Abbreviation: "VA",
		URL:          "https://en.wikipedia.org/wiki/Volt-ampere",
	}

	electricalReactivePowerQuantity = PhysicalQuantity{
		Name:         "ELECTRICAL_REACTIVE_POWER",
		Description:  "AC reactive power",
		Comment:      "The amount of power transferred where the current and voltage are not in phase.",
		Unit:         "Volt Ampere Reactive",
		Abbreviation: "VAR",
		URL:          "https://en.wikipedia.org/wiki/Volt-ampere#Reactive",
	}

	potentialDifferenceQuantity = PhysicalQuantity{
		Name:         "POTENTIAL_DIFFERENCE",
		Description:  "Potential difference",
		Abbreviation: "V",
		Unit:         "Volt",
		URL:          "https://en.wikipedia.org/wiki/Voltage",
	}

	powerFactorQuantity = PhysicalQuantity{
		Name:        "POWER_FACTOR",
		Description: "Power Factor",
		Comment: "Used in AC circuits only, the ratio of the real power absorbed by the load to the apparent power flowing in the " +
			"circuit. If less than one, the voltage and current are not in phase.",
		Unit:         "Cos(Phi)",
		Abbreviation: "Cos Phi",
		URL:          "https://en.wikipedia.org/wiki/Power_factor",
	}

	lengthQuantity = PhysicalQuantity{
		Name:         "LENGTH",
		Description:  "Length",
		Comment:      "The Physical size in one dimension of an object.",
		Unit:         "Meter",
		Abbreviation: "m",
		URL:          "https://en.wikipedia.org/wiki/Length",
	}

	distanceQuantity = PhysicalQuantity{
		Name:         "DISTANCE",
		Description:  "Distance",
		Comment:      "The amount of separation between two objects.",
		Unit:         "meter",
		Abbreviation: "m",
		URL:          "https://en.wikipedia.org/wiki/Distance",
	}

	speedQuantity = PhysicalQuantity{
		Name:         "SPEED",
		Description:  "Speed",
		Comment:      "The velocity, or length per Unit of time.",
		Abbreviation: "m/s",
		Unit:         "meter per second",
		URL:          "https://en.wikipedia.org/wiki/Speed",
	}

	angleQuantity = PhysicalQuantity{
		Name:         "ANGLE",
		Description:  "Angle",
		Comment:      "All standardized PGNs seen so far all use radians, but some manufacturer specific PGNs use degrees (deg).",
		URL:          "https://en.wikipedia.org/wiki/Angle",
		Abbreviation: "rad",
		Unit:         "radian",
	}

	angleDegQuantity = PhysicalQuantity{
		Name:         "ANGLE_DEG",
		Description:  "Angle",
		URL:          "https://en.wikipedia.org/wiki/Angle",
		Abbreviation: "deg",
		Unit:         "degree",
	}

	angularVelocityQuantity = PhysicalQuantity{
		Name:         "ANGULAR_VELOCITY",
		Description:  "Angular velocity",
		Comment:      "The speed at which a measured angle changes",
		URL:          "https://en.wikipedia.org/wiki/Angular_velocity",
		Abbreviation: "rad/s",
		Unit:         "radians per second",
	}

	volumeQuantity = PhysicalQuantity{
		Name:         "VOLUME",
		Description:  "Volume",
		Comment:      "A measure of occupied three-dimensional space.",
		URL:          "https://en.wikipedia.org/wiki/Volume",
		Abbreviation: "L",
		Unit:         "liter",
	}

	volumetricFlowQuantity = PhysicalQuantity{
		Name:         "VOLUMETRIC_FLOW",
		Description:  "Volumetric flow",
		Comment:      "The volume of fluid which passes per Unit time.",
		Abbreviation: "L/h",
		Unit:         "liter per hour",
		URL:          "https://en.wikipedia.org/wiki/Volumetric_flow_rate",
	}

	frequencyQuantity = PhysicalQuantity{
		Name:         "FREQUENCY",
		Description:  "Frequency",
		Abbreviation: "Hz",
		Unit:         "Hertz",
		URL:          "https://en.wikipedia.org/wiki/Radio_frequency",
	}

	dateQuantity = PhysicalQuantity{
		Name:        "DATE",
		Description: "Date",
		Comment: "A calendar date is a reference to a particular day in time, in NMEA 2000 " +
			"expressed as the number of days since 1970-01-01 (UNIX epoch).",
		Abbreviation: "d",
		Unit:         "days",
		URL:          "https://en.wikipedia.org/wiki/Calendar_date",
	}

	timeQuantity = PhysicalQuantity{
		Name:        "TIME",
		Description: "Time",
		Comment: "Time is what clocks measure. We use time to place events in sequence one after the other, and we use time to compare how " +
			"long events last. Absolute times in NMEA2000 are expressed as seconds since midnight(in an undefined timezone)",
		URL:          "https://en.wikipedia.org/wiki/Time",
		Abbreviation: "s",
		Unit:         "Second",
	}

	magneticFieldQuantity = PhysicalQuantity{
		Name:         "MAGNETIC_FIELD",
		Description:  "Magnetic field",
		Unit:         "Tesla",
		Abbreviation: "T",
		URL:          "https://en.wikipedia.org/wiki/Magnetic_field",
	}

	geoCoordinateQuantity = PhysicalQuantity{
		Name:         "GEOGRAPHICAL_COORDINATE",
		Description:  "Geographical coordinate",
		Comment:      "Latitude or longitude. Combined they form a unique point on earth, when height is disregarded.",
		Abbreviation: "deg",
		Unit:         "degree",
		URL:          "https://en.wikipedia.org/wiki/Geographic_coordinate_system",
	}

	temperatureQuantity = PhysicalQuantity{
		Name:         "TEMPERATURE",
		Description:  "Temperature",
		Unit:         "Kelvin",
		Abbreviation: "K",
		URL:          "https://en.wikipedia.org/wiki/Temperature",
	}

	pressureQuantity = PhysicalQuantity{
		Name:         "PRESSURE",
		Description:  "Pressure",
		Abbreviation: "Pa",
		Unit:         "Pascal",
		URL:          "https://en.wikipedia.org/wiki/Pressure",
	}

	pressureRateQuantity = PhysicalQuantity{
		Name:         "PRESSURE_RATE",
		Description:  "Pressure rate",
		Comment:      "How the pressure changes over time.",
		Abbreviation: "Pa/hr",
		Unit:         "Pascal per hour",
		URL:          "https://en.wikipedia.org/wiki/Pressure",
	}

	concentrationQuantity = PhysicalQuantity{
		Name:         "CONCENTRATION",
		Description:  "Concentration of one substance in another, in this marine context usually the amount of salts in water",
		URL:          "https://www.engineeringtoolbox.com/water-salinity-d_1251.html",
		Unit:         "parts per million",
		Abbreviation: "ppm",
	}

	signalToNoiseRatioQuantity = PhysicalQuantity{
		Name:         "SIGNAL_TO_NOISE_RATIO",
		Description:  "Signal-to-noise ratio",
		URL:          "https://en.wikipedia.org/wiki/Signal-to-noise_ratio",
		Abbreviation: "dB",
		Unit:         "decibel",
	}
)

var PhysicalQuantityList = []*PhysicalQuantity{
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

func (ana *analyzerImpl) fillFieldTypeLookupField(
	f *PGNField,
	lookup string,
	key int,
	str string,
	ft string,
) error {
	f.FT, _ = ana.GetFieldType(ft)
	if f.FT == nil {
		return fmt.Errorf("LookuPFieldType %s(%d) contains an invalid Fieldtype '%s'", lookup, key, ft)
	}
	f.Unit = f.FT.Unit
	f.Resolution = f.FT.Resolution
	f.HasSign = f.FT.HasSign == &trueValue
	if f.Size == 0 {
		f.Size = f.FT.Size
	}
	f.Name = str
	if f.Unit != "" {
		ana.fixupUnit(f)
	}

	UnitStr := f.Unit
	if UnitStr == "" {
		UnitStr = "NULL"
	}
	ana.Logger.Debugf("fillFieldTypeLookupField(Field, lookup='%s', key=%d, str='%s', ft='%s' Unit='%s' bits=%d",
		lookup,
		key,
		str,
		ft,
		UnitStr,
		f.Size)
	return nil
}
