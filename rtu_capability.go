package modbus

// RTUDisposition is the evidence-backed RTU qualification result.
type RTUDisposition string

const (
	// RTUFixtureOnlyNoHardware forbids enabled, supported, or qualified claims.
	RTUFixtureOnlyNoHardware RTUDisposition = "FIXTURE_ONLY_NO_HARDWARE"
)

// RTUMaturity identifies the current RTU runtime maturity.
type RTUMaturity string

const (
	RTUMaturityExperimental RTUMaturity = "experimental"
)

// RTUCapability is an immutable library-generated capability statement.
type RTUCapability struct {
	fixtureOptIn bool
}

// CurrentRTUCapability returns the default-disabled fixture-only disposition.
func CurrentRTUCapability() RTUCapability {
	return RTUCapability{}
}

// WithFixtureOptIn permits offline fixture execution without changing claims.
func (capability RTUCapability) WithFixtureOptIn() RTUCapability {
	capability.fixtureOptIn = true
	return capability
}

// Disposition returns the exact physical qualification disposition.
func (RTUCapability) Disposition() RTUDisposition {
	return RTUFixtureOnlyNoHardware
}

// Maturity returns the experimental maturity.
func (RTUCapability) Maturity() RTUMaturity {
	return RTUMaturityExperimental
}

// DefaultEnabled always reports false for the fixture-only slice.
func (RTUCapability) DefaultEnabled() bool {
	return false
}

// Supported always reports false without physical qualification.
func (RTUCapability) Supported() bool {
	return false
}

// HardwareQualified always reports false in M1-03.
func (RTUCapability) HardwareQualified() bool {
	return false
}

// FixtureOptedIn reports only explicit offline fixture execution consent.
func (capability RTUCapability) FixtureOptedIn() bool {
	return capability.fixtureOptIn
}
