package modbus

import "testing"

func TestRTUCapabilityIsFixtureOnlyExperimentalAndDefaultDisabled(t *testing.T) {
	capability := CurrentRTUCapability()
	if capability.Disposition() != RTUFixtureOnlyNoHardware {
		t.Fatalf("disposition = %q", capability.Disposition())
	}
	if capability.Maturity() != RTUMaturityExperimental {
		t.Fatalf("maturity = %q", capability.Maturity())
	}
	if capability.DefaultEnabled() ||
		capability.Supported() ||
		capability.HardwareQualified() ||
		capability.FixtureOptedIn() {
		t.Fatal("fixture-only capability made an enabled/support claim")
	}
}

func TestRTUExperimentalOptInCannotClaimPhysicalQualification(t *testing.T) {
	capability := CurrentRTUCapability().WithFixtureOptIn()
	if !capability.FixtureOptedIn() {
		t.Fatal("fixture opt-in not retained")
	}
	if capability.Disposition() != RTUFixtureOnlyNoHardware ||
		capability.Maturity() != RTUMaturityExperimental ||
		capability.DefaultEnabled() ||
		capability.Supported() ||
		capability.HardwareQualified() {
		t.Fatal("fixture opt-in upgraded RTU capability")
	}
}
