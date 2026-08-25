//go:build !linux

package modbus

import "errors"

var errRTUSerialUnsupported = errors.New("rtu serial is supported only on linux")

// OpenRTUSerial is unavailable outside Linux. Callers must fail closed rather
// than substituting a different transport or attempting device discovery.
func OpenRTUSerial(config RTUSerialConfig) (*RTUSerialStream, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return nil, errRTUSerialUnsupported
}
