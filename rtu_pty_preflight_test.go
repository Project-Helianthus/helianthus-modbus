package modbus

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"testing"
)

func rtuPTYPreflight(probe func(string) error, required string) (string, error) {
	path := "/dev/ptmx"
	if err := probe(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			reason := fmt.Sprintf("Linux PTY environment: devpts unavailable (%s: %v)", path, err)
			if required == "1" {
				return "", errors.New(reason)
			}
			return reason, nil
		}
		return "", fmt.Errorf("Linux PTY preflight %s: %w", path, err)
	}
	return "", nil
}

func TestM58PTYPreflight(t *testing.T) {
	for _, required := range []string{"", "1", "0", "true"} {
		for _, tc := range []struct {
			name string
			err  error
		}{
			{name: "present"},
			{name: "absent", err: fs.ErrNotExist},
			{name: "wrapped_absent", err: &fs.PathError{Op: "stat", Path: "/dev/ptmx", Err: fs.ErrNotExist}},
			{name: "permission", err: fs.ErrPermission},
			{name: "io", err: io.ErrUnexpectedEOF},
			{name: "unexpected_setup", err: errors.New("synthetic setup error")},
		} {
			t.Run("required="+required+"/"+tc.name, func(t *testing.T) {
				var calls []string
				reason, err := rtuPTYPreflight(func(probed string) error {
					calls = append(calls, probed)
					return tc.err
				}, required)
				if len(calls) != 1 || calls[0] != "/dev/ptmx" {
					t.Fatalf("probe calls = %v, want only /dev/ptmx", calls)
				}
				if errors.Is(tc.err, fs.ErrNotExist) {
					wantReason := fmt.Sprintf("Linux PTY environment: devpts unavailable (/dev/ptmx: %v)", tc.err)
					if required == "1" {
						if reason != "" || err == nil || err.Error() != wantReason {
							t.Fatalf("required absent facility = %q, %v; want failure %q", reason, err, wantReason)
						}
					} else if err != nil || reason != wantReason {
						t.Fatalf("optional absent facility = %q, %v; want explicit skip %q", reason, err, wantReason)
					}
				} else if reason != "" || !errors.Is(err, tc.err) {
					t.Fatalf("preflight = %q, %v; want no skip and error %v", reason, err, tc.err)
				}
			})
		}
	}
}
