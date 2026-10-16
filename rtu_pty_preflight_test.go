package modbus

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"testing"
)

func rtuPTYPreflight(probe func(string) error) (string, error) {
	for _, path := range []string{"/dev/pts/ptmx", "/dev/ptmx"} {
		if err := probe(path); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return fmt.Sprintf("Linux PTY environment: devpts unavailable (%s: %v)", path, err), nil
			}
			return "", fmt.Errorf("Linux PTY preflight %s: %w", path, err)
		}
	}
	return "", nil
}

func TestM58PTYPreflight(t *testing.T) {
	for _, path := range []string{"/dev/pts/ptmx", "/dev/ptmx"} {
		for _, tc := range []struct {
			name string
			err  error
			skip bool
		}{
			{name: "present"},
			{name: "absent", err: fs.ErrNotExist, skip: true},
			{name: "wrapped_absent", err: &fs.PathError{Op: "stat", Path: path, Err: fs.ErrNotExist}, skip: true},
			{name: "permission", err: fs.ErrPermission},
			{name: "io", err: io.ErrUnexpectedEOF},
			{name: "unexpected_setup", err: errors.New("synthetic setup error")},
		} {
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				var calls []string
				reason, err := rtuPTYPreflight(func(probed string) error {
					calls = append(calls, probed)
					if probed == path {
						return tc.err
					}
					return nil
				})
				wantCalls := []string{"/dev/pts/ptmx"}
				if path == "/dev/ptmx" || tc.err == nil {
					wantCalls = append(wantCalls, "/dev/ptmx")
				}
				if fmt.Sprint(calls) != fmt.Sprint(wantCalls) {
					t.Fatalf("probe calls = %v, want %v", calls, wantCalls)
				}
				if tc.skip {
					if err != nil || !strings.Contains(reason, "devpts unavailable") || !strings.Contains(reason, path) {
						t.Fatalf("absent facility = %q, %v; want explicit environment skip", reason, err)
					}
				} else if reason != "" || !errors.Is(err, tc.err) {
					t.Fatalf("preflight = %q, %v; want no skip and error %v", reason, err, tc.err)
				}
			})
		}
	}
}
