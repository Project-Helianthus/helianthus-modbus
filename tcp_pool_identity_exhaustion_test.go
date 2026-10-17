package modbus

import (
	"errors"
	"math"
	"testing"
)

func TestPoolCounterExhaustion(t *testing.T) {
	for _, field := range []string{"connection_identity", "transport_generation"} {
		t.Run(field, func(t *testing.T) {
			for _, keepLive := range []bool{false, true} {
				name := "empty_pool"
				if keepLive {
					name = "preserve_live_lease"
				}
				t.Run(name, func(t *testing.T) {
					pool, err := newTCPEndpointPool("synthetic-pool", EndpointPoolLimits{
						MaxConnections: 2,
						Connection:     ConnectionLimits{MaxInFlight: 1, MaxTombstones: 1},
					})
					if err != nil {
						t.Fatal(err)
					}
					var live TCPConnectionLease
					var liveOwner *TCPConnectionOwner
					var liveID, liveGeneration uint64
					if keepLive {
						live, err = pool.openConnection()
						if err != nil {
							t.Fatal(err)
						}
						liveOwner = live.ownerForEndpoint()
						liveID, liveGeneration = live.ConnectionID(), liveOwner.Generation()
					}
					wantID, wantGeneration := pool.nextConnectionID, pool.nextGeneration.Load()+1
					if field == "connection_identity" {
						pool.nextConnectionID = math.MaxUint64
						wantID = math.MaxUint64
					} else {
						pool.nextGeneration.Store(math.MaxUint64 - 1)
						wantGeneration = math.MaxUint64
					}
					last, err := pool.openConnection()
					if err != nil {
						t.Fatalf("final identity rejected: %v", err)
					}
					lastOwner := last.ownerForEndpoint()
					if lastOwner == nil {
						t.Fatal("final identity has no live owner")
					}
					if last.ConnectionID() != wantID || lastOwner.Generation() != wantGeneration {
						t.Fatalf("final identity = (%d, %d), want (%d, %d)", last.ConnectionID(), lastOwner.Generation(), wantID, wantGeneration)
					}
					wantActive := 0
					if keepLive {
						wantActive = 1
					}
					if got := pool.ActiveConnections(); got != wantActive+1 {
						t.Fatalf("active after final admission = %d, want %d", got, wantActive+1)
					}
					if err := pool.closeConnection(last); err != nil {
						t.Fatal(err)
					}
					if last.ownerForEndpoint() != nil || !lastOwner.Closed() {
						t.Fatal("final lease was not retired")
					}
					for attempt := 0; attempt < 3; attempt++ {
						failed, err := pool.openConnection()
						var protocolErr *ProtocolError
						if !errors.As(err, &protocolErr) || protocolErr.Kind != ErrorInvalidRange || protocolErr.Field != field {
							t.Errorf("attempt %d: error = %v, want invalid range for %s", attempt, err, field)
						}
						if failed != (TCPConnectionLease{}) {
							t.Errorf("attempt %d: failed allocation returned a lease", attempt)
						}
						if got := pool.ActiveConnections(); got != wantActive {
							t.Errorf("attempt %d: active = %d, want %d", attempt, got, wantActive)
						}
						if keepLive && (live.ConnectionID() != liveID || live.ownerForEndpoint() != liveOwner || liveOwner.Generation() != liveGeneration || liveOwner.Closed()) {
							t.Fatalf("attempt %d: failed allocation changed surviving lease", attempt)
						}
					}
					if keepLive {
						if err := pool.closeConnection(live); err != nil {
							t.Fatal("surviving lease cannot close:", err)
						}
						if got := pool.ActiveConnections(); got != 0 {
							t.Fatalf("active after survivor close = %d, want 0", got)
						}
					}
				})
			}
		})
	}
}
