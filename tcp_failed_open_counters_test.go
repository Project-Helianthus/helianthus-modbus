package modbus

import (
	"errors"
	"math"
	"reflect"
	"testing"
	"time"
)

type failedOpenResources struct {
	limits      EndpointPoolLimits
	connections map[uint64]*TCPConnectionOwner
	inFlight    map[uint16]ownedRequest
	tombstones  map[uint16]ownedRequest
}

func snapshotFailedOpenResources(pool *TCPEndpointPool, owner *TCPConnectionOwner) failedOpenResources {
	snapshot := failedOpenResources{
		limits:      pool.limits,
		connections: make(map[uint64]*TCPConnectionOwner),
		inFlight:    make(map[uint16]ownedRequest),
		tombstones:  make(map[uint16]ownedRequest),
	}
	for id, connection := range pool.connections {
		snapshot.connections[id] = connection
	}
	for id, request := range owner.inFlight {
		snapshot.inFlight[id] = *request
	}
	for id, request := range owner.tombstones {
		snapshot.tombstones[id] = request
	}
	return snapshot
}

func newFailedOpenPool(t *testing.T) *TCPEndpointPool {
	t.Helper()
	pool, err := newTCPEndpointPool("synthetic-pool", EndpointPoolLimits{
		MaxConnections: 2,
		Connection:     ConnectionLimits{MaxInFlight: 2, MaxTombstones: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

func requireFailedOpenError(t *testing.T, lease TCPConnectionLease, err error, kind ErrorKind, field string) {
	t.Helper()
	var protocolErr *ProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.Kind != kind || protocolErr.Field != field {
		t.Errorf("error = %v, want %v for %s", err, kind, field)
	}
	if lease != (TCPConnectionLease{}) {
		t.Error("failed allocation returned a nonzero lease")
	}
}

func TestTCPFailedOpenCountersPreserved(t *testing.T) {
	for _, tc := range []struct {
		name       string
		id         uint64
		generation uint64
		full       bool
		field      string
	}{
		{"connection_id_exhausted", 0, 1, false, "connection_identity"},
		{"connection_id_exhausted_generation_near_boundary", 0, math.MaxUint64 - 1, false, "connection_identity"},
		{"generation_exhausted", 2, math.MaxUint64, false, "transport_generation"},
		{"generation_exhausted_last_connection_id", math.MaxUint64, math.MaxUint64, false, "transport_generation"},
		{"both_exhausted", 0, math.MaxUint64, false, "connection_identity"},
		{"capacity", 2, 1, true, "connections"},
		{"capacity_before_exhausted_identities", 0, math.MaxUint64, true, "connections"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := newFailedOpenPool(t)
			live, err := pool.openConnection()
			if err != nil {
				t.Fatal(err)
			}
			owner := live.ownerForEndpoint()
			liveID, liveGeneration := live.ConnectionID(), owner.Generation()
			clock := &virtualTCPClock{}
			clock.Advance(time.Second)
			request, err := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0, 1)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := owner.reserveReadUntil(1, request, clock.Now()+time.Second); err != nil {
				t.Fatal(err)
			}
			if tc.full {
				pool.limits.MaxConnections = 1
			}
			pool.nextConnectionID = tc.id
			pool.nextGeneration.Store(tc.generation)
			initial := snapshotFailedOpenResources(pool, owner)
			for attempt := 0; attempt < 3; attempt++ {
				beforeID, beforeGeneration := pool.nextConnectionID, pool.nextGeneration.Load()
				failed, err := pool.openConnection()
				requireFailedOpenError(t, failed, err, ErrorInvalidRange, tc.field)
				if got := pool.nextConnectionID; got != beforeID {
					t.Errorf("attempt %d: nextConnectionID = %d, want unchanged %d", attempt, got, beforeID)
				}
				if got := pool.nextGeneration.Load(); got != beforeGeneration {
					t.Errorf("attempt %d: nextGeneration = %d, want unchanged %d", attempt, got, beforeGeneration)
				}
				if pool.nextConnectionID != tc.id || pool.nextGeneration.Load() != tc.generation {
					t.Errorf("attempt %d: counters differ from initial baseline", attempt)
				}
				if live.ConnectionID() != liveID || owner.connectionID != liveID {
					t.Errorf("attempt %d: survivor connection ID changed", attempt)
				}
				if owner.Generation() != liveGeneration {
					t.Errorf("attempt %d: survivor generation changed", attempt)
				}
				if live.ownerForEndpoint() != owner || owner.Closed() || owner.retired {
					t.Errorf("attempt %d: survivor lost its live owner", attempt)
				}
				if got := snapshotFailedOpenResources(pool, owner); !reflect.DeepEqual(got, initial) {
					t.Errorf("attempt %d: resources = %#v, want %#v", attempt, got, initial)
				}
				if pool.ActiveConnections() != 1 {
					t.Errorf("attempt %d: active connections = %d, want 1", attempt, pool.ActiveConnections())
				}
			}
			if err := pool.closeConnection(live); err != nil {
				t.Fatal("surviving lease cannot release capacity:", err)
			}
			if pool.ActiveConnections() != 0 {
				t.Fatal("surviving lease retained capacity after close")
			}
		})
	}
}

func TestTCPFailedOpenCountersNilPool(t *testing.T) {
	var pool *TCPEndpointPool
	for attempt := 0; attempt < 3; attempt++ {
		lease, err := pool.openConnection()
		requireFailedOpenError(t, lease, err, ErrorInvalidRequest, "endpoint_pool")
	}
}

func TestTCPFailedOpenCountersBoundarySuccess(t *testing.T) {
	for _, tc := range []struct {
		name           string
		id, generation uint64
		wantNextID     uint64
		wantGeneration uint64
	}{
		{"last_connection_id", math.MaxUint64, 1, 0, 2},
		{"last_generation", 2, math.MaxUint64 - 1, 3, math.MaxUint64},
		{"both_last", math.MaxUint64, math.MaxUint64 - 1, 0, math.MaxUint64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := newFailedOpenPool(t)
			pool.nextConnectionID = tc.id
			pool.nextGeneration.Store(tc.generation)
			lease, err := pool.openConnection()
			if err != nil {
				t.Fatal(err)
			}
			owner := lease.ownerForEndpoint()
			if owner == nil {
				t.Fatal("successful allocation has no owner")
			}
			if lease.ConnectionID() != tc.id || owner.connectionID != tc.id {
				t.Errorf("connection ID = %d, want %d", lease.ConnectionID(), tc.id)
			}
			if got := owner.Generation(); got != tc.wantGeneration {
				t.Errorf("generation = %d, want %d", got, tc.wantGeneration)
			}
			if got := pool.nextConnectionID; got != tc.wantNextID {
				t.Errorf("nextConnectionID = %d, want %d", got, tc.wantNextID)
			}
			if got := pool.nextGeneration.Load(); got != tc.wantGeneration {
				t.Errorf("nextGeneration = %d, want %d", got, tc.wantGeneration)
			}
			if pool.ActiveConnections() != 1 || owner.Closed() {
				t.Error("successful allocation did not retain one live owner")
			}
		})
	}
}
