package modbus

import (
	"math"
	"sync"
	"sync/atomic"
)

// EndpointPoolLimits bounds live TCP sockets and each socket owner.
type EndpointPoolLimits struct {
	MaxConnections int
	Connection     ConnectionLimits
}

// TCPEndpointPool owns a bounded set of independent socket owners.
type TCPEndpointPool struct {
	mu               sync.Mutex
	endpoint         string
	limits           EndpointPoolLimits
	nextConnectionID uint64
	nextGeneration   atomic.Uint64
	connections      map[uint64]*TCPConnectionOwner
}

// TCPConnectionLease is an opaque live socket-owner handle.
type TCPConnectionLease struct {
	pool         *TCPEndpointPool
	connectionID uint64
	owner        *TCPConnectionOwner
}

// ConnectionID returns the non-reused pool-local socket identity.
func (lease TCPConnectionLease) ConnectionID() uint64 {
	return lease.connectionID
}

func (lease TCPConnectionLease) ownerForEndpoint() *TCPConnectionOwner {
	if lease.pool == nil {
		return nil
	}
	lease.pool.mu.Lock()
	defer lease.pool.mu.Unlock()
	if lease.pool.connections[lease.connectionID] != lease.owner {
		return nil
	}
	return lease.owner
}

// newTCPEndpointPool validates bounded per-endpoint connection ownership.
func newTCPEndpointPool(
	endpoint string,
	limits EndpointPoolLimits,
) (*TCPEndpointPool, error) {
	if endpoint == "" ||
		limits.MaxConnections <= 0 ||
		limits.MaxConnections > 1<<16 ||
		limits.Connection.MaxInFlight <= 0 ||
		limits.Connection.MaxInFlight > 1<<16 ||
		limits.Connection.MaxTombstones <= 0 ||
		limits.Connection.MaxTombstones > 1<<16 {
		return nil, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"endpoint_pool_limits",
			-1,
		)
	}
	return &TCPEndpointPool{
		endpoint:         endpoint,
		limits:           limits,
		nextConnectionID: 1,
		connections:      make(map[uint64]*TCPConnectionOwner),
	}, nil
}

// OpenConnection creates exactly one owner for one new live socket.
func (pool *TCPEndpointPool) openConnection() (TCPConnectionLease, error) {
	if pool == nil {
		return TCPConnectionLease{}, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"endpoint_pool",
			-1,
		)
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if len(pool.connections) >= pool.limits.MaxConnections {
		return TCPConnectionLease{}, protocolError(
			ErrorInvalidRange,
			0,
			0,
			"connections",
			-1,
		)
	}
	if pool.nextConnectionID == 0 {
		return TCPConnectionLease{}, protocolError(
			ErrorInvalidRange,
			0,
			0,
			"connection_identity",
			-1,
		)
	}
	connectionID := pool.nextConnectionID
	generation := pool.allocateGeneration()
	if generation == 0 {
		return TCPConnectionLease{}, protocolError(
			ErrorInvalidRange,
			0,
			0,
			"transport_generation",
			-1,
		)
	}
	pool.nextConnectionID++
	owner, err := newTCPConnectionOwner(
		pool.endpoint,
		generation,
		pool.limits.Connection,
	)
	if err != nil {
		return TCPConnectionLease{}, err
	}
	owner.generationAllocator = func() uint64 {
		return pool.allocateGeneration()
	}
	owner.connectionID = connectionID
	owner.pool = pool
	pool.connections[connectionID] = owner
	return TCPConnectionLease{
		pool:         pool,
		connectionID: connectionID,
		owner:        owner,
	}, nil
}

func (pool *TCPEndpointPool) allocateGeneration() uint64 {
	for {
		current := pool.nextGeneration.Load()
		if current == math.MaxUint64 {
			return 0
		}
		if pool.nextGeneration.CompareAndSwap(current, current+1) {
			return current + 1
		}
	}
}

// CloseConnection invalidates one exact lease and releases pool capacity.
func (pool *TCPEndpointPool) closeConnection(
	lease TCPConnectionLease,
) error {
	if pool == nil {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"endpoint_pool",
			-1,
		)
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if lease.pool != pool ||
		lease.connectionID == 0 ||
		pool.connections[lease.connectionID] != lease.owner {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"connection_lease",
			-1,
		)
	}
	lease.owner.retire()
	delete(pool.connections, lease.connectionID)
	return nil
}

func (pool *TCPEndpointPool) releaseLostConnection(
	connectionID uint64,
	owner *TCPConnectionOwner,
) {
	if pool == nil {
		return
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if pool.connections[connectionID] == owner {
		delete(pool.connections, connectionID)
	}
}

// ActiveConnections returns the current bounded live socket count.
func (pool *TCPEndpointPool) ActiveConnections() int {
	if pool == nil {
		return 0
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	return len(pool.connections)
}
