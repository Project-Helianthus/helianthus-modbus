package modbus

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
)

type readStartedConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (conn *readStartedConn) Unwrap() net.Conn {
	return conn.Conn
}

func (*readStartedConn) modbusTCPTrustedDecorator() {}

func (conn *readStartedConn) Read(buffer []byte) (int, error) {
	conn.once.Do(func() { close(conn.started) })
	return conn.Conn.Read(buffer)
}

func TestTCPEndpointPoolBoundsConnectionsAndOwnsOneStatePerSocket(t *testing.T) {
	pool, err := newTCPEndpointPool(
		"tcp://192.0.2.10:502",
		EndpointPoolLimits{
			MaxConnections: 2,
			Connection: ConnectionLimits{
				MaxInFlight:   2,
				MaxTombstones: 2,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	first, err := pool.openConnection()
	if err != nil {
		t.Fatal(err)
	}
	second, err := pool.openConnection()
	if err != nil {
		t.Fatal(err)
	}
	if first.ConnectionID() == second.ConnectionID() ||
		first.ownerForEndpoint() == second.ownerForEndpoint() {
		t.Fatal("two socket leases share owner state")
	}
	_, err = pool.openConnection()
	_ = requireProtocolError(t, err, ErrorInvalidRange)
	if pool.ActiveConnections() != 2 {
		t.Fatalf("active connections = %d", pool.ActiveConnections())
	}
	firstOwner := first.ownerForEndpoint()
	if err := pool.closeConnection(first); err != nil {
		t.Fatal(err)
	}
	if first.ownerForEndpoint() != nil {
		t.Fatal("closed lease retained usable owner")
	}
	if !firstOwner.Closed() {
		t.Fatal("previously obtained owner remained live after pool close")
	}
	generation := firstOwner.Reconnect()
	request, _ := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0, 1)
	if _, err := firstOwner.ReserveRead(1, request); err == nil {
		t.Fatalf("retired owner resurrected at generation %d", generation)
	}
	replacement, err := pool.openConnection()
	if err != nil {
		t.Fatal(err)
	}
	if replacement.ConnectionID() == first.ConnectionID() {
		t.Fatal("closed socket identity was reused")
	}
}

func TestTCPEndpointPoolRejectsForgedAndForeignLeases(t *testing.T) {
	first, _ := newTCPEndpointPool(
		"tcp://192.0.2.10:502",
		EndpointPoolLimits{
			MaxConnections: 1,
			Connection: ConnectionLimits{
				MaxInFlight:   1,
				MaxTombstones: 1,
			},
		},
	)
	second, _ := newTCPEndpointPool(
		"tcp://192.0.2.11:502",
		EndpointPoolLimits{
			MaxConnections: 1,
			Connection: ConnectionLimits{
				MaxInFlight:   1,
				MaxTombstones: 1,
			},
		},
	)
	lease, _ := first.openConnection()
	if err := second.closeConnection(lease); err == nil {
		t.Fatal("foreign pool accepted lease")
	}
	if err := first.closeConnection(TCPConnectionLease{}); err == nil {
		t.Fatal("forged zero lease accepted")
	}
}

func TestPoolOwnsUniqueGenerationAllocationAcrossReconnects(t *testing.T) {
	pool, err := newTCPEndpointPool(
		"tcp://192.0.2.10:502",
		EndpointPoolLimits{
			MaxConnections: 2,
			Connection: ConnectionLimits{
				MaxInFlight:   1,
				MaxTombstones: 1,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := pool.openConnection()
	first.ownerForEndpoint().Close()
	if got := first.ownerForEndpoint().Reconnect(); got != 2 {
		t.Fatalf("reconnect generation = %d", got)
	}
	second, err := pool.openConnection()
	if err != nil {
		t.Fatal(err)
	}
	request, _ := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0, 1)
	firstReservation, _ := first.ownerForEndpoint().ReserveRead(1, request)
	secondReservation, _ := second.ownerForEndpoint().ReserveRead(1, request)
	if firstReservation.Generation() == secondReservation.Generation() {
		t.Fatal("two live sockets share transport generation")
	}
}

func TestTransportLossReleasesPoolCapacityAndInvalidatesLease(t *testing.T) {
	pool, err := newTCPEndpointPool(
		"tcp://192.0.2.10:502",
		EndpointPoolLimits{
			MaxConnections: 1,
			Connection: ConnectionLimits{
				MaxInFlight:   1,
				MaxTombstones: 1,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := pool.openConnection()
	if err != nil {
		t.Fatal(err)
	}
	owner := lease.ownerForEndpoint()
	client, server := net.Pipe()
	transport, err := newTCPTransport(client, owner, 260)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	_, transition, err := transport.ReadResponses(context.Background())
	if !errors.Is(err, io.EOF) || !transition.CloseConnection() {
		t.Fatalf("read error=%v transition=%#v", err, transition)
	}
	if pool.ActiveConnections() != 0 || lease.ownerForEndpoint() != nil {
		t.Fatalf(
			"active=%d lease_owner=%p",
			pool.ActiveConnections(),
			lease.ownerForEndpoint(),
		)
	}
	generation := owner.Generation()
	if got := owner.Reconnect(); got != generation {
		t.Fatalf("retired owner reconnected at generation %d", got)
	}
	rejectedClient, rejectedServer := net.Pipe()
	defer func() { _ = rejectedClient.Close() }()
	defer func() { _ = rejectedServer.Close() }()
	if _, err := newTCPTransport(rejectedClient, owner, 260); err == nil {
		t.Fatal("retired pooled owner accepted a replacement socket")
	}
	if _, err := pool.openConnection(); err != nil {
		t.Fatal("terminal socket retained pool capacity:", err)
	}
}

func TestStaleReaderCannotReleaseReconnectedPoolSlot(t *testing.T) {
	pool, err := newTCPEndpointPool(
		"tcp://192.0.2.10:502",
		EndpointPoolLimits{
			MaxConnections: 1,
			Connection: ConnectionLimits{
				MaxInFlight:   1,
				MaxTombstones: 1,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	lease, _ := pool.openConnection()
	owner := lease.ownerForEndpoint()
	oldClient, oldServer := net.Pipe()
	defer func() { _ = oldServer.Close() }()
	started := make(chan struct{})
	oldTransport, err := newTCPTransport(
		&readStartedConn{Conn: oldClient, started: started},
		owner,
		260,
	)
	if err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() {
		_, _, err := oldTransport.ReadResponses(context.Background())
		readDone <- err
	}()
	<-started
	owner.Close()
	if generation := owner.Reconnect(); generation != 2 {
		t.Fatalf("generation = %d", generation)
	}
	newClient, newServer := net.Pipe()
	defer func() { _ = newServer.Close() }()
	if _, err := newTCPTransport(newClient, owner, 260); err != nil {
		t.Fatal(err)
	}
	if err := <-readDone; err == nil {
		t.Fatal("stale reader returned nil")
	}
	if pool.ActiveConnections() != 1 || lease.ownerForEndpoint() != owner {
		t.Fatalf(
			"active=%d lease_owner=%p want=%p",
			pool.ActiveConnections(),
			lease.ownerForEndpoint(),
			owner,
		)
	}
	if _, err := pool.openConnection(); err == nil {
		t.Fatal("stale reader released a live pool slot")
	}
}

func TestPoolCloseRetainsInFlightFailuresOnRetiredOwner(t *testing.T) {
	pool, _ := newTCPEndpointPool(
		"tcp://192.0.2.10:502",
		EndpointPoolLimits{
			MaxConnections: 1,
			Connection: ConnectionLimits{
				MaxInFlight:   2,
				MaxTombstones: 2,
			},
		},
	)
	lease, _ := pool.openConnection()
	owner := lease.ownerForEndpoint()
	request, _ := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0, 1)
	_, _ = owner.ReserveRead(1, request)
	_, _ = owner.ReserveRead(2, request)
	if err := pool.closeConnection(lease); err != nil {
		t.Fatal(err)
	}
	if failed := owner.DrainFailedReservations(); len(failed) != 2 {
		t.Fatalf("failed reservations = %#v", failed)
	}
}

func TestTombstoneExhaustionClosesTransportAndReleasesPool(t *testing.T) {
	pool, _ := newTCPEndpointPool(
		"tcp://192.0.2.10:502",
		EndpointPoolLimits{
			MaxConnections: 1,
			Connection: ConnectionLimits{
				MaxInFlight:   2,
				MaxTombstones: 1,
			},
		},
	)
	lease, _ := pool.openConnection()
	owner := lease.ownerForEndpoint()
	client, server := net.Pipe()
	if _, err := newTCPTransport(client, owner, 260); err != nil {
		t.Fatal(err)
	}
	request, _ := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0, 1)
	first, _ := owner.ReserveRead(1, request)
	if err := owner.MarkWriteInvoked(first); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.RecordTransmit(first, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	if err := owner.AbandonResponseWait(first, AbandonTimeout); err != nil {
		t.Fatal(err)
	}
	second, _ := owner.ReserveRead(1, request)
	if err := owner.MarkWriteInvoked(second); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.RecordTransmit(second, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	if err := owner.AbandonResponseWait(
		second,
		AbandonTimeout,
	); err == nil {
		t.Fatal("tombstone exhaustion returned nil")
	}
	if pool.ActiveConnections() != 0 || lease.ownerForEndpoint() != nil {
		t.Fatalf(
			"active=%d lease_owner=%p",
			pool.ActiveConnections(),
			lease.ownerForEndpoint(),
		)
	}
	buffer := make([]byte, 1)
	if _, err := server.Read(buffer); !errors.Is(err, io.EOF) {
		t.Fatalf("peer read error = %v", err)
	}
	if _, err := pool.openConnection(); err != nil {
		t.Fatal("tombstone exhaustion retained pool slot:", err)
	}
}
