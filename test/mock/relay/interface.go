// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/relay/interface.go

// Package mock_relay is a generated GoMock package.
package mock_relay

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockRelayClient is a mock of RelayClient interface.
type MockRelayClient struct {
	ctrl     *gomock.Controller
	recorder *MockRelayClientMockRecorder
}

// MockRelayClientMockRecorder is the mock recorder for MockRelayClient.
type MockRelayClientMockRecorder struct {
	mock *MockRelayClient
}

// NewMockRelayClient creates a new mock instance.
func NewMockRelayClient(ctrl *gomock.Controller) *MockRelayClient {
	mock := &MockRelayClient{ctrl: ctrl}
	mock.recorder = &MockRelayClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRelayClient) EXPECT() *MockRelayClientMockRecorder {
	return m.recorder
}

// Close mocks base method.
func (m *MockRelayClient) Close() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close.
func (mr *MockRelayClientMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockRelayClient)(nil).Close))
}

// Publish mocks base method.
func (m *MockRelayClient) Publish(ctx context.Context, evtType int, data []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Publish", ctx, evtType, data)
	ret0, _ := ret[0].(error)
	return ret0
}

// Publish indicates an expected call of Publish.
func (mr *MockRelayClientMockRecorder) Publish(ctx, evtType, data interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Publish", reflect.TypeOf((*MockRelayClient)(nil).Publish), ctx, evtType, data)
}

// Subscribe mocks base method.
func (m *MockRelayClient) Subscribe(ctx context.Context, offset int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Subscribe", ctx, offset)
	ret0, _ := ret[0].(error)
	return ret0
}

// Subscribe indicates an expected call of Subscribe.
func (mr *MockRelayClientMockRecorder) Subscribe(ctx, offset interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Subscribe", reflect.TypeOf((*MockRelayClient)(nil).Subscribe), ctx, offset)
}

// MockRelayServer is a mock of RelayServer interface.
type MockRelayServer struct {
	ctrl     *gomock.Controller
	recorder *MockRelayServerMockRecorder
}

// MockRelayServerMockRecorder is the mock recorder for MockRelayServer.
type MockRelayServerMockRecorder struct {
	mock *MockRelayServer
}

// NewMockRelayServer creates a new mock instance.
func NewMockRelayServer(ctrl *gomock.Controller) *MockRelayServer {
	mock := &MockRelayServer{ctrl: ctrl}
	mock.recorder = &MockRelayServerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRelayServer) EXPECT() *MockRelayServerMockRecorder {
	return m.recorder
}

// Close mocks base method.
func (m *MockRelayServer) Close() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close.
func (mr *MockRelayServerMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockRelayServer)(nil).Close))
}

// ListenAndServe mocks base method.
func (m *MockRelayServer) ListenAndServe() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListenAndServe")
	ret0, _ := ret[0].(error)
	return ret0
}

// ListenAndServe indicates an expected call of ListenAndServe.
func (mr *MockRelayServerMockRecorder) ListenAndServe() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListenAndServe", reflect.TypeOf((*MockRelayServer)(nil).ListenAndServe))
}
