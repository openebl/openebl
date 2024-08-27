// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/relay/server/cert/cert_manager.go

// Package mock_cert is a generated GoMock package.
package mock_cert

import (
	context "context"
	x509 "crypto/x509"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockCertManager is a mock of CertManager interface.
type MockCertManager struct {
	ctrl     *gomock.Controller
	recorder *MockCertManagerMockRecorder
}

// MockCertManagerMockRecorder is the mock recorder for MockCertManager.
type MockCertManagerMockRecorder struct {
	mock *MockCertManager
}

// NewMockCertManager creates a new mock instance.
func NewMockCertManager(ctrl *gomock.Controller) *MockCertManager {
	mock := &MockCertManager{ctrl: ctrl}
	mock.recorder = &MockCertManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockCertManager) EXPECT() *MockCertManagerMockRecorder {
	return m.recorder
}

// AddCRL mocks base method.
func (m *MockCertManager) AddCRL(ctx context.Context, crlRaw []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddCRL", ctx, crlRaw)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddCRL indicates an expected call of AddCRL.
func (mr *MockCertManagerMockRecorder) AddCRL(ctx, crlRaw interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddCRL", reflect.TypeOf((*MockCertManager)(nil).AddCRL), ctx, crlRaw)
}

// SyncRootCerts mocks base method.
func (m *MockCertManager) SyncRootCerts(ctx context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SyncRootCerts", ctx)
	ret0, _ := ret[0].(error)
	return ret0
}

// SyncRootCerts indicates an expected call of SyncRootCerts.
func (mr *MockCertManagerMockRecorder) SyncRootCerts(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SyncRootCerts", reflect.TypeOf((*MockCertManager)(nil).SyncRootCerts), ctx)
}

// VerifyCert mocks base method.
func (m *MockCertManager) VerifyCert(ctx context.Context, ts int64, certChain []*x509.Certificate) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifyCert", ctx, ts, certChain)
	ret0, _ := ret[0].(error)
	return ret0
}

// VerifyCert indicates an expected call of VerifyCert.
func (mr *MockCertManagerMockRecorder) VerifyCert(ctx, ts, certChain interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyCert", reflect.TypeOf((*MockCertManager)(nil).VerifyCert), ctx, ts, certChain)
}