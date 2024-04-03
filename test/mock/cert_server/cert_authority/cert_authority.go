// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/cert_server/cert_authority/cert_authority.go

// Package mock_cert_authority is a generated GoMock package.
package mock_cert_authority

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	cert_authority "github.com/openebl/openebl/pkg/cert_server/cert_authority"
	model "github.com/openebl/openebl/pkg/cert_server/model"
)

// MockCertAuthority is a mock of CertAuthority interface.
type MockCertAuthority struct {
	ctrl     *gomock.Controller
	recorder *MockCertAuthorityMockRecorder
}

// MockCertAuthorityMockRecorder is the mock recorder for MockCertAuthority.
type MockCertAuthorityMockRecorder struct {
	mock *MockCertAuthority
}

// NewMockCertAuthority creates a new mock instance.
func NewMockCertAuthority(ctrl *gomock.Controller) *MockCertAuthority {
	mock := &MockCertAuthority{ctrl: ctrl}
	mock.recorder = &MockCertAuthorityMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockCertAuthority) EXPECT() *MockCertAuthorityMockRecorder {
	return m.recorder
}

// AddCertificateSigningRequest mocks base method.
func (m *MockCertAuthority) AddCertificateSigningRequest(ctx context.Context, ts int64, req cert_authority.AddCertificateSigningRequestRequest) (model.Cert, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddCertificateSigningRequest", ctx, ts, req)
	ret0, _ := ret[0].(model.Cert)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddCertificateSigningRequest indicates an expected call of AddCertificateSigningRequest.
func (mr *MockCertAuthorityMockRecorder) AddCertificateSigningRequest(ctx, ts, req interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddCertificateSigningRequest", reflect.TypeOf((*MockCertAuthority)(nil).AddCertificateSigningRequest), ctx, ts, req)
}

// AddRootCertificate mocks base method.
func (m *MockCertAuthority) AddRootCertificate(ctx context.Context, ts int64, req cert_authority.AddRootCertificateRequest) (model.Cert, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddRootCertificate", ctx, ts, req)
	ret0, _ := ret[0].(model.Cert)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddRootCertificate indicates an expected call of AddRootCertificate.
func (mr *MockCertAuthorityMockRecorder) AddRootCertificate(ctx, ts, req interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddRootCertificate", reflect.TypeOf((*MockCertAuthority)(nil).AddRootCertificate), ctx, ts, req)
}

// CreateCACertificateSigningRequest mocks base method.
func (m *MockCertAuthority) CreateCACertificateSigningRequest(ctx context.Context, ts int64, req cert_authority.CreateCACertificateSigningRequestRequest) (model.Cert, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateCACertificateSigningRequest", ctx, ts, req)
	ret0, _ := ret[0].(model.Cert)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateCACertificateSigningRequest indicates an expected call of CreateCACertificateSigningRequest.
func (mr *MockCertAuthorityMockRecorder) CreateCACertificateSigningRequest(ctx, ts, req interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateCACertificateSigningRequest", reflect.TypeOf((*MockCertAuthority)(nil).CreateCACertificateSigningRequest), ctx, ts, req)
}

// IssueCertificate mocks base method.
func (m *MockCertAuthority) IssueCertificate(ctx context.Context, ts int64, req cert_authority.IssueCertificateRequest) (model.Cert, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IssueCertificate", ctx, ts, req)
	ret0, _ := ret[0].(model.Cert)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IssueCertificate indicates an expected call of IssueCertificate.
func (mr *MockCertAuthorityMockRecorder) IssueCertificate(ctx, ts, req interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IssueCertificate", reflect.TypeOf((*MockCertAuthority)(nil).IssueCertificate), ctx, ts, req)
}

// RejectCertificateSigningRequest mocks base method.
func (m *MockCertAuthority) RejectCertificateSigningRequest(ctx context.Context, ts int64, req cert_authority.RejectCertificateSigningRequestRequest) (model.Cert, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RejectCertificateSigningRequest", ctx, ts, req)
	ret0, _ := ret[0].(model.Cert)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RejectCertificateSigningRequest indicates an expected call of RejectCertificateSigningRequest.
func (mr *MockCertAuthorityMockRecorder) RejectCertificateSigningRequest(ctx, ts, req interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RejectCertificateSigningRequest", reflect.TypeOf((*MockCertAuthority)(nil).RejectCertificateSigningRequest), ctx, ts, req)
}

// RespondCACertificateSigningRequest mocks base method.
func (m *MockCertAuthority) RespondCACertificateSigningRequest(ctx context.Context, ts int64, req cert_authority.RespondCACertificateSigningRequestRequest) (model.Cert, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RespondCACertificateSigningRequest", ctx, ts, req)
	ret0, _ := ret[0].(model.Cert)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RespondCACertificateSigningRequest indicates an expected call of RespondCACertificateSigningRequest.
func (mr *MockCertAuthorityMockRecorder) RespondCACertificateSigningRequest(ctx, ts, req interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RespondCACertificateSigningRequest", reflect.TypeOf((*MockCertAuthority)(nil).RespondCACertificateSigningRequest), ctx, ts, req)
}

// RevokeRootCertificate mocks base method.
func (m *MockCertAuthority) RevokeRootCertificate(ctx context.Context, ts int64, req cert_authority.RevokeCertificateRequest) (model.Cert, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RevokeRootCertificate", ctx, ts, req)
	ret0, _ := ret[0].(model.Cert)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RevokeRootCertificate indicates an expected call of RevokeRootCertificate.
func (mr *MockCertAuthorityMockRecorder) RevokeRootCertificate(ctx, ts, req interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RevokeRootCertificate", reflect.TypeOf((*MockCertAuthority)(nil).RevokeRootCertificate), ctx, ts, req)
}