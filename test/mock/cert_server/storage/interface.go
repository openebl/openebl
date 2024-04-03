// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/cert_server/storage/interface.go

// Package mock_storage is a generated GoMock package.
package mock_storage

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	model "github.com/openebl/openebl/pkg/cert_server/model"
	storage "github.com/openebl/openebl/pkg/cert_server/storage"
)

// MockTx is a mock of Tx interface.
type MockTx struct {
	ctrl     *gomock.Controller
	recorder *MockTxMockRecorder
}

// MockTxMockRecorder is the mock recorder for MockTx.
type MockTxMockRecorder struct {
	mock *MockTx
}

// NewMockTx creates a new mock instance.
func NewMockTx(ctrl *gomock.Controller) *MockTx {
	mock := &MockTx{ctrl: ctrl}
	mock.recorder = &MockTxMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTx) EXPECT() *MockTxMockRecorder {
	return m.recorder
}

// Commit mocks base method.
func (m *MockTx) Commit(ctx context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Commit", ctx)
	ret0, _ := ret[0].(error)
	return ret0
}

// Commit indicates an expected call of Commit.
func (mr *MockTxMockRecorder) Commit(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Commit", reflect.TypeOf((*MockTx)(nil).Commit), ctx)
}

// Exec mocks base method.
func (m *MockTx) Exec(ctx context.Context, sql string, arguments ...any) (storage.Result, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, sql}
	for _, a := range arguments {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Exec", varargs...)
	ret0, _ := ret[0].(storage.Result)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Exec indicates an expected call of Exec.
func (mr *MockTxMockRecorder) Exec(ctx, sql interface{}, arguments ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, sql}, arguments...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Exec", reflect.TypeOf((*MockTx)(nil).Exec), varargs...)
}

// Query mocks base method.
func (m *MockTx) Query(ctx context.Context, sql string, args ...any) (storage.Rows, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, sql}
	for _, a := range args {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Query", varargs...)
	ret0, _ := ret[0].(storage.Rows)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Query indicates an expected call of Query.
func (mr *MockTxMockRecorder) Query(ctx, sql interface{}, args ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, sql}, args...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Query", reflect.TypeOf((*MockTx)(nil).Query), varargs...)
}

// QueryRow mocks base method.
func (m *MockTx) QueryRow(ctx context.Context, sql string, args ...any) storage.Row {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, sql}
	for _, a := range args {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "QueryRow", varargs...)
	ret0, _ := ret[0].(storage.Row)
	return ret0
}

// QueryRow indicates an expected call of QueryRow.
func (mr *MockTxMockRecorder) QueryRow(ctx, sql interface{}, args ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, sql}, args...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "QueryRow", reflect.TypeOf((*MockTx)(nil).QueryRow), varargs...)
}

// Rollback mocks base method.
func (m *MockTx) Rollback(ctx context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Rollback", ctx)
	ret0, _ := ret[0].(error)
	return ret0
}

// Rollback indicates an expected call of Rollback.
func (mr *MockTxMockRecorder) Rollback(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Rollback", reflect.TypeOf((*MockTx)(nil).Rollback), ctx)
}

// MockRows is a mock of Rows interface.
type MockRows struct {
	ctrl     *gomock.Controller
	recorder *MockRowsMockRecorder
}

// MockRowsMockRecorder is the mock recorder for MockRows.
type MockRowsMockRecorder struct {
	mock *MockRows
}

// NewMockRows creates a new mock instance.
func NewMockRows(ctrl *gomock.Controller) *MockRows {
	mock := &MockRows{ctrl: ctrl}
	mock.recorder = &MockRowsMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRows) EXPECT() *MockRowsMockRecorder {
	return m.recorder
}

// Close mocks base method.
func (m *MockRows) Close() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Close")
}

// Close indicates an expected call of Close.
func (mr *MockRowsMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockRows)(nil).Close))
}

// Err mocks base method.
func (m *MockRows) Err() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Err")
	ret0, _ := ret[0].(error)
	return ret0
}

// Err indicates an expected call of Err.
func (mr *MockRowsMockRecorder) Err() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Err", reflect.TypeOf((*MockRows)(nil).Err))
}

// Next mocks base method.
func (m *MockRows) Next() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Next")
	ret0, _ := ret[0].(bool)
	return ret0
}

// Next indicates an expected call of Next.
func (mr *MockRowsMockRecorder) Next() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Next", reflect.TypeOf((*MockRows)(nil).Next))
}

// Scan mocks base method.
func (m *MockRows) Scan(dest ...any) error {
	m.ctrl.T.Helper()
	varargs := []interface{}{}
	for _, a := range dest {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Scan", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// Scan indicates an expected call of Scan.
func (mr *MockRowsMockRecorder) Scan(dest ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Scan", reflect.TypeOf((*MockRows)(nil).Scan), dest...)
}

// MockRow is a mock of Row interface.
type MockRow struct {
	ctrl     *gomock.Controller
	recorder *MockRowMockRecorder
}

// MockRowMockRecorder is the mock recorder for MockRow.
type MockRowMockRecorder struct {
	mock *MockRow
}

// NewMockRow creates a new mock instance.
func NewMockRow(ctrl *gomock.Controller) *MockRow {
	mock := &MockRow{ctrl: ctrl}
	mock.recorder = &MockRowMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRow) EXPECT() *MockRowMockRecorder {
	return m.recorder
}

// Scan mocks base method.
func (m *MockRow) Scan(dest ...any) error {
	m.ctrl.T.Helper()
	varargs := []interface{}{}
	for _, a := range dest {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Scan", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// Scan indicates an expected call of Scan.
func (mr *MockRowMockRecorder) Scan(dest ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Scan", reflect.TypeOf((*MockRow)(nil).Scan), dest...)
}

// MockResult is a mock of Result interface.
type MockResult struct {
	ctrl     *gomock.Controller
	recorder *MockResultMockRecorder
}

// MockResultMockRecorder is the mock recorder for MockResult.
type MockResultMockRecorder struct {
	mock *MockResult
}

// NewMockResult creates a new mock instance.
func NewMockResult(ctrl *gomock.Controller) *MockResult {
	mock := &MockResult{ctrl: ctrl}
	mock.recorder = &MockResultMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockResult) EXPECT() *MockResultMockRecorder {
	return m.recorder
}

// RowsAffected mocks base method.
func (m *MockResult) RowsAffected() (int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RowsAffected")
	ret0, _ := ret[0].(int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RowsAffected indicates an expected call of RowsAffected.
func (mr *MockResultMockRecorder) RowsAffected() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RowsAffected", reflect.TypeOf((*MockResult)(nil).RowsAffected))
}

// MockTransactionInterface is a mock of TransactionInterface interface.
type MockTransactionInterface struct {
	ctrl     *gomock.Controller
	recorder *MockTransactionInterfaceMockRecorder
}

// MockTransactionInterfaceMockRecorder is the mock recorder for MockTransactionInterface.
type MockTransactionInterfaceMockRecorder struct {
	mock *MockTransactionInterface
}

// NewMockTransactionInterface creates a new mock instance.
func NewMockTransactionInterface(ctrl *gomock.Controller) *MockTransactionInterface {
	mock := &MockTransactionInterface{ctrl: ctrl}
	mock.recorder = &MockTransactionInterfaceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTransactionInterface) EXPECT() *MockTransactionInterfaceMockRecorder {
	return m.recorder
}

// CreateTx mocks base method.
func (m *MockTransactionInterface) CreateTx(ctx context.Context, options ...storage.CreateTxOption) (storage.Tx, context.Context, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx}
	for _, a := range options {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "CreateTx", varargs...)
	ret0, _ := ret[0].(storage.Tx)
	ret1, _ := ret[1].(context.Context)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// CreateTx indicates an expected call of CreateTx.
func (mr *MockTransactionInterfaceMockRecorder) CreateTx(ctx interface{}, options ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx}, options...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateTx", reflect.TypeOf((*MockTransactionInterface)(nil).CreateTx), varargs...)
}

// MockCertStorage is a mock of CertStorage interface.
type MockCertStorage struct {
	ctrl     *gomock.Controller
	recorder *MockCertStorageMockRecorder
}

// MockCertStorageMockRecorder is the mock recorder for MockCertStorage.
type MockCertStorageMockRecorder struct {
	mock *MockCertStorage
}

// NewMockCertStorage creates a new mock instance.
func NewMockCertStorage(ctrl *gomock.Controller) *MockCertStorage {
	mock := &MockCertStorage{ctrl: ctrl}
	mock.recorder = &MockCertStorageMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockCertStorage) EXPECT() *MockCertStorageMockRecorder {
	return m.recorder
}

// AddCertificate mocks base method.
func (m *MockCertStorage) AddCertificate(ctx context.Context, tx storage.Tx, cert model.Cert) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddCertificate", ctx, tx, cert)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddCertificate indicates an expected call of AddCertificate.
func (mr *MockCertStorageMockRecorder) AddCertificate(ctx, tx, cert interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddCertificate", reflect.TypeOf((*MockCertStorage)(nil).AddCertificate), ctx, tx, cert)
}

// CreateTx mocks base method.
func (m *MockCertStorage) CreateTx(ctx context.Context, options ...storage.CreateTxOption) (storage.Tx, context.Context, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx}
	for _, a := range options {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "CreateTx", varargs...)
	ret0, _ := ret[0].(storage.Tx)
	ret1, _ := ret[1].(context.Context)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// CreateTx indicates an expected call of CreateTx.
func (mr *MockCertStorageMockRecorder) CreateTx(ctx interface{}, options ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx}, options...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateTx", reflect.TypeOf((*MockCertStorage)(nil).CreateTx), varargs...)
}

// ListCertificates mocks base method.
func (m *MockCertStorage) ListCertificates(ctx context.Context, tx storage.Tx, req storage.ListCertificatesRequest) (storage.ListCertificatesResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListCertificates", ctx, tx, req)
	ret0, _ := ret[0].(storage.ListCertificatesResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListCertificates indicates an expected call of ListCertificates.
func (mr *MockCertStorageMockRecorder) ListCertificates(ctx, tx, req interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListCertificates", reflect.TypeOf((*MockCertStorage)(nil).ListCertificates), ctx, tx, req)
}