// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/ory/fosite (interfaces: TokenExchangeAccessRequester)

// Package internal is a generated GoMock package.
package internal

import (
	url "net/url"
	reflect "reflect"
	time "time"

	gomock "github.com/golang/mock/gomock"
	fosite "github.com/ory/fosite"
)

// MockTokenExchangeAccessRequester is a mock of TokenExchangeAccessRequester interface.
type MockTokenExchangeAccessRequester struct {
	ctrl     *gomock.Controller
	recorder *MockTokenExchangeAccessRequesterMockRecorder
}

// MockTokenExchangeAccessRequesterMockRecorder is the mock recorder for MockTokenExchangeAccessRequester.
type MockTokenExchangeAccessRequesterMockRecorder struct {
	mock *MockTokenExchangeAccessRequester
}

// NewMockTokenExchangeAccessRequester creates a new mock instance.
func NewMockTokenExchangeAccessRequester(ctrl *gomock.Controller) *MockTokenExchangeAccessRequester {
	mock := &MockTokenExchangeAccessRequester{ctrl: ctrl}
	mock.recorder = &MockTokenExchangeAccessRequesterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTokenExchangeAccessRequester) EXPECT() *MockTokenExchangeAccessRequesterMockRecorder {
	return m.recorder
}

// AppendRequestedScope mocks base method.
func (m *MockTokenExchangeAccessRequester) AppendRequestedScope(arg0 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "AppendRequestedScope", arg0)
}

// AppendRequestedScope indicates an expected call of AppendRequestedScope.
func (mr *MockTokenExchangeAccessRequesterMockRecorder) AppendRequestedScope(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AppendRequestedScope", reflect.TypeOf((*MockTokenExchangeAccessRequester)(nil).AppendRequestedScope), arg0)
}

// GetClient mocks base method.
func (m *MockTokenExchangeAccessRequester) GetClient() fosite.Client {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetClient")
	ret0, _ := ret[0].(fosite.Client)
	return ret0
}

// GetClient indicates an expected call of GetClient.
func (mr *MockTokenExchangeAccessRequesterMockRecorder) GetClient() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetClient", reflect.TypeOf((*MockTokenExchangeAccessRequester)(nil).GetClient))
}

// GetGrantTypes mocks base method.
func (m *MockTokenExchangeAccessRequester) GetGrantTypes() fosite.Arguments {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGrantTypes")
	ret0, _ := ret[0].(fosite.Arguments)
	return ret0
}

// GetGrantTypes indicates an expected call of GetGrantTypes.
func (mr *MockTokenExchangeAccessRequesterMockRecorder) GetGrantTypes() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGrantTypes", reflect.TypeOf((*MockTokenExchangeAccessRequester)(nil).GetGrantTypes))
}

// GetGrantedAudience mocks base method.
func (m *MockTokenExchangeAccessRequester) GetGrantedAudience() fosite.Arguments {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGrantedAudience")
	ret0, _ := ret[0].(fosite.Arguments)
	return ret0
}

// GetGrantedAudience indicates an expected call of GetGrantedAudience.
func (mr *MockTokenExchangeAccessRequesterMockRecorder) GetGrantedAudience() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGrantedAudience", reflect.TypeOf((*MockTokenExchangeAccessRequester)(nil).GetGrantedAudience))
}

// GetGrantedScopes mocks base method.
func (m *MockTokenExchangeAccessRequester) GetGrantedScopes() fosite.Arguments {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGrantedScopes")
	ret0, _ := ret[0].(fosite.Arguments)
	return ret0
}

// GetGrantedScopes indicates an expected call of GetGrantedScopes.
func (mr *MockTokenExchangeAccessRequesterMockRecorder) GetGrantedScopes() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGrantedScopes", reflect.TypeOf((*MockTokenExchangeAccessRequester)(nil).GetGrantedScopes))
}

// GetID mocks base method.
func (m *MockTokenExchangeAccessRequester) GetID() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetID")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetID indicates an expected call of GetID.
func (mr *MockTokenExchangeAccessRequesterMockRecorder) GetID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetID", reflect.TypeOf((*MockTokenExchangeAccessRequester)(nil).GetID))
}

// GetRequestForm mocks base method.
func (m *MockTokenExchangeAccessRequester) GetRequestForm() url.Values {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRequestForm")
	ret0, _ := ret[0].(url.Values)
	return ret0
}

// GetRequestForm indicates an expected call of GetRequestForm.
func (mr *MockTokenExchangeAccessRequesterMockRecorder) GetRequestForm() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRequestForm", reflect.TypeOf((*MockTokenExchangeAccessRequester)(nil).GetRequestForm))
}

// GetRequestedAt mocks base method.
func (m *MockTokenExchangeAccessRequester) GetRequestedAt() time.Time {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRequestedAt")
	ret0, _ := ret[0].(time.Time)
	return ret0
}

// GetRequestedAt indicates an expected call of GetRequestedAt.
func (mr *MockTokenExchangeAccessRequesterMockRecorder) GetRequestedAt() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRequestedAt", reflect.TypeOf((*MockTokenExchangeAccessRequester)(nil).GetRequestedAt))
}

// GetRequestedAudience mocks base method.
func (m *MockTokenExchangeAccessRequester) GetRequestedAudience() fosite.Arguments {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRequestedAudience")
	ret0, _ := ret[0].(fosite.Arguments)
	return ret0
}

// GetRequestedAudience indicates an expected call of GetRequestedAudience.
func (mr *MockTokenExchangeAccessRequesterMockRecorder) GetRequestedAudience() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRequestedAudience", reflect.TypeOf((*MockTokenExchangeAccessRequester)(nil).GetRequestedAudience))
}

// GetRequestedScopes mocks base method.
func (m *MockTokenExchangeAccessRequester) GetRequestedScopes() fosite.Arguments {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRequestedScopes")
	ret0, _ := ret[0].(fosite.Arguments)
	return ret0
}

// GetRequestedScopes indicates an expected call of GetRequestedScopes.
func (mr *MockTokenExchangeAccessRequesterMockRecorder) GetRequestedScopes() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRequestedScopes", reflect.TypeOf((*MockTokenExchangeAccessRequester)(nil).GetRequestedScopes))
}

// GetSession mocks base method.
func (m *MockTokenExchangeAccessRequester) GetSession() fosite.Session {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSession")
	ret0, _ := ret[0].(fosite.Session)
	return ret0
}

// GetSession indicates an expected call of GetSession.
func (mr *MockTokenExchangeAccessRequesterMockRecorder) GetSession() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSession", reflect.TypeOf((*MockTokenExchangeAccessRequester)(nil).GetSession))
}

// GetSubjectTokenClient mocks base method.
func (m *MockTokenExchangeAccessRequester) GetSubjectTokenClient() fosite.TokenExchangeClient {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSubjectTokenClient")
	ret0, _ := ret[0].(fosite.TokenExchangeClient)
	return ret0
}

// GetSubjectTokenClient indicates an expected call of GetSubjectTokenClient.
func (mr *MockTokenExchangeAccessRequesterMockRecorder) GetSubjectTokenClient() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSubjectTokenClient", reflect.TypeOf((*MockTokenExchangeAccessRequester)(nil).GetSubjectTokenClient))
}

// GrantAudience mocks base method.
func (m *MockTokenExchangeAccessRequester) GrantAudience(arg0 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "GrantAudience", arg0)
}

// GrantAudience indicates an expected call of GrantAudience.
func (mr *MockTokenExchangeAccessRequesterMockRecorder) GrantAudience(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GrantAudience", reflect.TypeOf((*MockTokenExchangeAccessRequester)(nil).GrantAudience), arg0)
}

// GrantScope mocks base method.
func (m *MockTokenExchangeAccessRequester) GrantScope(arg0 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "GrantScope", arg0)
}

// GrantScope indicates an expected call of GrantScope.
func (mr *MockTokenExchangeAccessRequesterMockRecorder) GrantScope(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GrantScope", reflect.TypeOf((*MockTokenExchangeAccessRequester)(nil).GrantScope), arg0)
}

// Merge mocks base method.
func (m *MockTokenExchangeAccessRequester) Merge(arg0 fosite.Requester) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Merge", arg0)
}

// Merge indicates an expected call of Merge.
func (mr *MockTokenExchangeAccessRequesterMockRecorder) Merge(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Merge", reflect.TypeOf((*MockTokenExchangeAccessRequester)(nil).Merge), arg0)
}

// Sanitize mocks base method.
func (m *MockTokenExchangeAccessRequester) Sanitize(arg0 []string) fosite.Requester {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Sanitize", arg0)
	ret0, _ := ret[0].(fosite.Requester)
	return ret0
}

// Sanitize indicates an expected call of Sanitize.
func (mr *MockTokenExchangeAccessRequesterMockRecorder) Sanitize(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Sanitize", reflect.TypeOf((*MockTokenExchangeAccessRequester)(nil).Sanitize), arg0)
}

// SetID mocks base method.
func (m *MockTokenExchangeAccessRequester) SetID(arg0 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetID", arg0)
}

// SetID indicates an expected call of SetID.
func (mr *MockTokenExchangeAccessRequesterMockRecorder) SetID(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetID", reflect.TypeOf((*MockTokenExchangeAccessRequester)(nil).SetID), arg0)
}

// SetRequestedAudience mocks base method.
func (m *MockTokenExchangeAccessRequester) SetRequestedAudience(arg0 fosite.Arguments) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetRequestedAudience", arg0)
}

// SetRequestedAudience indicates an expected call of SetRequestedAudience.
func (mr *MockTokenExchangeAccessRequesterMockRecorder) SetRequestedAudience(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetRequestedAudience", reflect.TypeOf((*MockTokenExchangeAccessRequester)(nil).SetRequestedAudience), arg0)
}

// SetRequestedScopes mocks base method.
func (m *MockTokenExchangeAccessRequester) SetRequestedScopes(arg0 fosite.Arguments) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetRequestedScopes", arg0)
}

// SetRequestedScopes indicates an expected call of SetRequestedScopes.
func (mr *MockTokenExchangeAccessRequesterMockRecorder) SetRequestedScopes(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetRequestedScopes", reflect.TypeOf((*MockTokenExchangeAccessRequester)(nil).SetRequestedScopes), arg0)
}

// SetSession mocks base method.
func (m *MockTokenExchangeAccessRequester) SetSession(arg0 fosite.Session) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetSession", arg0)
}

// SetSession indicates an expected call of SetSession.
func (mr *MockTokenExchangeAccessRequesterMockRecorder) SetSession(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetSession", reflect.TypeOf((*MockTokenExchangeAccessRequester)(nil).SetSession), arg0)
}

// SetSubjectTokenClient mocks base method.
func (m *MockTokenExchangeAccessRequester) SetSubjectTokenClient(arg0 fosite.TokenExchangeClient) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetSubjectTokenClient", arg0)
}

// SetSubjectTokenClient indicates an expected call of SetSubjectTokenClient.
func (mr *MockTokenExchangeAccessRequesterMockRecorder) SetSubjectTokenClient(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetSubjectTokenClient", reflect.TypeOf((*MockTokenExchangeAccessRequester)(nil).SetSubjectTokenClient), arg0)
}
