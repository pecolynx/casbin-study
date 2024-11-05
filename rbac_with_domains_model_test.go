package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_rbac_with_domains_model(t *testing.T) {
	const conf = `
	[request_definition]
	r = sub, obj, act, dom
	
	[policy_definition]
	p = sub, obj, act, dom
	
	[role_definition]
	g = _, _, _
	
	[policy_effect]
	e = some(where (p.eft == allow))
	
	[matchers]
	m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
	`

	const policy = `
	p, admin, data1, read, domain1
	p, admin, data1, write, domain1
	p, admin, data2, read, domain2
	p, admin, data2, write, domain2

	g, alice, admin, domain1
	g, bob, admin, domain2
	`

	e := NewEnforcer(t, conf, policy)
	tests := []test_sdoa{
		{subject: "alice", domain: "domain1", object: "data1", action: "read", want: true},
		{subject: "alice", domain: "domain1", object: "data1", action: "write", want: true},
		{subject: "alice", domain: "domain2", object: "data2", action: "read", want: false},
		{subject: "alice", domain: "domain2", object: "data2", action: "write", want: false},

		{subject: "bob", domain: "domain1", object: "data1", action: "read", want: false},
		{subject: "bob", domain: "domain1", object: "data1", action: "write", want: false},
		{subject: "bob", domain: "domain2", object: "data2", action: "read", want: true},
		{subject: "bob", domain: "domain2", object: "data2", action: "write", want: true},
	}
	// actions
	assert.Equal(t, []string{"read", "write"}, e.GetAllNamedActions("p"))
	assert.Equal(t, []string{"read", "write"}, e.GetAllActions())

	assert.Equal(t, []string{"admin"}, e.GetAllSubjects())
	assert.Equal(t, []string{"admin"}, e.GetAllNamedSubjects("p"))
	assert.Equal(t, []string{"alice", "admin"}, e.GetAllUsersByDomain("domain1"))
	assert.Equal(t, []string{"bob", "admin"}, e.GetAllUsersByDomain("domain2"))

	assert.Equal(t, []string{"data1", "data2"}, e.GetAllObjects())
	assert.Equal(t, []string{"data1", "data2"}, e.GetAllNamedObjects("p"))

	assert.Equal(t, []string{"admin"}, e.GetAllRolesByDomain("domain1"))
	assert.Equal(t, []string{"admin"}, e.GetAllRoles())

	// assert.Equal(t, nil, e.GetAllNamedRoles("p"))
	assert.Equal(t, [][]string{{"alice", "admin", "domain1"}, {"bob", "admin", "domain2"}}, e.GetGroupingPolicy())
	// assert.Equal(t, nil, e.GetNamedGroupingPolicy("p"))

	for _, tt := range tests {
		t.Run(tt.String(), func(t *testing.T) {
			ok, err := e.Enforce(tt.subject, tt.object, tt.action, tt.domain)
			require.NoError(t, err)
			assert.Equal(t, tt.want, ok)
		})
	}
}
