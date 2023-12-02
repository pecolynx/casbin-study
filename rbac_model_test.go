package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_rbac_model(t *testing.T) {
	const conf = `
	[request_definition]
	r = sub, obj, act
	
	[policy_definition]
	p = sub, obj, act
	
	[role_definition]
	g = _, _
	
	[policy_effect]
	e = some(where (p.eft == allow))
	
	[matchers]
	m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
	`

	const policy = `
	p, alice, data1, read
	p, bob, data2, write
	p, data2_admin, data2, read
	p, data2_admin, data2, write
	
	g, alice, data2_admin
	`

	e := NewEnforcer(t, conf, policy)
	tests := []test_soa{
		{subject: "alice", object: "data1", action: "read", want: true},
		{subject: "alice", object: "data1", action: "write", want: false},
		{subject: "alice", object: "data2", action: "read", want: true},
		{subject: "alice", object: "data2", action: "write", want: true},

		{subject: "bob", object: "data1", action: "read", want: false},
		{subject: "bob", object: "data1", action: "write", want: false},
		{subject: "bob", object: "data2", action: "read", want: false},
		{subject: "bob", object: "data2", action: "write", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.String(), func(t *testing.T) {
			ok, err := e.Enforce(tt.subject, tt.object, tt.action)
			require.NoError(t, err)
			assert.Equal(t, tt.want, ok)
		})
	}
}
