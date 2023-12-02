package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_rbac_role_hierarchy(t *testing.T) {
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
	p, team1, data1, read
	p, team1, data1, write
	p, team2, data2, read
	p, team2, data2, write
	p, all_users, public_data, read
	p, data_admin, public_data, write

	g, alice, team1
	g, bob, team2
	g, charlie, team3
	g, team1, all_users
	g, team2, all_users
	g, team3, all_users
	g, charlie, data_admin
	`

	e := NewEnforcer(t, conf, policy)
	tests := []test_soa{
		{subject: "alice", object: "data1", action: "read", want: true},
		{subject: "alice", object: "data1", action: "write", want: true},
		{subject: "alice", object: "data2", action: "read", want: false},
		{subject: "alice", object: "data2", action: "write", want: false},
		{subject: "alice", object: "public_data", action: "read", want: true},
		{subject: "alice", object: "public_data", action: "write", want: false},

		{subject: "bob", object: "data1", action: "read", want: false},
		{subject: "bob", object: "data1", action: "write", want: false},
		{subject: "bob", object: "data2", action: "read", want: true},
		{subject: "bob", object: "data2", action: "write", want: true},
		{subject: "bob", object: "public_data", action: "read", want: true},
		{subject: "bob", object: "public_data", action: "write", want: false},

		{subject: "charlie", object: "data1", action: "read", want: false},
		{subject: "charlie", object: "data1", action: "write", want: false},
		{subject: "charlie", object: "data2", action: "read", want: false},
		{subject: "charlie", object: "data2", action: "write", want: false},
		{subject: "charlie", object: "public_data", action: "read", want: true},
		{subject: "charlie", object: "public_data", action: "write", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.String(), func(t *testing.T) {
			ok, err := e.Enforce(tt.subject, tt.object, tt.action)
			require.NoError(t, err)
			assert.Equal(t, tt.want, ok)
		})
	}
}
