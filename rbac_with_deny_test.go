package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_rbac_with_deny(t *testing.T) {
	const conf = `
	[request_definition]
	r = sub, obj, act

	[policy_definition]
	p = sub, obj, act, eft

	[role_definition]
	g = _, _

	[policy_effect]
	e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

	[matchers]
	m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
	`

	const policy = `
	p, alice, data1, read, allow
	p, bob, data2, write, allow
	p, data2_admin, data2, read, allow
	p, data2_admin, data2, write, allow
	p, alice, data2, write, deny

	g, alice, data2_admin
	`

	e := NewEnforcer(t, conf, policy)
	tests := []test_soa{
		{subject: "alice", object: "data1", action: "read", want: true},
		{subject: "alice", object: "data1", action: "write", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.String(), func(t *testing.T) {
			ok, err := e.Enforce(tt.subject, tt.object, tt.action)
			require.NoError(t, err)
			assert.Equal(t, tt.want, ok)
		})
	}
}
