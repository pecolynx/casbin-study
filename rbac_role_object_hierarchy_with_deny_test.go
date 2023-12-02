package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_rbac_role_object_hierarchy_with_deny(t *testing.T) {
	const conf = `
	[request_definition]
	r = sub, obj, act

	[policy_definition]
	p = sub, obj, act, eft

	[role_definition]
	g = _, _
	g2 = _, _

	[policy_effect]
	e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

	[matchers]
	m = g(r.sub, p.sub) && g2(r.obj, p.obj) && r.act == p.act
	`

	const policy = `
	p, group1, data1, read, allow
	p, group2, data2, read, deny
	p, group3, data3, read, allow

	g, alice, group3
	g, group3, group2
	g, group2, group1

	g2, data3, data2
	g2, data2, data1
	`

	e := NewEnforcer(t, conf, policy)
	tests := []test_soa{
		{subject: "alice", object: "data1", action: "read", want: true},
		{subject: "alice", object: "data2", action: "read", want: false},
		{subject: "alice", object: "data3", action: "read", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.String(), func(t *testing.T) {
			ok, err := e.Enforce(tt.subject, tt.object, tt.action)
			require.NoError(t, err)
			assert.Equal(t, tt.want, ok)
		})
	}
}
