package main

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sortStrings(x []string) []string {
	sort.Strings(x)
	return x
}

func Test_delete(t *testing.T) {
	const conf = `
	[request_definition]
	r = sub, obj, act, dom
	
	[policy_definition]
	p = sub, obj, act, eft, dom
	
	[role_definition]
	g = _, _, _
	g2 = _, _, _
	
	[policy_effect]
	e = some(where (p.eft == allow)) && !some(where (p.eft == deny))
	
	[matchers]
	m = g(r.sub, p.sub, r.dom) && (keyMatch(r.obj, p.obj) || g2(r.obj, p.obj, r.dom)) && r.act == p.act
	`

	const policy = `
	p, alice, domain:1_data:1, read, allow, domain1
	p, bob, domain:2_data:2, write, allow, domain2
	p, bob, domain:1_data:2, write, allow, domain1
	p, charlie, domain:1_data*, read, allow, domain1
	p, domain:1_data2_admin, domain:1_data:2, read, allow, domain1
	p, domain:1_data2_admin, domain:1_data:2, write, allow, domain1
	
	g, alice, domain:1_data2_admin, domain1
	g2, domain:1_data_child, domain:1_data_parent, domain1
	g2, domain:2_data_child, domain:2_data_parent, domain2
	`

	e := NewEnforcer(t, conf, policy)

	tests := []test_sdoa{
		{subject: "alice", domain: "domain1", object: "domain:1_data:1", action: "read", want: true},
		{subject: "alice", domain: "domain1", object: "domain:1_data:1", action: "write", want: false},
		{subject: "alice", domain: "domain1", object: "domain:1_data:2", action: "read", want: true},
		{subject: "alice", domain: "domain1", object: "domain:1_data:2", action: "write", want: true},

		{subject: "bob", domain: "domain1", object: "domain:1_data:1", action: "read", want: false},
		{subject: "bob", domain: "domain1", object: "domain:1_data:1", action: "write", want: false},
		{subject: "bob", domain: "domain1", object: "domain:1_data:2", action: "read", want: false},
		{subject: "bob", domain: "domain1", object: "domain:1_data:2", action: "write", want: true},

		{subject: "charlie", domain: "domain1", object: "domain:1_data:2", action: "read", want: true},
		{subject: "charlie", domain: "domain1", object: "domain:1_data_parent", action: "read", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.String(), func(t *testing.T) {
			ok, err := e.Enforce(tt.subject, tt.object, tt.action, tt.domain)
			require.NoError(t, err)
			assert.Equal(t, tt.want, ok)
		})
	}

	// actions
	assert.Equal(t, []string{"read", "write"}, e.GetAllNamedActions("p"))
	assert.Equal(t, []string{"read", "write"}, e.GetAllActions())

	assert.Equal(t, []string{"alice", "bob", "charlie", "domain:1_data2_admin"}, e.GetAllSubjects())
	assert.Equal(t, []string{"alice", "bob", "charlie", "domain:1_data2_admin"}, e.GetAllNamedSubjects("p"))
	assert.Equal(t, []string{"alice", "bob", "charlie", "domain:1_data2_admin"}, e.GetAllUsersByDomain("domain1"))

	assert.Equal(t, []string{"domain:1_data:1", "domain:2_data:2", "domain:1_data:2", "domain:1_data*"}, e.GetAllObjects())
	assert.Equal(t, []string{"domain:1_data:1", "domain:2_data:2", "domain:1_data:2", "domain:1_data*"}, e.GetAllNamedObjects("p"))

	assert.Equal(t, []string{"domain:1_data2_admin"}, e.GetAllRolesByDomain("domain1"))
	assert.Equal(t, []string{"domain:1_data2_admin", "domain:1_data_parent", "domain:2_data_parent"}, sortStrings(e.GetAllRoles()))

	// assert.Equal(t, nil, e.GetAllNamedRoles("p"))
	assert.Equal(t, [][]string{{"alice", "domain:1_data2_admin", "domain1"}}, e.GetGroupingPolicy())
	assert.Equal(t, [][]string{{"alice", "domain:1_data2_admin", "domain1"}}, e.GetNamedGroupingPolicy("g"))
	assert.Equal(t, [][]string{
		{"domain:1_data_child", "domain:1_data_parent", "domain1"},
		{"domain:2_data_child", "domain:2_data_parent", "domain2"},
	}, e.GetNamedGroupingPolicy("g2"))
	// assert.Equal(t, nil, e.GetNamedGroupingPolicy("p"))

	assert.Equal(t, [][]string{
		{"alice", "domain:1_data:1", "read", "allow", "domain1"},
		{"bob", "domain:2_data:2", "write", "allow", "domain2"},
		{"bob", "domain:1_data:2", "write", "allow", "domain1"},
		{"charlie", "domain:1_data*", "read", "allow", "domain1"},
		{"domain:1_data2_admin", "domain:1_data:2", "read", "allow", "domain1"},
		{"domain:1_data2_admin", "domain:1_data:2", "write", "allow", "domain1"},
	}, e.GetNamedPolicy("p"))

	// delete user
	assert.Equal(t, [][]string{{"alice", "domain:1_data:1", "read", "allow", "domain1"}}, e.GetFilteredNamedPolicy("p", 0, "alice"))
	ok, err := e.RemoveFilteredNamedPolicy("p", 0, "alice")
	assert.True(t, ok)
	assert.NoError(t, err)
	assert.Len(t, e.GetFilteredNamedPolicy("p", 0, "alice"), 0)
	ok, err = e.AddNamedPolicy("p", "alice", "domain:1_data:1", "read", "allow", "domain1")
	assert.True(t, ok)
	assert.NoError(t, err)
	assert.Equal(t, [][]string{{"alice", "domain:1_data:1", "read", "allow", "domain1"}}, e.GetFilteredNamedPolicy("p", 0, "alice"))

	ok, err = e.RemoveNamedPolicy("p", "alice", "domain:1_data:1", "read", "allow", "domain1")
	assert.True(t, ok)
	assert.NoError(t, err)
	assert.Len(t, e.GetFilteredNamedPolicy("p", 0, "alice"), 0)

	// delete role
	assert.Equal(t, [][]string{
		{"domain:1_data2_admin", "domain:1_data:2", "read", "allow", "domain1"},
		{"domain:1_data2_admin", "domain:1_data:2", "write", "allow", "domain1"},
	}, e.GetFilteredNamedPolicy("p", 0, "domain:1_data2_admin"))
	ok, err = e.RemoveFilteredNamedPolicy("p", 0, "domain:1_data2_admin")
	assert.True(t, ok)
	assert.NoError(t, err)
	assert.Len(t, e.GetFilteredNamedPolicy("p", 0, "domain:1_data2_admin"), 0)

	// delete grouping subject
	assert.Equal(t, [][]string{{"alice", "domain:1_data2_admin", "domain1"}}, e.GetNamedGroupingPolicy("g"))
	ok, err = e.RemoveFilteredNamedGroupingPolicy("g", 0, "alice")
	assert.True(t, ok)
	assert.NoError(t, err)
	assert.Len(t, e.GetNamedGroupingPolicy("g"), 0)

	ok, err = e.AddNamedGroupingPolicy("g", "alice", "domain:1_data2_admin", "domain1")
	assert.True(t, ok)
	assert.NoError(t, err)
	assert.Equal(t, [][]string{{"alice", "domain:1_data2_admin", "domain1"}}, e.GetNamedGroupingPolicy("g"))

	ok, err = e.RemoveNamedGroupingPolicy("g", "alice", "domain:1_data2_admin", "domain1")
	assert.True(t, ok)
	assert.NoError(t, err)
	assert.Len(t, e.GetNamedGroupingPolicy("g"), 0)

	// delete grouping object
	assert.Equal(t, [][]string{
		{"domain:1_data_child", "domain:1_data_parent", "domain1"},
		{"domain:2_data_child", "domain:2_data_parent", "domain2"},
	}, e.GetNamedGroupingPolicy("g2"))
	ok, err = e.RemoveFilteredNamedGroupingPolicy("g2", 0, "domain:1_data_child")
	assert.True(t, ok)
	assert.NoError(t, err)
	assert.Len(t, e.GetNamedGroupingPolicy("g2"), 1)
	ok, err = e.RemoveFilteredNamedGroupingPolicy("g2", 0, "domain:2_data_child")
	assert.True(t, ok)
	assert.NoError(t, err)
	assert.Len(t, e.GetNamedGroupingPolicy("g2"), 0)
}
