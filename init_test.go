package main

import (
	"fmt"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/stretchr/testify/require"
)

type test_soa struct {
	subject string
	object  string
	action  string
	want    bool
}

func (t *test_soa) String() string {
	return fmt.Sprintf("%s,%s,%s,%v", t.subject, t.object, t.action, t.want)
}

type test_sdoa struct {
	subject string
	domain  string
	object  string
	action  string
	want    bool
}

func (t *test_sdoa) String() string {
	return fmt.Sprintf("%s,%s,%s,%s,%v", t.subject, t.domain, t.object, t.action, t.want)
}
func NewEnforcer(t *testing.T, conf, policy string) *casbin.Enforcer {
	a := NewStringAdapter(policy)
	m, err := model.NewModelFromString(conf)
	require.NoError(t, err)
	require.NotNil(t, m)
	e, err := casbin.NewEnforcer(m, a)
	require.NoError(t, err)

	return e
}
