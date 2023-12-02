package main

import (
	"fmt"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
)

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
`

func initEnforcer() (*casbin.Enforcer, error) {

	a := NewStringAdapter(policy)
	m, err := model.NewModelFromString(conf)
	if err != nil {
		return nil, fmt.Errorf("model.NewModelFromString. err: %w", err)
	}

	e, err := casbin.NewEnforcer(m, a)
	if err != nil {
		return nil, fmt.Errorf("casbin.NewEnforcer. err: %w", err)
	}

	return e, nil
}

func main() {
	{
		e, err := initEnforcer()
		if err != nil {
			panic(err)
		}
		ok, err := e.Enforce("alice", "data1", "read")
		if err != nil {
			panic(err)
		}
		fmt.Println(ok)
	}
	e, err := casbin.NewEnforcer("model.conf", "policy.csv")
	ok, err := e.Enforce("alice", "data1", "read")
	if err != nil {
		panic(err)
	}
	fmt.Println(ok)
	fmt.Println("Hello")
}
