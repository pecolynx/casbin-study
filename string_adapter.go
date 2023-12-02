package main

import (
	"errors"
	"strings"
	"unicode"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
)

// type Adapter interface {
// 	// LoadPolicy loads all policy rules from the storage.
// 	LoadPolicy(model model.Model) error
// 	// SavePolicy saves all policy rules to the storage.
// 	SavePolicy(model model.Model) error

// 	// AddPolicy adds a policy rule to the storage.
// 	// This is part of the Auto-Save feature.
// 	AddPolicy(sec string, ptype string, rule []string) error
// 	// RemovePolicy removes a policy rule from the storage.
// 	// This is part of the Auto-Save feature.
// 	RemovePolicy(sec string, ptype string, rule []string) error
// 	// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
// 	// This is part of the Auto-Save feature.
// 	RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error
// }

type stringAdapter struct {
	policy string
}

func NewStringAdapter(policy string) *stringAdapter {
	return &stringAdapter{
		policy: policy,
	}
}

func (a *stringAdapter) LoadPolicy(model model.Model) error {
	strs := strings.Split(a.policy, "\n")
	for _, s := range strs {
		s = strings.TrimLeftFunc(s, unicode.IsSpace)
		if s == "" {
			continue
		}
		persist.LoadPolicyLine(s, model)
	}

	return nil
}

func (a *stringAdapter) SavePolicy(model model.Model) error {
	return errors.New("not implemented")
}

func (a *stringAdapter) AddPolicy(sec string, ptype string, rule []string) error {
	return errors.New("not implemented")
}

func (a *stringAdapter) RemovePolicy(sec string, ptype string, rule []string) error {
	return errors.New("not implemented")
}

func (a *stringAdapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return errors.New("not implemented")
}
