package rbac

import (
	"encoding/json"
	"fmt"
	"sync"
)

// Permission defines rbac permission
type Permission struct {
	ID          string
	Description string
	sync.Map    // key action, val nil
}

type jsPermission struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Actions     []Action `json:"actions"`
}

func newPermission(ID, description string, actions ...Action) *Permission {
	perm := &Permission{ID: ID, Description: description}
	for _, a := range actions {
		if a == CRUD {
			perm.Store(Create, nil)
			perm.Store(Read, nil)
			perm.Store(Update, nil)
			perm.Store(Delete, nil)
		} else {
			perm.Store(a, nil)
		}
	}
	return perm
}

// String returns as string
func (p *Permission) String() string {
	return fmt.Sprintf("Permission{ID: %s, Description: %s}", p.ID, p.Description)
}

// Actions returns list of Actions
func (p *Permission) Actions() []Action {
	res := []Action{}
	p.Range(func(k, v interface{}) bool {
		res = append(res, k.(Action))
		return true
	})
	return res
}

// MarshalJSON serializes a Permission to JSON
func (p *Permission) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsPermission{
		ID:          p.ID,
		Description: p.Description,
		Actions:     p.Actions(),
	})
}
