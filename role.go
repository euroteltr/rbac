package rbac

import (
	"fmt"
	"sync"
)

// Role defines a role
type Role struct {
	ID          string     `json:"id"`
	Description string     `json:"description"`
	sync.Map    `json:"-"` // key: permissionID, values sync.Map[action]=true/false
	parents     sync.Map
}

type grantsMap map[string][]Action

// RoleGrants is used during JSON Marshalling
type RoleGrants struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	Grants      grantsMap `json:"grants"`
	Parents     []string  `json:"parents"`
}

func (r *Role) grant(p *Permission, actions ...Action) {
	var acts interface{}
	var ok bool
	if acts, ok = r.Load(p.ID); !ok {
		acts = &sync.Map{}
		r.Store(p.ID, acts)
	}
	for _, a := range actions {
		acts.(*sync.Map).Store(a, true)
	}
}

func (r *Role) revoke(p *Permission, actions ...Action) {
	if acts, ok := r.Load(p.ID); ok {
		for _, a := range actions {
			acts.(*sync.Map).Store(a, false)
		}
		// Remove permission from role if all actions are false
		hasTrue := false
		acts.(*sync.Map).Range(func(_, v interface{}) bool {
			if v.(bool) == true {
				hasTrue = true
				return false
			}
			return true
		})
		if !hasTrue {
			log.Debugf("Deleting permission %s from role %s as no valid action found", p.ID, r.ID)
			r.Delete(p.ID)
		}
	}
}

func (r *Role) isGranted(p *Permission, actions ...Action) (res bool) {
	return r.isGrantedStr(p.ID, actions...)
}

func (r *Role) isGrantedStr(pID string, actions ...Action) bool {
	if acts, ok := r.Load(pID); ok {
		for _, a := range actions {
			resI, ok := acts.(*sync.Map).Load(a)
			if !ok || resI == nil || resI.(bool) == false {
				log.Debugf("action %s is not granted to perm %s, found %v, %v", a, pID, ok, resI)
				return false
			}
		}
		return true
	}
	log.Debugf("permission %s is not granted to role %s", pID, r.ID)

	return false
}

func (r *Role) getGrants() grantsMap {
	var res = make(map[string][]Action)

	r.Range(func(permID, v interface{}) bool {
		if _, ok := res[permID.(string)]; !ok {
			res[permID.(string)] = []Action{}
		}
		v.(*sync.Map).Range(func(a, _ interface{}) bool {
			res[permID.(string)] = append(res[permID.(string)], a.(Action))
			return true
		})
		return true
	})
	return res
}

// HasParent checks if a role is in parent roles
func (r *Role) HasParent(parentID string) bool {
	ok := hasParentDeep(r, parentID)
	return ok
}

// hasParentDeep check the parent tree for the parentID
func hasParentDeep(child *Role, parentID string) (found bool) {
	if _, ok := child.parents.Load(parentID); ok {
		return ok
	}
	found = false
	child.parents.Range(func(key, value interface{}) bool {
		found = hasParentDeep(value.(*Role), parentID)
		if found {
			// returning false breaks out of Range call.
			return false
		}
		// returning true continues Range call.
		return true
	})
	return found
}

// AddParent Adds parent role
func (r *Role) AddParent(parentRole *Role) error {
	if _, ok := r.parents.Load(parentRole.ID); ok {
		log.Errorf("parent role with ID %s is already defined for role %s", parentRole.ID, r.ID)
		return fmt.Errorf("parent role with ID %s is already defined for role %s", parentRole.ID, r.ID)
	}
	if parentRole.HasParent(r.ID) {
		log.Errorf("circular reference is found for parentrole:%s while adding to role:%s", parentRole.ID, r.ID)
		return fmt.Errorf("circular reference is found for parentrole:%s while adding to role:%s", parentRole.ID, r.ID)
	}
	r.parents.Store(parentRole.ID, parentRole)
	return nil
}

// RemoveParent removes parent role
func (r *Role) RemoveParent(parentRole *Role) error {
	if _, ok := r.parents.Load(parentRole.ID); !ok {
		log.Errorf("parent role with ID %s is not defined for role %s", parentRole.ID, r.ID)
		return fmt.Errorf("parent role with ID %s is not defined for role %s", parentRole.ID, r.ID)
	}
	r.parents.Delete(parentRole.ID)
	return nil
}

// Parents returns list of parent roles
func (r *Role) Parents() []*Role {
	res := []*Role{}
	r.parents.Range(func(_, v interface{}) bool {
		res = append(res, v.(*Role))
		return true
	})
	return res
}

// ParentIDs return a list of parent role IDs
func (r *Role) ParentIDs() []string {
	res := []string{}
	for _, r := range r.Parents() {
		res = append(res, r.ID)
	}
	return res
}
