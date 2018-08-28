/*`rbac`` is role based access control library for GOlang. At core uses
sync.Map so, it can be used from multiple goroutines concurrently.
"Keep it simple" is also in core.

It supports role inheritance.

It can be used in middleware.
*/package rbac

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

var log Logger

// RBAC is role bases access control manager
type RBAC struct {
	sync.Map             // key: role.ID, value: role
	permissions sync.Map // registered permissions
}

type jsRBAC struct {
	Permissions []*Permission `json:"permissions"`
	Roles       []*RoleGrants `json:"roles"`
}

// New returns a new RBAC instance
func New(logger Logger) *RBAC {
	SetLogger(logger)
	return &RBAC{}
}

// SetLogger sets rbac logger
func SetLogger(logger Logger) {
	if logger != nil {
		log = logger
	} else {
		log = &NullLogger{}
	}
}

// Clone clones RBAC instance
func (r *RBAC) Clone(roles bool) (trg *RBAC) {
	trg = &RBAC{}
	r.permissions.Range(func(k, v interface{}) bool {
		trg.permissions.Store(k, v)
		return true
	})
	if roles {
		r.Range(func(k, v interface{}) bool {
			trg.Store(k, v)
			return true
		})
	}
	return
}

// RegisterPermission defines and registers a permission
func (r *RBAC) RegisterPermission(permissionID, description string, actions ...Action) (*Permission, error) {
	if r.IsPermissionExist(permissionID, "") {
		log.Errorf("permission %s is already registered", permissionID)
		return nil, fmt.Errorf("permission %s is already registered", permissionID)
	}
	perm := newPermission(permissionID, description, actions...)
	r.permissions.Store(permissionID, perm)
	return perm, nil
}

// IsPermissionExist checks if a permission with target ID and action is defined
func (r *RBAC) IsPermissionExist(permissionID string, action Action) (res bool) {
	perm, res := r.permissions.Load(permissionID)
	if res && action != None {
		_, res = perm.(*Permission).Load(action)
	}
	return res
}

//RegisterRole defines and registers a role
func (r *RBAC) RegisterRole(roleID string, description string) (*Role, error) {
	if r.IsRoleExist(roleID) {
		log.Errorf("role %s is already registered", roleID)
		return nil, fmt.Errorf("role %s is already registered", roleID)
	}
	role := &Role{ID: roleID, Description: description}
	r.Store(roleID, role)
	return role, nil
}

// GetRole finds and returns role from instance, if role is not found returns nil
func (r *RBAC) GetRole(roleID string) *Role {
	rol, ok := r.Load(roleID)
	if !ok {
		log.Errorf("role %s is not registered", roleID)
		return nil
	}
	return rol.(*Role)
}

// RemoveRole deletes role from instance
func (r *RBAC) RemoveRole(roleID string) error {
	if !r.IsRoleExist(roleID) {
		log.Errorf("role %s is not registered", roleID)
		return fmt.Errorf("role %s is  not registered", roleID)
	}
	r.Delete(roleID)
	for _, role := range r.Roles() {
		if role != nil {
			if role.HasParent(roleID) {
				role.RemoveParent(role)
			}
		}
	}
	return nil
}

// Roles reuturns all registered roles
func (r *RBAC) Roles() (res []*Role) {
	r.Range(func(k, v interface{}) bool {
		res = append(res, v.(*Role))
		return true
	})
	return res
}

// IsRoleExist checks if a role with target ID is defined
func (r *RBAC) IsRoleExist(roleID string) (res bool) {
	_, res = r.Load(roleID)
	return res
}

// Permit grants a permission with defined actions to a role
func (r *RBAC) Permit(roleID string, perm *Permission, actions ...Action) error {
	if perm == nil {
		log.Errorf("nil perm is sent for revoking from role %s", roleID)
		return fmt.Errorf("permission can not be nil")
	}

	if role, ok := r.Load(roleID); ok {
		for _, a := range actions {
			// Check if this action is valid for this permission:
			if !r.IsPermissionExist(perm.ID, a) {
				log.Errorf("action %s is not registered for permission %s", a, perm.ID)
				return fmt.Errorf("action %s is not registered for permission %s", a, perm.ID)
			}
		}
		role.(*Role).grant(perm, actions...)
	} else {
		log.Errorf("role %s is not registered")
		return fmt.Errorf("role %s is not registered", roleID)
	}
	return nil
}

// Revoke removes a permission from a role
func (r *RBAC) Revoke(roleID string, perm *Permission, actions ...Action) error {
	if perm == nil {
		log.Errorf("nil perm is sent for revoking from roleRoles %s", roleID)
		return fmt.Errorf("permission can not be nil")
	}
	if role, ok := r.Load(roleID); ok {
		for _, a := range actions {
			if !r.IsPermissionExist(perm.ID, a) {
				log.Errorf("action %s is not registered for permission %s", a, perm.ID)
				return fmt.Errorf("action %s is not registered for permission %s", a, perm.ID)
			}
		}
		role.(*Role).revoke(perm, actions...)
	} else {
		log.Errorf("role %s is not registered", roleID)
		return fmt.Errorf("role %s is not registered", roleID)
	}
	return nil
}

// IsGranted checks if a role with target permission and actions has a grant
func (r *RBAC) IsGranted(roleID string, perm *Permission, actions ...Action) bool {
	if perm == nil {
		log.Errorf("Nil perm is sent for granted check for role %s", roleID)
		return false
	}
	return r.IsGrantedStr(roleID, perm.ID, actions...)
}

// IsGrantedStr checks if permID is greanted with target actions for role
func (r *RBAC) IsGrantedStr(roleID string, permID string, actions ...Action) bool {
	if role, ok := r.Load(roleID); ok {
		validActions := []Action{}
		for _, a := range actions {
			// Check if this action is valid for this permission:
			if !r.IsPermissionExist(permID, a) {
				log.Errorf("Action %s for permission %s is not defined, while checking grants for role %s", a, permID, roleID)
				return false
			}
			validActions = append(validActions, a)
		}
		if role.(*Role).isGrantedStr(permID, validActions...) {
			return true
		}
		for _, pr := range role.(*Role).Parents() {
			if pr.isGrantedStr(permID, validActions...) {
				return true
			}
		}
	}
	log.Errorf("Role with ID %s is not found while checking grants for perm %s", roleID, permID)
	return false
}

func hasAction(actions []Action, action Action) bool {
	for _, a := range actions {
		if a == action {
			return true
		}
	}
	return false
}

// GetAllPermissions returns granted permissions for a role(including inherited permissions from parents)
func (r *RBAC) GetAllPermissions(roleIDs []string) map[string][]Action {
	perms := map[string][]Action{}
	for _, roleID := range roleIDs {
		if role, ok := r.Load(roleID); ok {
			// Merge permission actions
			for k, v := range role.(*Role).getGrants() {
				if actions, ok := perms[k]; ok {
					for _, a := range v {
						if !hasAction(actions, a) {
							actions = append(actions, a)
						}
					}
					perms[k] = actions
				} else {
					perms[k] = v
				}
			}
			// Merge permission actions with parent's actions
			for _, pr := range role.(*Role).Parents() {
				for k, v := range pr.getGrants() {
					if actions, ok := perms[k]; ok {
						for _, a := range v {
							if !hasAction(actions, a) {
								actions = append(actions, a)
							}
						}
						perms[k] = actions
					} else {
						perms[k] = v
					}
				}
			}
		} else {
			log.Errorf("Role with ID %s is not found", roleID)
		}
	}
	return perms
}

// AnyGranted checks if any role has the permission.
func (r *RBAC) AnyGranted(roleIDs []string, perm *Permission, action ...Action) (res bool) {
	for _, roleID := range roleIDs {
		if r.IsGranted(roleID, perm, action...) {
			res = true
			break
		}
	}
	return res
}

// AllGranted checks if all roles have the permission.
func (r *RBAC) AllGranted(roleIDs []string, perm *Permission, action ...Action) (res bool) {
	for _, roleID := range roleIDs {
		if !r.IsGranted(roleID, perm, action...) {
			res = true
			break
		}
	}
	return !res
}

// RoleGrants returns all roles
func (r *RBAC) RoleGrants() []*RoleGrants {
	res := []*RoleGrants{}
	r.Range(func(_, v interface{}) bool {
		res = append(res, &RoleGrants{
			ID:          v.(*Role).ID,
			Description: v.(*Role).Description,
			Grants:      v.(*Role).getGrants(),
			Parents:     v.(*Role).ParentIDs(),
		})
		return true
	})
	return res
}

// Permissions returns all Permissions
func (r *RBAC) Permissions() []*Permission {
	res := []*Permission{}
	r.permissions.Range(func(_, v interface{}) bool {
		res = append(res, v.(*Permission))
		return true
	})
	return res
}

// MarshalJSON serializes a all roles to JSON
func (r *RBAC) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsRBAC{
		Roles:       r.RoleGrants(),
		Permissions: r.Permissions(),
	})
}

// UnmarshalJSON parses RBAC from JSON
func (r *RBAC) UnmarshalJSON(b []byte) (err error) {
	s := jsRBAC{}
	if err = json.Unmarshal(b, &s); err != nil {
		return err
	}
	for _, roleGrants := range s.Roles {
		_, err := r.RegisterRole(roleGrants.ID, roleGrants.Description)
		if err != nil {
			return err
		}
		for permID, actions := range roleGrants.Grants {
			perm, ok := r.permissions.Load(permID)
			if !ok {
				return fmt.Errorf("permission %s for role %s is not registered", permID, roleGrants.ID)
			}
			if err = r.Permit(roleGrants.ID, perm.(*Permission), actions...); err != nil {
				return err
			}
		}
	}

	for _, roleGrants := range s.Roles {
		role := r.GetRole(roleGrants.ID)
		if role == nil {
			log.Errorf("can not find role %s", roleGrants.ID)
		} else {
			for _, parentID := range roleGrants.Parents {
				parentRole := r.GetRole(parentID)
				if parentRole == nil {
					log.Errorf("can not find parent role %s for role %s", parentID, parentRole.ID)
				} else {
					role.AddParent(parentRole)
				}
			}
		}
	}
	return nil
}

// LoadJSON loads all data from a reader
func (r *RBAC) LoadJSON(reader io.Reader) error {
	return json.NewDecoder(reader).Decode(r)
}

// SaveJSON saves all to a writer
func (r *RBAC) SaveJSON(writer io.Writer) (err error) {
	enc := json.NewEncoder(writer)
	enc.SetIndent("", "  ")
	if err = enc.Encode(jsRBAC{
		Roles:       r.RoleGrants(),
		Permissions: r.Permissions(),
	}); err != nil {
		log.Errorf("can not encode to json, err:%v", err)
		return err
	}
	return nil
}
