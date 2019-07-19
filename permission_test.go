package rbac

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

func TestPermission(t *testing.T) {
	R := New(nil) //NewConsoleLogger()
	crudActions := []Action{Create, Read, Update, Delete}
	usersPerm, err := R.RegisterPermission("users", "User resource", crudActions...)
	if err != nil {
		t.Fatalf("can not register users permission, err: %v", err)
	}
	if len(usersPerm.Actions()) != len(crudActions) {
		t.Fatalf("user permission actions are not valid, expected %d items, got %d items", len(crudActions), len(usersPerm.Actions()))
	}

	_, err = json.Marshal(usersPerm)
	if err != nil {
		t.Fatalf("users json marshall failed with %v", err)
	}
	if usersPerm.String() != "Permission{ID: users, Description: User resource}" {
		t.Fatalf("users string value is inconsistent")
	}
	testPerm := newPermission("test", "Test", CRUD)
	if len(testPerm.Actions()) != len(crudActions) {
		t.Fatalf("test permission actions are not valid, expected %d items, got %d items", len(crudActions), len(testPerm.Actions()))
	}

	strActions := []string{}
	for _, a := range crudActions {
		strActions = append(strActions, string(a))
	}
	sort.Strings(strActions)
	if !reflect.DeepEqual(testPerm.ActionsStrSlice(), strActions) {
		t.Fatalf("test permission actions are not valid, expected %d items, got %d items", len(testPerm.ActionsStrSlice()), len(strActions))
	}
}
