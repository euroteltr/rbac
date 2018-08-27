package rbac

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

func TestRBAC(t *testing.T) {
	R := New(nil) //NewConsoleLogger()
	crudActions := []Action{Create, Read, Update, Delete}
	usersPerm, err := R.RegisterPermission("users", "User resource", crudActions...)
	if err != nil {
		t.Fatalf("can not register users permission, err: %v", err)
	}

	if !R.IsPermissionExist("users", "") {
		t.Fatalf("users role should exit")
	}
	for _, action := range crudActions {
		if !R.IsPermissionExist("users", action) {
			t.Fatalf("users permission with action %s should exit", action)
		}
	}

	ApproveAction := Action("approve")
	_, err = R.RegisterPermission("posts", "Post resource", Create, Read, Update, Delete, ApproveAction)
	if err != nil {
		t.Fatalf("can not register posts permission, err: %v", err)
	}
	if !R.IsPermissionExist("posts", ApproveAction) {
		t.Fatalf("posts permission with approve action should exit")
	}

	if len(R.Permissions()) != 2 {
		t.Fatalf("should have 2 permissions registered, got %d", len(R.Permissions()))
	}

	adminRole, err := R.RegisterRole("admin", "Admin role")
	if err != nil {
		t.Fatalf("can not add admin role, err: %v", err)
	}

	if _, err = R.RegisterRole("admin", "Admin role"); err == nil {
		t.Fatalf("should get error when re-registering role")
	}

	if err = R.Permit(adminRole.ID, usersPerm, crudActions...); err != nil {
		t.Fatalf("can not permit all crud actions to role %s", adminRole.ID)
	}

	if !R.IsGranted(adminRole.ID, usersPerm, crudActions...) {
		t.Fatalf("admin role should have all crud actions granted")
	}

	if R.IsGranted(adminRole.ID, usersPerm, "unknown") {
		t.Fatalf("admin role should not have unknown action granted")
	}

	sysAdmRole, err := R.RegisterRole("sysadm", "System admin role")
	if err != nil {
		t.Fatalf("can not add agent role, err: %v", err)
	}

	if err = sysAdmRole.AddParent(adminRole); err != nil {
		t.Fatalf("adding parent role failed with: %v", err)
	}

	if err = adminRole.AddParent(sysAdmRole); strings.Index(err.Error(), "circular") == -1 {
		t.Fatalf("circular parent check failed with err: %v", err)
	}

	if !R.IsGranted(sysAdmRole.ID, usersPerm, crudActions...) {
		t.Fatalf("sysadmin role should have all crud actions granted")
	}

	if !adminRole.isGranted(usersPerm, crudActions...) {
		t.Fatalf("admin role should have all crud actions granted")
	}

	if err = sysAdmRole.RemoveParent(adminRole); err != nil {
		t.Fatalf("removing parent role failed with: %v", err)
	}

	if err = sysAdmRole.AddParent(adminRole); err != nil {
		t.Fatalf("adding parent role failed with: %v", err)
	}

	b, err := json.Marshal(R)
	if err != nil {
		t.Fatalf("rback marshall failed with %v", err)
	}

	filename := "/tmp/rbac.json"
	RNew := R.Clone(false)
	fw, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("unable to create json file, err:%v", err)
	}
	if err = R.SaveJSON(fw); err != nil {
		t.Fatalf("unable to save to json file, err:%v", err)
	}
	defer fw.Close()

	f, err := os.Open(filename)
	if err != nil {
		t.Fatalf("can not open temp file: %v", err)
	}
	defer f.Close()
	if err = RNew.LoadJSON(f); err != nil {
		t.Fatalf("unable to load from json file, err:%v", err)
	}

	if !RNew.IsGranted(sysAdmRole.ID, usersPerm, crudActions...) {
		t.Fatalf("sysadmin role should have all crud actions granted")
	}

	R2 := R.Clone(false)
	if err = json.Unmarshal(b, R2); err != nil {
		t.Fatalf("rback unmarshall failed with %v", err)
	}

	if len(R.Roles()) != len(R2.Roles()) {
		t.Fatalf("role counts differ, expected %d, got %d", len(R.Roles()), len(R2.Roles()))
	}

	if !R2.IsGranted(adminRole.ID, usersPerm, crudActions...) {
		t.Fatalf("loaded admin role should have all crud actions granted")
	}
	aPerms := R2.GetAllPermissions(adminRole.ID)
	if us, ok := aPerms[usersPerm.ID]; !ok {
		t.Fatalf("users permission must exit in all perms of sysadmin role(inherited)")
	} else {
		found := false
		for _, a := range us {
			if a == Delete {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("Delete action is missing in users permission for all permissions of sysadmin role(inherited)")
		}
	}

	sPerms := R2.GetAllPermissions(sysAdmRole.ID)
	if us, ok := sPerms[usersPerm.ID]; !ok {
		t.Fatalf("users permission must exit in all perms of admin role")
	} else {
		found := false
		for _, a := range us {
			if a == Delete {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("Delete action is missing in users permission for all permissions of admin role")
		}
	}

	if R2.RemoveRole(sysAdmRole.ID); err != nil {
		t.Fatalf("removing role failed with: %v", err)
	}

	if R2.Revoke(adminRole.ID, usersPerm, Delete); err != nil {
		t.Fatalf("removing perm from role failed with: %v", err)
	}

	if !hasAction(usersPerm.Actions(), Delete) {
		t.Fatalf("perm should have delete action")
	}
}

func TestDefaultLogger(t *testing.T) {
	var buf bytes.Buffer
	old := os.Stdout // keep backup of the real stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	logger := NewNullLogger()
	SetLogger(logger)
	log.Debugf("TEST")
	log.Errorf("TEST2")

	outC := make(chan string)
	// copy the output in a separate goroutine so printing can't block indefinitely
	go func() {
		io.Copy(&buf, r)
		outC <- buf.String()
	}()

	w.Close()
	os.Stdout = old // restoring the real stdout
	_ = <-outC

	if string(buf.Bytes()) != "" {
		t.Fatalf("logger output is not compatible, expected: `%s`, got: `%s`", "", buf.Bytes())
	}
}
