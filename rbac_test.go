package rbac

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func TestRBAC(t *testing.T) {

	// Add Actions
	R := New(nil) //NewConsoleLogger()
	crudActions := []Action{Create, Read, Update, Delete}
	ApproveAction := Action("approve")

	// Add permissions
	usersPerm, err := R.RegisterPermission("users", "User resource", crudActions...)
	if err != nil {
		t.Fatalf("can not register users permission, err: %v", err)
	}
	_, err = R.RegisterPermission("users", "User resource", crudActions...)
	if err == nil {
		t.Fatalf("should not be able to register users permission twice")
	}
	if !R.IsPermissionExist(usersPerm.ID, "") {
		t.Fatalf("users role should exit")
	}
	for _, action := range crudActions {
		if !R.IsPermissionExist(usersPerm.ID, action) {
			t.Fatalf("users permission with action %s should exit", action)
		}
	}

	postPerm, err := R.RegisterPermission("post", "Post resource", Create, Read, Update, Delete, ApproveAction)
	if err != nil {
		t.Fatalf("can not register posts permission, err: %v", err)
	}
	if !R.IsPermissionExist(postPerm.ID, ApproveAction) {
		t.Fatalf("posts permission with approve action should exit")
	}
	if len(R.Permissions()) != 2 {
		t.Fatalf("should have 2 permissions registered, got %d", len(R.Permissions()))
	}

	var viewSomething *Permission
	viewSomething, err = R.RegisterPermission("viewSomething", "view something", Read)
	if err != nil {
		t.Fatalf("can not register viewSomething permission, err: %v", err)
	}
	if !R.IsPermissionExist(viewSomething.ID, Read) {
		t.Fatalf("viewSomething permission with Read action should exit")
	}
	if len(R.Permissions()) != 3 {
		t.Fatalf("should have 3 permissions registered, got %d", len(R.Permissions()))
	}

	// Test GetRole/RemoveRole
	if tRole := R.GetRole("test_role"); tRole != nil {
		t.Fatalf("test_role should not exists yet")
	}
	if err := R.RemoveRole("test_role"); err == nil {
		t.Fatalf("test_role should not exists yet")
	}
	_, err = R.RegisterRole("test_role", "NoParent role")
	if err != nil {
		t.Fatalf("can not add test_role role, err: %v", err)
	}
	if tRole := R.GetRole("test_role"); tRole == nil {
		t.Fatalf("test_role should exists")
	}
	if err := R.RemoveRole("test_role"); err != nil {
		t.Fatalf("test_role get removed, err: %v", err)
	}

	// Add Roles
	// noparent - stand alone role
	//
	// viewer - has viewSomething.Read permission
	//   `-> admin - inherits from viewer.  has users.CRUD permission
	// 	`-> sysAdmin - inherits admin.  Has post.CURD AND post.Approve permissions`

	// noparent Role
	noparentRole, err := R.RegisterRole("noparent", "NoParent role")
	if err != nil {
		t.Fatalf("can not add noparent role, err: %v", err)
	}
	if tRole := R.GetRole(noparentRole.ID); tRole == nil {
		t.Fatalf("noparentRole should exists")
	}

	// viewer Role
	viewerRole, err := R.RegisterRole("viewer", "Viewer role")
	if err != nil {
		t.Fatalf("can not add viewer role, err: %v", err)
	}

	if err = R.Permit(viewerRole.ID, viewSomething, Read); err != nil {
		t.Fatalf("can not permit Read action to role %s", viewerRole.ID)
	}

	if !R.IsGranted(viewerRole.ID, viewSomething, Read) {
		t.Fatalf("viewerRole role should have Read actions granted")
	}

	// admin Role
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
	if err = adminRole.AddParent(viewerRole); err != nil {
		t.Fatalf("adding parent role failed with: %v", err)
	}

	// sysAdmin Role
	sysAdminRole, err := R.RegisterRole("sysAdmin", "System admin role")
	if err != nil {
		t.Fatalf("can not add agent role, err: %v", err)
	}
	if err = R.Permit(sysAdminRole.ID, postPerm, append(crudActions, ApproveAction)...); err != nil {
		t.Fatalf("can not permit all crud actions to role %s", adminRole.ID)
	}
	if err = sysAdminRole.AddParent(adminRole); err != nil {
		t.Fatalf("adding parent role failed with: %v", err)
	}

	// Test Permit branches
	if err = R.Permit(sysAdminRole.ID, nil, ApproveAction); err == nil {
		t.Fatalf("Permit should fail with nil permission")
	}
	if err = R.Permit(sysAdminRole.ID, viewSomething, ApproveAction); err == nil {
		t.Fatalf("Permit should fail with invalid action for permission")
	}
	if err = R.Permit("fake_role", viewSomething, ApproveAction); err == nil {
		t.Fatalf("Permit should fail with nonexisting role")
	}

	// Test Revoke branches
	if err = R.Revoke(sysAdminRole.ID, nil, ApproveAction); err == nil {
		t.Fatalf("Revoke should fail with nil permission")
	}
	if err = R.Revoke(sysAdminRole.ID, viewSomething, ApproveAction); err == nil {
		t.Fatalf("Revoke should fail with invalid action for permission")
	}
	if err = R.Revoke("fake_role", viewSomething, ApproveAction); err == nil {
		t.Fatalf("Revoke should fail with nonexisting role")
	}

	// Test IsGranted branches
	if R.IsGranted(sysAdminRole.ID, nil, ApproveAction) {
		t.Fatalf("IsGranted should fail with nil permission")
	}
	if !R.IsGranted(adminRole.ID, usersPerm, crudActions...) {
		t.Fatalf("sysAdmin role should have all crud actions granted")
	}
	if !adminRole.isGranted(usersPerm, crudActions...) {
		t.Fatalf("admin role should have all crud actions granted")
	}

	// Test IsGrantInherited branches
	if R.IsGrantInherited(sysAdminRole.ID, nil, ApproveAction) {
		t.Fatalf("IsGrantInherited should fail with nil permission")
	}
	if R.IsGrantInherited(sysAdminRole.ID, usersPerm, ApproveAction) {
		t.Fatalf("IsGrantInherited should fail with invalid action for permission")
	}
	if !R.IsGrantInherited(sysAdminRole.ID, usersPerm, crudActions...) {
		t.Fatalf("sysAdmin role should have all crud actions granted")
	}
	if !adminRole.isGrantInherited(usersPerm, crudActions...) {
		t.Fatalf("admin role should have all crud actions granted")
	}
	if R.IsGrantInherited("fake_role", usersPerm, crudActions...) {
		t.Fatalf("noexisting role should not have all crud actions granted")
	}

	// Check circular heritage.
	if err = sysAdminRole.AddParent(adminRole); err == nil {
		t.Fatalf("Should not be able to add adminRole as parent to sysAdminRole again.")
	}
	if err = viewerRole.AddParent(sysAdminRole); strings.Index(err.Error(), "circular") == -1 {
		t.Fatalf("circular parent check failed with err: %v", err)
	}

	// Check inheritance
	if ok := adminRole.HasParent(viewerRole.ID); !ok {
		t.Fatalf("adminRole should have viewerRole as parent.")
	}
	if ok := adminRole.HasAncestor(viewerRole.ID); !ok {
		t.Fatalf("adminRole should have viewerRole as ancestor.")
	}
	if ok := sysAdminRole.HasParent(viewerRole.ID); ok {
		t.Fatalf("sysAdminRole should not have viewerRole as parent.")
	}
	if ok := sysAdminRole.HasAncestor(viewerRole.ID); !ok {
		t.Fatalf("sysAdminRole should have viewerRole as ancestor.")
	}
	if ok := sysAdminRole.HasParent(noparentRole.ID); ok {
		t.Fatalf("sysAdminRole should not have noparentRole as parent.")
	}
	if ok := sysAdminRole.HasAncestor(noparentRole.ID); ok {
		t.Fatalf("sysAdminRole should not have noparentRole as ancestor.")
	}

	// Check hasAction branches
	if hasAction([]Action{ApproveAction}, Read) {
		t.Fatalf("Read should not be in this action list")
	}

	// Check AnyGranted branches
	if !R.AnyGranted([]string{adminRole.ID, sysAdminRole.ID}, usersPerm, Delete) {
		t.Fatalf("roles should have users.delete")
	}
	if R.AllGranted([]string{adminRole.ID, sysAdminRole.ID}, usersPerm, Create) {
		t.Fatalf("roles should not have users.create")
	}

	// Check AnyGrantInherited branches
	if !R.AnyGrantInherited([]string{adminRole.ID, sysAdminRole.ID}, postPerm, ApproveAction) {
		t.Fatalf("one role should have postPerm.ApproveAction")
	}
	if !R.AllGrantInherited([]string{adminRole.ID, sysAdminRole.ID}, viewSomething, Read) {
		t.Fatalf("roles should all have viewSomething.Read")
	}
	if R.AllGrantInherited([]string{adminRole.ID, viewerRole.ID}, usersPerm, Create) {
		t.Fatalf("veiwer role should not have userPerm.Create")
	}

	if err = sysAdminRole.RemoveParent(adminRole); err != nil {
		t.Fatalf("removing parent role failed with: %v", err)
	}

	if err = sysAdminRole.AddParent(adminRole); err != nil {
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

	if !RNew.IsGranted(adminRole.ID, usersPerm, crudActions...) {
		t.Fatalf("sysAdmin role should have all crud actions granted")
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
	aPerms := R2.GetAllPermissions([]string{adminRole.ID})
	if us, ok := aPerms[usersPerm.ID]; !ok {
		t.Fatalf("users permission must exit in all perms of sysAdmin role(inherited)")
	} else {
		found := false
		for _, a := range us {
			if a == Delete {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("Delete action is missing in users permission for all permissions of sysAdmin role(inherited)")
		}
	}

	sPerms := R2.GetAllPermissions([]string{sysAdminRole.ID})
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

	if R2.RemoveRole(sysAdminRole.ID); err != nil {
		t.Fatalf("removing role failed with: %v", err)
	}

	if R2.Revoke(adminRole.ID, usersPerm, Delete); err != nil {
		t.Fatalf("removing perm from role failed with: %v", err)
	}

	if !hasAction(usersPerm.Actions(), Delete) {
		t.Fatalf("perm should have delete action")
	}

	if R2.AnyGranted([]string{adminRole.ID, sysAdminRole.ID}, usersPerm, Delete) {
		t.Fatalf("roles should not have users.delete")
	}
	if R2.AllGranted([]string{adminRole.ID, sysAdminRole.ID}, usersPerm, Create) {
		t.Fatalf("roles should have users.create")
	}

	// Test Remove parent.
	if !adminRole.HasParent(viewerRole.ID) {
		t.Fatal("viewerRole should be a parent of adminRole.")
	}
	if R.RemoveRole(viewerRole.ID); err != nil {
		t.Fatalf("removing role failed with: %v", err)
	}
	if adminRole.HasParent(viewerRole.ID) {
		t.Fatal("viewerRole should no longer be a parent of adminRole.")
	}
	if sysAdminRole.HasAncestor(viewerRole.ID) {
		t.Fatal("viewerRole should no longer be an ancestor of sysAdminRole.")
	}
}

func TestDefaultLogger(t *testing.T) {
	var buf bytes.Buffer
	old := os.Stdout // keep backup of the real stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	logger := NewNullLogger()
	SetLogger(logger)
	log.Debugf("TEST %v", 1)
	log.Errorf("TEST2 %v", errors.New("test"))

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
