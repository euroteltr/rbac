/*
Package rbac is role based access control library. At core uses `sync.Map` so,
it can be used from multiple goroutines concurrently.package rbac

rbac is dependend on these terms:

		- Action	Defines what can possible for a permission
		- Permission	Defines permission related to a resource to be accessed
		- Role	Defines group of permissions with defined actions


Usage:

Library usage has 2 phases:

	- Development
	- Runtime

Development Phase

First get an instance for `RBAC`


	import rbac

	R := rbac.New(nil)
	// you can pass a logger to constructor also:
	// R := rbac.New(rbac.ConsoleLogger)


During development you will register your permissions for your each resource
with valid actions for that permission:


	// You can also use rbac.CRUD for those crud actions
	usersPerm, err := R.RegisterPermission("users", "User resource", rbac.Create, rbac.Read, rbac.Update, rbac.Delete)
	if err != nil {
		panic(err)
	}


`userPerm` is defined with CRUD actions, which means that any action not in that list will be invalid. You can define your own actions( like `ApproveAction := rbac.Action("approve")`) and add them also.

Runtime Phase

At run time we define our roles and permit permissions to them.

	adminRole, err := R.RegisterRole("admin", "Admin role")
	if err != nil {
		fmt.Printf("can not add admin role, err: %v\n", err)
	}
	if err = R.Permit(adminRole.ID, usersPerm, rbac.CRUD, ApproveAction); err != nil {
		fmt.Errorf("can not permit crud and ApproveAction actions to role %s\n", adminRole.ID)
	}


Now we can check if a role is granted some permission:


	if !R.IsGranted(adminRole.ID, usersPerm, rbac.Write) {
		fmt.Printf("admin role does not have write grant on users\n")
	}else{
		fmt.Printf("admin role does have write grant on users\n")
	}

	// You can also check by perm.ID also
	if !R.IsGrantedStr("admin", "users", rbac.CRUD) {
		fmt.Printf("admin role does not have CRUD grants on users\n")
	}else{
		fmt.Printf("admin role does have CRUD grants on users\n")
	}


Persisting and Loading

`rbac.RBAC` is `json` compatible. You can dump all data in `RBAC` instance to JSON:


	b, err := json.Marshal(R)
	if err != nil {
		fmt.Printf("rback marshall failed with %v\n", err)
	}else{
		fmt.Printf("RBAC: %s", b)
	}


Also you can use builtin `SaveJSON` function to save to a file:

	if err = R.SaveJSON("/tmp/rbac.json"); err != nil {
		fmt.Printf("unable to save to json file, err:%v\n", err)
	}


And load it from file:


	if err = R.LoadJSON("/tmp/rbac.json"); err != nil {
		fmt.Errorf("unable to load from json file, err:%v\n", err)
	}


In dumped JSON root "permissons" part is for reference. Root `roles` is the part you can modify in file and reload it to define `Role`s with `Permission`s.


	{
	"permissions": [
		{
		"id": "users",
		"description": "User resource",
		"actions": [
			"create",
			"read",
			"update",
			"delete"
		]
		}
	],
	"roles": [
		{
		"id": "admin",
		"description": "Admin role",
		"grants": {
			"users": [
			"create",
			"read",
			"update",
			"delete"
			]
		},
		"parents": []
		}
	]
	}

You can load this JSON data:

	if err := json.Unmarshal(b, R); err != nil {
		fmt.Errorf("rback unmarshall failed with %v\n", err)
	}
	// now you have *RBAC instance => R

Role inheritance

A `Role` can have parent `Role`s. You can add a parent `Role` like this:

	// Add a new role
	sysAdmRole, err := R.RegisterRole("sysadm", "System admin role")
	if err != nil {
		fmt.Printf("can not add agent role, err: %v\n", err)
	}

	// Now add adminRole as parent
	if err = sysAdmRole.AddParent(adminRole); err != nil {
		fmt.Printf("adding parent role failed with: %v\n", err)
	}

	// Now all permissions in adminRole will be also valid for sysAdmRole
	if R.IsGranted(sysAdmRole.ID, usersPerm, rbac.CRUD) {
		fmt.Printf("sysadmin role has all crud actions granted\n")
	}


If circular parent reference is found, you'll get error while running `AddParent`.

*/
package rbac
