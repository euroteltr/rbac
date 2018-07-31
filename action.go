package rbac

// Action is permission action
type Action string

const (
	// None is for empty action
	None Action = ""
	// Create is for create action
	Create Action = "create"
	// Read is for read action
	Read Action = "read"
	// Update is for  update action
	Update Action = "update"
	// Delete is for delete action
	Delete Action = "delete"
	// CRUD is for, create+read+update+delete permissions
	CRUD Action = "crud"
	// Download is for downloading action
	Download = "download"
	// Upload is for uploading action
	Upload = "upload"
)
