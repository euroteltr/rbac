package main

import (
	"net/http"

	"github.com/euroteltr/rbac"
	"github.com/euroteltr/rbac/middlewares/echorbac"

	"github.com/labstack/echo"
)

func statsHandle(c echo.Context) error {
	return c.JSON(http.StatusOK, echo.Map{
		"message": "has admin role",
	})
}

func usersHandle(c echo.Context) error {
	return c.JSON(http.StatusOK, echo.Map{
		"message": "users page",
	})
}

// Session middleware is simple session settler, instead use with your auth middleware
func Session(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Set("roles", []string{"admin"})
		return next(c)
	}
}

func main() {
	e := echo.New()

	// Debug mode
	e.Debug = true

	//-------------------
	// Custom middleware
	//-------------------
	e.Use(Session)
	// Init RBAC and register permissions for our resources
	R := rbac.New(rbac.NewConsoleLogger())
	statsPerm, _ := R.RegisterPermission("stats", "Stats resource", rbac.Read)
	usersPerm, _ := R.RegisterPermission("users", "Users resource", rbac.CRUD)

	// Now load or define roles
	adminRole, _ := R.RegisterRole("admin", "Admin role")
	R.Permit(adminRole.ID, statsPerm, rbac.Read)

	// Middleware function shorthand
	isGranted := echorbac.HasRole(R)

	// Routes and check for grants
	e.GET("/stats", statsHandle, isGranted(statsPerm, rbac.Read))
	e.GET("/users", usersHandle, isGranted(usersPerm, rbac.Update))
	// default route
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	})

	// Start server
	e.Logger.Fatal(e.Start(":1323"))
}
