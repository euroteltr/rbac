package echorbac

import (
	"github.com/euroteltr/rbac"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/labstack/gommon/log"
)

type (
	// EchoRBAC defines the config for RBAC middleware.
	EchoRBAC struct {
		// Skipper defines a function to skip middleware.
		Skipper middleware.Skipper
		// SessionRolesKeyName is a string to find current user's roles(default is "roles")
		SessionRolesKeyName string
		RBAC                *rbac.RBAC
	}
)

var (
	// DefaultEchoRBAC is the default BasicAuth middleware config.
	DefaultEchoRBAC = EchoRBAC{
		Skipper: middleware.DefaultSkipper,
	}
)

// IsGrantedFunc is used to check grants
type IsGrantedFunc = func(perm *rbac.Permission, actions ...rbac.Action) echo.MiddlewareFunc

// HasRole returns an HasRole middleware with default config.
func HasRole(R *rbac.RBAC) IsGrantedFunc {
	DefaultEchoRBAC.RBAC = R
	return HasRoleWithConfig(DefaultEchoRBAC)
}

// HasRoleWithConfig returns an HasRole middleware with config.
func HasRoleWithConfig(config EchoRBAC) IsGrantedFunc {
	if config.Skipper == nil {
		config.Skipper = DefaultEchoRBAC.Skipper
	}

	if config.RBAC == nil {
		panic("RBAC instance is not defined")
	}

	if config.SessionRolesKeyName == "" {
		config.SessionRolesKeyName = "roles"
	}

	return func(perm *rbac.Permission, actions ...rbac.Action) echo.MiddlewareFunc {
		return func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(c echo.Context) error {
				if config.Skipper(c) {
					return next(c)
				}
				rolesI := c.Get(config.SessionRolesKeyName)
				if rolesI == nil {
					log.Errorf("No rbac roles key %s", config.SessionRolesKeyName)
				} else if config.RBAC.AnyGranted(rolesI.([]string), perm, actions...) {
					return next(c)
				}
				return echo.ErrUnauthorized
			}
		}
	}
}
