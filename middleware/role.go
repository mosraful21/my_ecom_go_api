package middleware

import (
	"net/http"

	"my_ecom_api/config"
	"my_ecom_api/utils"
)

func RequireAdminRole(roles ...int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			if ID(r) == 0 {
				utils.Error(w, http.StatusUnauthorized, "unauthorized")
				return
			}

			if Type(r) != config.TypeAdmin {
				utils.Error(w, http.StatusForbidden, "admin access required")
				return
			}

			role := Role(r)

			for _, allowedRole := range roles {
				if role == allowedRole {
					next.ServeHTTP(w, r)
					return
				}
			}

			utils.Error(w, http.StatusForbidden, "insufficient permissions")
		})
	}
}

func RequireType(expected int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ID(r) == 0 {
				utils.Error(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			if Type(r) != expected {
				utils.Error(w, http.StatusForbidden, "access denied")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
