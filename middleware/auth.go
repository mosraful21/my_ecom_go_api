package middleware

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"my_ecom_api/config"
	"my_ecom_api/utils"
)

type key string

const (
	UserID    key = "user_id"
	UserType  key = "type"
	AdminRole key = "admin_role"
)

func CreateSession(db *sql.DB, ownerType int, ownerID int64) (string, error) {
	token, err := utils.RandomToken()
	if err != nil {
		return "", err
	}
	now := time.Now().Unix()
	var userID, adminID any
	if ownerType == config.TypeUser {
		userID = ownerID
	} else {
		adminID = ownerID
	}
	_, err = db.Exec(`INSERT INTO auth_sessions (user_id, admin_id, token_hash, created_at) VALUES (?,?,?,?)`,
		userID, adminID, utils.HashToken(token), now)
	return token, err
}

func SetCookie(w http.ResponseWriter, name, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    token,
		Path:     "/",
		MaxAge:   400 * 24 * 60 * 60,
		HttpOnly: true,
		// Secure:   true, // for production lavel
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})
}

func ClearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: false, SameSite: http.SameSiteLaxMode,
	})
}

func Require(cfg *config.Config, db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(cfg.CookieName)
			if err != nil || cookie.Value == "" {
				utils.Error(w, http.StatusUnauthorized, "login required")
				return
			}

			var userID, adminID sql.NullInt64
			var revokedAt sql.NullInt64
			err = db.QueryRowContext(r.Context(), `SELECT user_id, admin_id, revoked_at FROM auth_sessions WHERE token_hash=?`,
				utils.HashToken(cookie.Value)).Scan(&userID, &adminID, &revokedAt)
			if err != nil || revokedAt.Valid {
				utils.Error(w, http.StatusUnauthorized, "invalid or logged out session")
				return
			}

			ctx := r.Context()
			if userID.Valid {
				var status int
				err = db.QueryRowContext(r.Context(), `SELECT status FROM users WHERE id=?`, userID.Int64).Scan(&status)
				if err != nil || status != config.StatusActive {
					utils.Error(w, http.StatusUnauthorized, "user account is not active")
					return
				}
				ctx = context.WithValue(ctx, UserID, userID.Int64)
				ctx = context.WithValue(ctx, UserType, config.TypeUser)
				ctx = context.WithValue(ctx, AdminRole, 0)
			} else if adminID.Valid {
				var role, status int
				err = db.QueryRowContext(r.Context(), `SELECT role,status FROM admin WHERE id=?`, adminID.Int64).Scan(&role, &status)
				if err != nil || status != config.StatusActive {
					utils.Error(w, http.StatusUnauthorized, "admin account is not active")
					return
				}
				ctx = context.WithValue(ctx, UserID, adminID.Int64)
				ctx = context.WithValue(ctx, UserType, config.TypeAdmin)
				ctx = context.WithValue(ctx, AdminRole, role)
			} else {
				utils.Error(w, http.StatusUnauthorized, "invalid session")
				return
			}

			SetCookie(w, cfg.CookieName, cookie.Value)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func ID(r *http.Request) int64 { v, _ := r.Context().Value(UserID).(int64); return v }
func Type(r *http.Request) int { v, _ := r.Context().Value(UserType).(int); return v }
func Role(r *http.Request) int { v, _ := r.Context().Value(AdminRole).(int); return v }
