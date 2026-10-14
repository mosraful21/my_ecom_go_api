package middleware

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"my_ecom_api/config"
	"my_ecom_api/utils"
)

type key string

const (
	UserType  key = "type"
	UserID    key = "user_id"
	AdminRole key = "admin_role"
)

const SessionTTL = 365 * 24 * 60 * 60

func CreateSession(db *sql.DB, ownerType int, ownerID int64) (string, error) {
	if db == nil || ownerID <= 0 {
		return "", errors.New("invalid session owner")
	}

	if ownerType != config.TypeUser && ownerType != config.TypeAdmin {
		return "", errors.New("invalid session owner type")
	}

	token, err := utils.RandomToken()
	if err != nil {
		return "", err
	}

	var userID, adminID any

	if ownerType == config.TypeUser {
		userID = ownerID
	} else {
		adminID = ownerID
	}

	createdAt := time.Now().Unix()
	_, err = db.Exec(
		`INSERT INTO auth_sessions
			(user_id, admin_id, token_hash, created_at)
		 VALUES (?, ?, ?, ?)`,
		userID,
		adminID,
		utils.HashToken(token),
		createdAt,
	)
	if err != nil {
		return "", err
	}
	return token, nil
}

func SetCookie(w http.ResponseWriter, name string, token string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    token,
		Path:     "/",
		MaxAge:   SessionTTL,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func ClearCookie(w http.ResponseWriter, name string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func Require(cfg *config.Config, db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg == nil || db == nil || cfg.CookieName == "" {
				utils.Error(w, http.StatusInternalServerError, "authentication is not configured")
				return
			}

			cookie, err := r.Cookie(cfg.CookieName)
			if err != nil || cookie.Value == "" {
				utils.Error(w, http.StatusUnauthorized, "login required")
				return
			}

			var userID, adminID sql.NullInt64
			var revokedAt, createdAt sql.NullInt64

			err = db.QueryRowContext(
				r.Context(),
				`SELECT user_id, admin_id, revoked_at, created_at
				 FROM auth_sessions
				 WHERE token_hash = ?`,
				utils.HashToken(cookie.Value),
			).Scan(
				&userID,
				&adminID,
				&revokedAt,
				&createdAt,
			)

			if errors.Is(err, sql.ErrNoRows) {
				utils.Error(w, http.StatusUnauthorized, "invalid or expired session")
				return
			}

			if err != nil {
				utils.Error(w, http.StatusInternalServerError, "authentication failed")
				return
			}

			if revokedAt.Valid || !createdAt.Valid || userID.Valid == adminID.Valid {
				utils.Error(w, http.StatusUnauthorized, "invalid or expired session")
				return
			}

			created := time.Unix(createdAt.Int64, 0)
			now := time.Now()

			if created.After(now) ||
				now.Sub(created) >= time.Duration(SessionTTL)*time.Second {
				utils.Error(w, http.StatusUnauthorized, "session expired")
				return
			}

			ctx := r.Context()
			if userID.Valid {
				var status int

				err = db.QueryRowContext(
					r.Context(),
					`SELECT status FROM users WHERE id = ?`,
					userID.Int64,
				).Scan(&status)

				if errors.Is(err, sql.ErrNoRows) {
					utils.Error(w, http.StatusUnauthorized, "invalid session")
					return
				}

				if err != nil {
					utils.Error(w, http.StatusInternalServerError, "authentication failed")
					return
				}

				if status != config.StatusActive {
					utils.Error(w, http.StatusUnauthorized, "user account is not active")
					return
				}

				ctx = context.WithValue(ctx, UserID, userID.Int64)
				ctx = context.WithValue(ctx, UserType, config.TypeUser)
				ctx = context.WithValue(ctx, AdminRole, 0)

			} else {
				var role, status int

				err = db.QueryRowContext(
					r.Context(),
					`SELECT role, status FROM admin WHERE id = ?`,
					adminID.Int64,
				).Scan(&role, &status)

				if errors.Is(err, sql.ErrNoRows) {
					utils.Error(w, http.StatusUnauthorized, "invalid session")
					return
				}

				if err != nil {
					utils.Error(w, http.StatusInternalServerError, "authentication failed")
					return
				}

				if status != config.StatusActive {
					utils.Error(w, http.StatusUnauthorized, "admin account is not active")
					return
				}

				ctx = context.WithValue(ctx, UserID, adminID.Int64)
				ctx = context.WithValue(ctx, UserType, config.TypeAdmin)
				ctx = context.WithValue(ctx, AdminRole, role)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func ID(r *http.Request) int64 {
	v, _ := r.Context().Value(UserID).(int64)
	return v
}

func Type(r *http.Request) int {
	v, _ := r.Context().Value(UserType).(int)
	return v
}

func Role(r *http.Request) int {
	v, _ := r.Context().Value(AdminRole).(int)
	return v
}
