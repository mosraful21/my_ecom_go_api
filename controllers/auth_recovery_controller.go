package controllers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"

	"my_ecom_api/config"
	"my_ecom_api/models"
	"my_ecom_api/utils"
)

type AuthRecoveryController struct {
	DB  *sql.DB
	Cfg *config.Config
	RDB *redis.Client
}

func getClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func recoveryKey(sessionID string) string {
	return "password_recovery:" + sessionID
}

func (c *AuthRecoveryController) auditPasswordReset(ctx context.Context, ownerType string, ownerID *int64, phone string, eventType string, ip string, userAgent string) error {
	phoneHash := utils.HashPhone(
		c.Cfg.RecoverySecret,
		phone,
	)

	var dbOwnerID interface{}

	if ownerID != nil {
		dbOwnerID = *ownerID
	}

	_, err := c.DB.ExecContext(
		ctx,
		`INSERT INTO password_reset_audits
		(owner_type, owner_id, phone_hash, event_type, ip_address, user_agent, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ownerType,
		dbOwnerID,
		phoneHash,
		eventType,
		ip,
		userAgent,
		time.Now().Unix(),
	)

	return err
}

func (c *AuthRecoveryController) saveRecoverySession(ctx context.Context, sessionID string, session models.RecoverySession) error {
	data, err := json.Marshal(session)
	if err != nil {
		return err
	}

	return c.RDB.Set(
		ctx,
		recoveryKey(sessionID),
		data,
		time.Duration(config.RecoverySessionTTL)*time.Second,
	).Err()
}

func (c *AuthRecoveryController) getRecoverySession(ctx context.Context, sessionID string) (models.RecoverySession, error) {
	var session models.RecoverySession

	data, err := c.RDB.Get(
		ctx,
		recoveryKey(sessionID),
	).Bytes()

	if err != nil {
		return session, err
	}

	if err := json.Unmarshal(data, &session); err != nil {
		return session, err
	}

	return session, nil
}

func (c *AuthRecoveryController) deleteRecoverySession(ctx context.Context, sessionID string) error {
	return c.RDB.Del(
		ctx,
		recoveryKey(sessionID),
	).Err()
}
