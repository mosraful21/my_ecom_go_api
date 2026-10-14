package controllers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
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

var verifyOTPScript = redis.NewScript(`
local raw = redis.call('GET', KEYS[1])
if not raw then return cjson.encode({status=-1}) end
local s = cjson.decode(raw)
if s.owner_type ~= ARGV[1] then return cjson.encode({status=-2, session=s}) end
if s.otp_verified == true then return cjson.encode({status=-3, session=s}) end
if tonumber(s.otp_expires_at or 0) <= tonumber(ARGV[2]) then
  return cjson.encode({status=-4, session=s})
end
if tonumber(s.otp_attempts or 0) >= tonumber(ARGV[5]) then
  return cjson.encode({status=-5, session=s})
end
if s.otp_hash ~= ARGV[3] then
  s.otp_attempts = tonumber(s.otp_attempts or 0) + 1
  local ttl = redis.call('PTTL', KEYS[1])
  if ttl <= 0 then return cjson.encode({status=-1}) end
  redis.call('SET', KEYS[1], cjson.encode(s), 'PX', ttl)
  return cjson.encode({status=0, session=s})
end
s.otp_verified = true
s.reset_token_hash = ARGV[4]
s.reset_token_expires_at = tonumber(ARGV[6])
s.reset_in_progress = false
local ttl = redis.call('PTTL', KEYS[1])
if ttl <= 0 then return cjson.encode({status=-1}) end
redis.call('SET', KEYS[1], cjson.encode(s), 'PX', ttl)
return cjson.encode({status=1, session=s})
`)

var claimResetScript = redis.NewScript(`
local raw = redis.call('GET', KEYS[1])
if not raw then return cjson.encode({status=-1}) end
local s = cjson.decode(raw)
if s.owner_type ~= ARGV[1] then return cjson.encode({status=-2, session=s}) end
if s.otp_verified ~= true then return cjson.encode({status=-3, session=s}) end
if tonumber(s.reset_token_expires_at or 0) <= tonumber(ARGV[2]) then
  return cjson.encode({status=-4, session=s})
end
if s.reset_token_hash ~= ARGV[3] then return cjson.encode({status=-5, session=s}) end
if s.reset_in_progress == true then return cjson.encode({status=-6, session=s}) end
s.reset_in_progress = true
local ttl = redis.call('PTTL', KEYS[1])
if ttl <= 0 then return cjson.encode({status=-1}) end
redis.call('SET', KEYS[1], cjson.encode(s), 'PX', ttl)
return cjson.encode({status=1, session=s})
`)

var releaseResetClaimScript = redis.NewScript(`
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local s = cjson.decode(raw)
if s.reset_token_hash ~= ARGV[1] or s.reset_in_progress ~= true then return 0 end
s.reset_in_progress = false
local ttl = redis.call('PTTL', KEYS[1])
if ttl <= 0 then return 0 end
redis.call('SET', KEYS[1], cjson.encode(s), 'PX', ttl)
return 1
`)

var consumeResetClaimScript = redis.NewScript(`
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local s = cjson.decode(raw)
if s.reset_token_hash ~= ARGV[1] or s.reset_in_progress ~= true then return 0 end
return redis.call('DEL', KEYS[1])
`)

var forgotPasswordRateLimitScript = redis.NewScript(`
local phoneCount = redis.call('INCR', KEYS[1])
if phoneCount == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
local ipCount = redis.call('INCR', KEYS[2])
if ipCount == 1 then redis.call('EXPIRE', KEYS[2], ARGV[2]) end
if phoneCount > tonumber(ARGV[3]) or ipCount > tonumber(ARGV[4]) then return 0 end
return 1
`)

type recoveryScriptResult struct {
	Status  int                    `json:"status"`
	Session models.RecoverySession `json:"session"`
}

func (c *AuthRecoveryController) verifyOTPAtomic(
	ctx context.Context, sessionID, ownerType, inputHash, resetTokenHash string,
	now, resetExpiresAt int64,
) (int, models.RecoverySession, error) {
	var result recoveryScriptResult
	raw, err := verifyOTPScript.Run(ctx, c.RDB, []string{recoveryKey(sessionID)},
		ownerType, now, inputHash, resetTokenHash, config.MaxOTPAttempts, resetExpiresAt).Text()
	if err != nil {
		return 0, result.Session, err
	}
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return 0, result.Session, err
	}
	return result.Status, result.Session, nil
}

func (c *AuthRecoveryController) claimResetTokenAtomic(
	ctx context.Context, sessionID, ownerType, tokenHash string, now int64,
) (int, models.RecoverySession, error) {
	var result recoveryScriptResult
	raw, err := claimResetScript.Run(ctx, c.RDB, []string{recoveryKey(sessionID)}, ownerType, now, tokenHash).Text()
	if err != nil {
		return 0, result.Session, err
	}
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return 0, result.Session, err
	}
	return result.Status, result.Session, nil
}

func (c *AuthRecoveryController) releaseResetClaim(ctx context.Context, sessionID, tokenHash string) error {
	return releaseResetClaimScript.Run(ctx, c.RDB, []string{recoveryKey(sessionID)}, tokenHash).Err()
}

func (c *AuthRecoveryController) consumeResetClaim(ctx context.Context, sessionID, tokenHash string) error {
	return consumeResetClaimScript.Run(ctx, c.RDB, []string{recoveryKey(sessionID)}, tokenHash).Err()
}

func (c *AuthRecoveryController) allowForgotPassword(ctx context.Context, ownerType, phone, ip string) (bool, error) {
	phoneKey := "password_recovery_rate:phone:" + ownerType + ":" + utils.HashPhone(c.Cfg.RecoverySecret, phone)
	ipKey := "password_recovery_rate:ip:" + utils.HashPhone(c.Cfg.RecoverySecret, ip)
	allowed, err := forgotPasswordRateLimitScript.Run(
		ctx,
		c.RDB,
		[]string{phoneKey, ipKey},
		config.ForgotPasswordCooldown,
		config.ForgotPasswordIPWindowSeconds,
		config.MaxForgotPasswordRequests,
		config.MaxForgotPasswordRequestsPerIP,
	).Int()
	if err != nil {
		return false, err
	}
	return allowed == 1, nil
}

var recordLoginFailureScript = redis.NewScript(`
local phoneCount = redis.call('INCR', KEYS[1])
if phoneCount == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
local ipCount = redis.call('INCR', KEYS[2])
if ipCount == 1 then redis.call('EXPIRE', KEYS[2], ARGV[1]) end
return {phoneCount, ipCount}
`)

func (c *AuthRecoveryController) loginRateKeys(ownerType, phone, ip string) (string, string) {
	phoneKey := "login_fail:phone:" + ownerType + ":" + utils.HashPhone(c.Cfg.RecoverySecret, phone)
	ipKey := "login_fail:ip:" + utils.HashPhone(c.Cfg.RecoverySecret, ip)
	return phoneKey, ipKey
}

func (c *AuthRecoveryController) loginBlocked(ctx context.Context, ownerType, phone, ip string) (bool, error) {
	phoneKey, ipKey := c.loginRateKeys(ownerType, phone, ip)
	values, err := c.RDB.MGet(ctx, phoneKey, ipKey).Result()
	if err != nil {
		return false, err
	}
	phoneCount, ipCount := int64(0), int64(0)
	if len(values) > 0 && values[0] != nil {
		switch v := values[0].(type) {
		case string:
			phoneCount, _ = strconv.ParseInt(v, 10, 64)
		case int64:
			phoneCount = v
		}
	}
	if len(values) > 1 && values[1] != nil {
		switch v := values[1].(type) {
		case string:
			ipCount, _ = strconv.ParseInt(v, 10, 64)
		case int64:
			ipCount = v
		}
	}
	return phoneCount >= 10 || ipCount >= 50, nil
}

func (c *AuthRecoveryController) recordFailedLogin(ctx context.Context, ownerType, phone, ip string) error {
	phoneKey, ipKey := c.loginRateKeys(ownerType, phone, ip)
	return recordLoginFailureScript.Run(ctx, c.RDB, []string{phoneKey, ipKey}, 15*60).Err()
}

func (c *AuthRecoveryController) clearLoginPhoneFailures(ctx context.Context, ownerType, phone string) error {
	phoneKey, _ := c.loginRateKeys(ownerType, phone, "")
	return c.RDB.Del(ctx, phoneKey).Err()
}
