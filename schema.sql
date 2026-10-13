CREATE DATABASE IF NOT EXISTS my_ecom_go CHARACTER
SET
  utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE
  IF NOT EXISTS admin (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    phone VARCHAR(30) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(150) NULL,
    image VARCHAR(255) NULL,
    gender VARCHAR(20) NULL,
    division VARCHAR(100) NULL,
    district VARCHAR(100) NULL,
    thana VARCHAR(100) NULL,
    post_office VARCHAR(100) NULL,
    address TEXT NULL,
    role TINYINT UNSIGNED NOT NULL,
    type TINYINT UNSIGNED NOT NULL DEFAULT 1,
    status TINYINT UNSIGNED NOT NULL DEFAULT 1,
    version BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    INDEX idx_admin_email (email)
  ) ENGINE = InnoDB;

CREATE TABLE
  IF NOT EXISTS users (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    phone VARCHAR(30) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(150) NULL,
    image VARCHAR(255) NULL,
    gender VARCHAR(20) NULL,
    division VARCHAR(100) NULL,
    district VARCHAR(100) NULL,
    thana VARCHAR(100) NULL,
    post_office VARCHAR(100) NULL,
    address TEXT NULL,
    type TINYINT UNSIGNED NOT NULL DEFAULT 2,
    status TINYINT UNSIGNED NOT NULL DEFAULT 1,
    version BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    INDEX idx_users_email (email)
  ) ENGINE = InnoDB;

CREATE TABLE
  IF NOT EXISTS auth_sessions (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NULL,
    admin_id BIGINT UNSIGNED NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    revoked_at BIGINT NULL,
    created_at BIGINT NOT NULL,
    INDEX idx_session_user (user_id),
    INDEX idx_session_admin (admin_id),
    CONSTRAINT fk_session_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_session_admin FOREIGN KEY (admin_id) REFERENCES admin (id) ON DELETE CASCADE
  ) ENGINE = InnoDB;

CREATE TABLE
  password_reset_audits (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    owner_type VARCHAR(20) NOT NULL,
    owner_id BIGINT UNSIGNED NULL,
    phone_hash CHAR(64) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    ip_address VARCHAR(45) NULL,
    user_agent VARCHAR(500) NULL,
    created_at BIGINT NOT NULL,
    INDEX idx_password_reset_audit_owner (owner_type, owner_id, created_at),
    INDEX idx_password_reset_audit_phone (phone_hash, created_at),
    INDEX idx_password_reset_audit_event (event_type, created_at)
  ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

CREATE TABLE
  IF NOT EXISTS products (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    description TEXT NULL,
    price DECIMAL(15, 2) NOT NULL DEFAULT 0,
    stock INT NOT NULL DEFAULT 0,
    status TINYINT UNSIGNED NOT NULL DEFAULT 1,
    image VARCHAR(255) NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    INDEX idx_products_status (status)
  ) ENGINE = InnoDB;