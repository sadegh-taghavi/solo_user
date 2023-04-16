CREATE DATABASE solo_user;
ALTER DATABASE solo_user CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

USE solo_user;

CREATE TABLE verify (
	id INT NOT NULL AUTO_INCREMENT,
	token VARCHAR(64) NOT NULL,
	data VARCHAR(2048) NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY ( id ),
	CONSTRAINT UNIQUE ( token )
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE INDEX idx_verify_token ON verify (token);

CREATE TABLE users (
	id INT NOT NULL AUTO_INCREMENT,
	user_id VARCHAR(64) NOT NULL,
	email VARCHAR(64) NOT NULL,
	name VARCHAR(64) NOT NULL,
	password VARCHAR(64) NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY ( id ),
	CONSTRAINT UNIQUE ( email ),
	CONSTRAINT UNIQUE ( name )
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE INDEX idx_user_id ON users (user_id);
CREATE INDEX idx_email ON users (email);
