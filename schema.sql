DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS roles;

CREATE TABLE roles(
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(25) NOT NULL,
    description TEXT
) ENGINE INNODB;

CREATE TABLE users(
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(25) UNIQUE NOT NULL,
    first_name VARCHAR(25) NOT NULL,
    last_name VARCHAR(25) NOT NULL,
    middle_name VARCHAR(25) DEFAULT NULL,
    password_hash VARCHAR(256) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    role_id INTEGER,
    FOREIGN KEY (role_id) REFERENCES roles(id)
) ENGINE INNODB;

INSERT INTO roles (id, name) 
VALUES (1, 'admin');

INSERT INTO users (username, first_name, last_name, password_hash, role_id)
VALUES ('admin', 'Иванов', 'Иван', SHA2('qwerty', 256), 1);

INSERT INTO users (username, first_name, last_name, password_hash, role_id)
VALUES ('user', 'Жаныбек', 'Просто', SHA2('qwerty', 256), 1);