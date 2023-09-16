pub(crate) const CREATE_TABLE: &str = "
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
	password TEXT NOT NULL,
    is_admin BOOL DEFAULT FALSE
);
";

pub(crate) const INSERT_USER: &str = "
INSERT INTO users (id, email, password, is_admin) VALUES ($1, $2, $3, $4);
";

pub(crate) const UPDATE_USER: &str = "
UPDATE users SET 
    email = $2,
    password = $3,
    is_admin = $4
WHERE
    id = $1
";

pub(crate) const SELECT_BY_ID: &str = "
SELECT * FROM users WHERE id = $1;
";

pub(crate) const SELECT_BY_EMAIL: &str = "
SELECT * FROM users WHERE email = $1;
";

pub(crate) const REMOVE_BY_ID: &str = "
DELETE FROM users WHERE id = $1;
";
pub(crate) const REMOVE_BY_EMAIL: &str = "
DELETE FROM users WHERE email = $1;
";
