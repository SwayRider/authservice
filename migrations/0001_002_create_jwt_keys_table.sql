-- +migrate Up
CREATE TABLE IF NOT EXISTS jwt_keys (
    id SERIAL PRIMARY KEY,
    private_key TEXT NOT NULL,
    public_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    valid_until TIMESTAMPTZ NOT NULL
	
);

-- +migrate Down
DROP TABLE jwt_keys;
