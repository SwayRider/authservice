-- +migrate Up
CREATE TABLE service_clients (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    client_id TEXT NOT NULL UNIQUE,
    client_secret TEXT NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +migrate Down
DROP TABLE service_clients;
