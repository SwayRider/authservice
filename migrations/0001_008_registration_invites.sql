-- +migrate Up
CREATE TABLE registration_invites (
    id         UUID        PRIMARY KEY,
    email      TEXT        UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +migrate Down
DROP TABLE registration_invites;
