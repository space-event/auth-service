-- +goose Up
CREATE TABLE users (
    id text primary key,
    email text not null unique,
    firstname text not null,
    lastname text not null,
    password_hash text not null,
    created_at timestamptz not null
);

CREATE TABLE refresh_tokens (
    id text primary key,
    token text not null,
    expires_at timestamptz not null,
    is_revoked boolean not null,
    user_id text not null,
    created_at timestamptz not null
);

CREATE TABLE password_reset_tokens (
    id text not null,
    email text not null,
    token_hash text not null,
    expires_at timestamptz not null,
    created_at timestamptz not null
);