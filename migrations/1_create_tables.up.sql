-- +goose Up
CREATE TABLE users (
    id uuid primary key,
    email text not null unique,
    firstname text not null,
    lastname text not null,
    password_hash text not null,
    created_at timestamptz not null
);

CREATE TABLE refresh_tokens (
    id uuid primary key,
    token text not null unique ,
    expires_at timestamptz not null,
    is_revoked boolean not null,
    user_id text not null,
    created_at timestamptz not null
);

CREATE TABLE password_reset_tokens (
    id uuid primary key,
    email text not null,
    token_hash text not null unique,
    expires_at timestamptz not null,
    created_at timestamptz not null
);