package main

import (
	"context"

	"github.com/jackc/pgx/v4/pgxpool"
)

type Users interface {
	Create(ctx context.Context, username, password string, admin bool) error
	ChangePassword(ctx context.Context, username, password string) error
	GetById(ctx context.Context, id int) (User, error)
	Delete(ctx context.Context, id int) error
	GetByUsername(ctx context.Context, username string) (User, error)
	CheckPassword(ctx context.Context, username, password string) (bool, User, error)
	NotifyPlayerService(ctx context.Context, display string, id int) error
}

type Env struct {
	users  Users
	secret string
}

func NewEnv(pool *pgxpool.Pool, secret string) Env {
	ur := NewUserRepo(pool)
	return Env{
		users:  ur,
		secret: secret,
	}
}
