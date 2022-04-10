package main

import "context"

type Users interface {
	Create(ctx context.Context, username, password string) error
	ChangePassword(ctx context.Context, username, password string) error
	GetById(ctx context.Context, id int) (User, error)
	Delete(ctx context.Context, id int) error
	GetByUsername(ctx context.Context, username string) (User, error)
	CheckPassword(ctx context.Context, username, password string) (bool, User, error)
}

type Env struct {
	users  Users
	secret string
}
