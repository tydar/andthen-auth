package main

import "context"

type Users interface {
	Create(ctx context.Context, username, password string) error
	ChangePassword(ctx context.Context, username, password string) error
	All(ctx context.Context) ([]User, error)
	GetById(ctx context.Context, id int) (User, error)
	Delete(ctx context.Context, id int) error
	GetByUsername(ctx context.Context, username string) (User, error)
	CheckPassword(ctx context.Context, username, password string) (bool, error)
}

type Env struct {
	users Users
}
