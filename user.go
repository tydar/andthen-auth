package main

import (
	"context"
	"fmt"

	"github.com/jackc/pgx"
	"github.com/jackc/pgx/v4/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// UserRepo is the implementing type for the User interface defined in env.go
type UserRepo struct {
	pool *pgxpool.Pool
}

func NewUserRepo(pool *pgxpool.Pool) *UserRepo {
	return &UserRepo{
		pool: pool,
	}
}

// User is the struct mapping to the User table
type User struct {
	ID       int
	Username string
	Password string
}

// Create stores a new user in the database
func (ur UserRepo) Create(ctx context.Context, username, password string) error {
	bcryptCost := 10

	_, err := ur.GetByUsername(ctx, username)
	if err == nil {
		return fmt.Errorf("user with this username already exists")
	}

	hashedPass, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return fmt.Errorf("bcrypt.GenerateFromPassword: %v", err)
	}

	_, err = ur.pool.Exec(ctx,
		"INSERT INTO users (username, password) values ($1, $2)",
		username,
		hashedPass,
	)

	if err != nil {
		return fmt.Errorf("pool.Exec: %v", err)
	}

	return nil
}

func (ur UserRepo) GetByUsername(ctx context.Context, username string) (User, error) {
	u := ur.pool.QueryRow(ctx, "SELECT * FROM users WHERE username = $1", username)

	return scanToUser(u)
}

func (ur UserRepo) CheckPassword(ctx context.Context, username, password string) (bool, error) {
	u, err := ur.GetByUsername(ctx, username)
	if err != nil {
		return false, fmt.Errorf("GetByUsername: %v", err)
	}

	expectedPass := u.Password
	if err := bcrypt.CompareHashAndPassword([]byte(expectedPass), []byte(password)); err != nil {
		return false, nil
	}

	return true, nil
}

// utility functions
func scanToUser(r pgx.Row) (User, error) {
	var id int
	var username, password string

	if err := r.Scan(&id, &username, &password); err != nil {
		return User{}, fmt.Errorf("pgx.Row.Scan: %v", err)
	}

	return User{
		ID:       id,
		Username: username,
		Password: password,
	}, nil
}
