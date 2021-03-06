package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// UserRepo is the implementing type for the User interface defined in env.go
type UserRepo struct {
	pool *pgxpool.Pool
}

func NewUserRepo(pool *pgxpool.Pool) UserRepo {
	return UserRepo{
		pool: pool,
	}
}

// User is the struct mapping to the User table
type User struct {
	ID       int
	Username string
	Password string
	Admin    bool
}

func (u User) ToSafeJSONString() string {
	// since it's a flat known object, just spit out the JSON string representation w/o password hash
	// to avoid error juggling from encoding/json
	// may have to change later if user records become more complex

	return fmt.Sprintf("{\"username\":\"%s\",\"id\":%d,\"admin\":%t}", u.Username, u.ID, u.Admin)
}

// Create stores a new user in the database
func (ur UserRepo) Create(ctx context.Context, username, password string, admin bool) error {
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
		"INSERT INTO users (username, password, admin) values ($1, $2, $3)",
		username,
		hashedPass,
		admin,
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

func (ur UserRepo) GetById(ctx context.Context, id int) (User, error) {
	u := ur.pool.QueryRow(ctx, "SELECT * FROM users WHERE id = $1", id)

	return scanToUser(u)
}

func (ur UserRepo) Delete(ctx context.Context, id int) error {
	_, err := ur.pool.Exec(ctx, "DELETE FROM users WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("pool.Exec: %v", err)
	}

	return nil
}

func (ur UserRepo) CheckPassword(ctx context.Context, username, password string) (bool, User, error) {
	u, err := ur.GetByUsername(ctx, username)
	if err != nil {
		return false, User{}, fmt.Errorf("GetByUsername: %v", err)
	}

	expectedPass := u.Password
	if err := bcrypt.CompareHashAndPassword([]byte(expectedPass), []byte(password)); err != nil {
		return false, User{}, nil
	}

	return true, u, nil
}

func (ur UserRepo) ChangePassword(ctx context.Context, username, password string) error {
	bcryptCost := 10

	u, err := ur.GetByUsername(ctx, username)
	if err != nil {
		return fmt.Errorf("GetByUsername: %v", err)
	}

	hashedPass, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return fmt.Errorf("bcrypt.GenerateFromPassword: %v", err)
	}

	_, err = ur.pool.Exec(ctx,
		"UPDATE users SET password = $1 WHERE id = $2",
		hashedPass,
		u.ID,
	)

	if err != nil {
		return fmt.Errorf("pool.Exec: %v", err)
	}

	return nil
}

type NotificationPayload struct {
	DisplayName string `json:"display_name"`
	UserId      int    `json:"user_id"`
}

func (ur UserRepo) NotifyPlayerService(ctx context.Context, display string, id int) error {
	payload := NotificationPayload{DisplayName: display, UserId: id}
	payloadStr, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("json.Marshal: %v", err)
	}

	_, err = ur.pool.Exec(ctx,
		"SELECT pg_notify('user_player', $1)",
		payloadStr,
	)
	if err != nil {
		return fmt.Errorf("pool.Exec: %v", err)
	}

	return nil
}

// utility functions
func scanToUser(r pgx.Row) (User, error) {
	var id int
	var username, password string
	var admin bool

	if err := r.Scan(&id, &username, &password, &admin); err != nil {
		return User{}, fmt.Errorf("pgx.Row.Scan: %v", err)
	}

	return User{
		ID:       id,
		Username: username,
		Password: password,
		Admin:    admin,
	}, nil
}
