package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/jackc/pgx/v4/pgxpool"
)

func main() {
	dbUrl := os.Getenv("DATABASE_URL")
	servePort := os.Getenv("PORT")
	if servePort == "" {
		servePort = "8080"
	}

	cf, err := pgxpool.ParseConfig(dbUrl)
	if err != nil {
		log.Fatalf("pgxpool.ParseConfig: %v", err)
	}

	pool, err := pgxpool.ConnectConfig(context.Background(), cf)
	if err != nil {
		log.Fatalf("pgxpool.ConnectConfig: %v", err)
	}

	env := NewEnv(pool, "your-256-bit-secret")

	if err := env.users.Create(context.TODO(), "test", "test2"); err != nil {
		log.Fatalf("env.users.Create: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login/", env.Login)
	mux.HandleFunc("/refresh/", env.Refresh)

	if err := http.ListenAndServe(":"+servePort, mux); err != nil {
		log.Fatalf("ListenAndServe: %v", err)
	}
}
