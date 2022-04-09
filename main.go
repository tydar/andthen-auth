package main

import "fmt"

func main() {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	secret := []byte("your-256-bit-secret")

	jwt, err := parseToken(token, secret)
	if err != nil {
		panic(err)
	}

	fmt.Println(jwt)

	payload := jwt.Payload
	jwt2, err := newToken(payload, secret)
	if err != nil {
		panic(err)
	}

	fmt.Println(jwt2)
	jwt3, err := parseToken(jwt2.Raw, secret)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%v\n", jwt3.Valid)
}
