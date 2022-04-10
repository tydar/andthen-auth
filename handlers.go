package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func (e Env) Login(w http.ResponseWriter, r *http.Request) {
	noData := map[string]interface{}{}
	if r.Method != "POST" {
		writeJsendError(w, "method not allowed"+r.Method, http.StatusMethodNotAllowed, noData)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	username := r.PostFormValue("username")
	password := r.PostFormValue("password")

	if username == "" || password == "" {
		writeJsendError(w, "username and password required", http.StatusBadRequest, noData)
		return
	}

	good, user, err := e.users.CheckPassword(r.Context(), username, password)
	if err != nil {
		writeJsendError(w, fmt.Sprintf("Database error: CheckPassword: %v", err), http.StatusInternalServerError, noData)
		return
	}

	if good {
		tok, err := jwtFromUser(user, e.secret)
		if err != nil {
			writeJsendError(w, fmt.Sprintf("error generating token: %v", err), http.StatusInternalServerError, noData)
			return
		}
		w.Header().Set("Authorization", "Bearer "+tok.String())
		writeJsendSuccess(w, map[string]interface{}{"id": user.ID, "username": user.Username})
		return
	}
	// fail...
	writeJsendFailure(w, map[string]interface{}{"validation": "incorrect username or password"})
}

// utility

func jwtResponse(w http.ResponseWriter, user User, secret string) {
	tok, err := jwtFromUser(user, secret)
	if err != nil {
		http.Error(w, fmt.Sprintf("jwtFromUser: %v", err), http.StatusInternalServerError)
	}

	io.WriteString(w, tok.String())
}

func jwtFromUser(user User, secret string) (JWT, error) {
	jwtPayload := make(map[string]interface{})
	jwtPayload["id"] = user.ID
	jwtPayload["username"] = user.Username

	tok, err := newToken(jwtPayload, []byte(secret))
	if err != nil {
		return JWT{}, fmt.Errorf("newToken: %v", err)
	}

	return tok, nil
}

// jsend helpers

type JsendError struct {
	Status  string
	Message string
	Code    int
	Data    map[string]interface{}
}

func (j JsendError) String() string {
	str, err := json.Marshal(j)
	if err != nil {
		return "{\"status\":\"error\",\"message\":\"Error generating error\"}"
	}

	return string(str)
}

func jsendError(message string, code int, data map[string]interface{}) string {
	jsendErr := JsendError{
		Status:  "error",
		Message: message,
	}

	if code > -1 {
		jsendErr.Code = code
	}

	if len(data) > 0 {
		jsendErr.Data = data
	}

	return fmt.Sprint(jsendErr)
}

func writeJsendError(w http.ResponseWriter, message string, code int, data map[string]interface{}) {
	errMsg := jsendError(message, code, data)
	http.Error(w, errMsg, code)
}

type JsendSuccess struct {
	Status string
	Data   map[string]interface{}
}

func (j JsendSuccess) String() string {
	var str []byte
	var err error
	if len(j.Data) == 0 {
		intermediate := make(map[string]interface{})
		intermediate["status"] = "success"
		intermediate["data"] = nil
		str, err = json.Marshal(intermediate)
	} else {
		str, err = json.Marshal(j)
	}

	if err != nil {
		return jsendError("bad server response",
			http.StatusInternalServerError,
			j.Data,
		)
	}

	return string(str)
}

func jsendSuccess(data map[string]interface{}) string {
	jsendSucc := JsendSuccess{
		Status: "success",
		Data:   data,
	}

	return jsendSucc.String()
}

// there is a chance this can write an error without setting an error status code but it should be very rare
// may come back to clean it up later
func writeJsendSuccess(w http.ResponseWriter, data map[string]interface{}) {
	io.WriteString(w, jsendSuccess(data))
}

type JsendFailure struct {
	Status string
	Data   map[string]interface{}
}

func (j JsendFailure) String() string {
	var str []byte
	var err error
	if len(j.Data) == 0 {
		intermediate := make(map[string]interface{})
		intermediate["status"] = "success"
		intermediate["data"] = nil
		str, err = json.Marshal(intermediate)
	} else {
		str, err = json.Marshal(j)
	}

	if err != nil {
		return jsendError("bad server response",
			http.StatusInternalServerError,
			j.Data,
		)
	}

	return string(str)
}

func jsendFailure(data map[string]interface{}) string {
	jsendFail := JsendFailure{
		Status: "fail",
		Data:   data,
	}

	return jsendFail.String()
}

func writeJsendFailure(w http.ResponseWriter, data map[string]interface{}) {
	io.WriteString(w, jsendFailure(data))
}
