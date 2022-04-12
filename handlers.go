package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

//handlers and request/response types

type LoginRequest struct {
	Username string
	Password string
}

func (e Env) Login(w http.ResponseWriter, r *http.Request) {
	noData := map[string]interface{}{}
	if r.Method != "POST" {
		writeJsendError(w, "method not allowed"+r.Method, http.StatusMethodNotAllowed, noData)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	var parsedBody LoginRequest
	err := decodeJSONBody(w, r, &parsedBody)
	if err != nil {
		var mr *malformedRequest
		if errors.As(err, &mr) {
			writeJsendError(w, mr.msg, mr.status, noData)
		} else {
			writeJsendError(w, fmt.Sprintf("decodeJSONBody: %v", err), http.StatusInternalServerError, noData)
		}
		return
	}

	if parsedBody.Username == "" || parsedBody.Password == "" {
		writeJsendError(w, "username and password required", http.StatusBadRequest, noData)
		return
	}

	good, user, err := e.users.CheckPassword(r.Context(), parsedBody.Username, parsedBody.Password)
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

		ref, err := refreshFromUser(user, e.secret)
		if err != nil {
			writeJsendError(w, fmt.Sprintf("error generating refresh token: %v", err), http.StatusInternalServerError, noData)
			return
		}

		refCookie := &http.Cookie{
			Name:     "andthen_refresh",
			Value:    ref.String(),
			Expires:  time.Now().Add(4 * time.Hour),
			HttpOnly: true,
		}

		http.SetCookie(w, refCookie)

		writeJsendSuccess(w, map[string]interface{}{"id": user.ID, "username": user.Username})
		return
	}
	writeJsendFailure(w, map[string]interface{}{"validation": "incorrect username or password"})
}

func (e Env) Refresh(w http.ResponseWriter, r *http.Request) {
	noData := map[string]interface{}{}
	if r.Method != "GET" {
		writeJsendError(w, "method not allowed: "+r.Method, http.StatusMethodNotAllowed, noData)
		return
	}

	refCookie, err := r.Cookie("andthen_refresh")
	if err != nil {
		writeJsendError(w, "missing/bad andthen_refresh cookie", http.StatusBadRequest, noData)
		return
	}

	tok, err := parseToken(refCookie.Value, []byte(e.secret))
	if err != nil {
		writeJsendError(w,
			"error parsing JWT token for refresh",
			http.StatusInternalServerError,
			map[string]interface{}{"internalError": err.Error()},
		)
		return
	}

	exp, prs := tok.Payload["exp"]
	if !tok.Valid || !prs {
		writeJsendError(w, "JWT token invalid", http.StatusBadRequest, noData)
		return
	}

	expStr, ok := exp.(float64)
	if !ok {
		writeJsendError(w, fmt.Sprintf("JWT expiration time invalid: %v", exp), http.StatusBadRequest, noData)
		return
	}

	/*
		expFloat, err := strconv.ParseFloat(expStr, 64)
		if err != nil {
			writeJsendError(w, "JWT expiration time parse failure", http.StatusBadRequest, noData)
		}
	*/

	expTime := time.Unix(int64(expStr), 0)
	if expTime.Before(time.Now()) {
		writeJsendFailure(w, map[string]interface{}{"msg": "refresh token expired"})
		return
	}

	// since we know the refresh token is good, issue a new access token & refresh token
	uid, ok := tok.Payload["id"].(float64)
	if !ok {
		writeJsendError(w, fmt.Sprintf("bad uid in token: %T", tok.Payload["id"]), http.StatusBadRequest, noData)
		return
	}

	user, err := e.users.GetById(r.Context(), int(uid))
	if err != nil {
		writeJsendError(w, "user lookup failed: "+err.Error(), http.StatusInternalServerError, noData)
	}

	newAccess, err := jwtFromUser(user, e.secret)
	if err != nil {
		writeJsendError(w, "token generation failed", http.StatusInternalServerError, noData)
		return
	}

	newRefresh, err := refreshFromUser(user, e.secret)
	if err != nil {
		writeJsendError(w, "refresh token generation failed", http.StatusInternalServerError, noData)
		return
	}

	w.Header().Set("Authorization", "Bearer "+newAccess.String())
	newRefCookie := http.Cookie{
		Name:     "andthen_refresh",
		Value:    newRefresh.String(),
		HttpOnly: true,
		Expires:  time.Now().Add(4 * time.Hour),
	}

	http.SetCookie(w, &newRefCookie)
	writeJsendSuccess(w, map[string]interface{}{"id": user.ID, "username": user.Username})
}

type SignupRequest struct {
	Username string
	Password string
}

func (e Env) Signup(w http.ResponseWriter, r *http.Request) {
	noData := map[string]interface{}{}
	if r.Method != "POST" {
		writeJsendError(w, "method invalid: "+r.Method, http.StatusMethodNotAllowed, noData)
	}

	w.Header().Set("Content-Type", "application/json")

	var parsedBody SignupRequest
	err := decodeJSONBody(w, r, &parsedBody)
	if err != nil {
		var mr *malformedRequest
		if errors.As(err, &mr) {
			writeJsendError(w, mr.msg, mr.status, noData)
		} else {
			writeJsendError(w, fmt.Sprintf("decodeJSONBody: %v", err), http.StatusInternalServerError, noData)
		}
		return
	}

	if parsedBody.Username == "" || parsedBody.Password == "" {
		writeJsendError(w, "username and password required", http.StatusBadRequest, noData)
		return
	}

	if err := e.users.Create(r.Context(), parsedBody.Username, parsedBody.Password, false); err != nil {
		if err.Error() == "user with this username already exists" {
			writeJsendError(w, err.Error(), http.StatusConflict, noData)
			return
		}

		writeJsendError(w, "account creation error: "+err.Error(), http.StatusInternalServerError, noData)
		return
	}

	//TODO: hit player creation endpoint after creating user. Delete user if unable to create player.
	user, err := e.users.GetByUsername(r.Context(), parsedBody.Username)
	if err != nil {
		writeJsendError(w, "error fetching user data: "+err.Error(), http.StatusInternalServerError, noData)
		return
	}

	if err := e.users.NotifyPlayerService(r.Context(), user.Username, user.ID); err != nil {
		writeJsendError(w, "error notifying player service: "+err.Error(), http.StatusInternalServerError, noData)
		return
	}

	writeJsendSuccess(w, map[string]interface{}{"msg": "account created"})
	return
}

// utility

// jwt functions
//TODO: make time to expire configurable

func jwtFromUser(user User, secret string) (JWT, error) {
	jwtPayload := make(map[string]interface{})
	jwtPayload["id"] = user.ID
	jwtPayload["username"] = user.Username
	jwtPayload["admin"] = user.Admin
	jwtPayload["iat"] = time.Now().Unix()
	jwtPayload["exp"] = time.Now().Add(15 * time.Minute).Unix()
	jwtPayload["use"] = "auth"

	tok, err := newToken(jwtPayload, []byte(secret))
	if err != nil {
		return JWT{}, fmt.Errorf("newToken: %v", err)
	}

	return tok, nil
}

func refreshFromUser(user User, secret string) (JWT, error) {
	jwtPayload := make(map[string]interface{})
	jwtPayload["id"] = user.ID
	jwtPayload["username"] = user.Username
	jwtPayload["iat"] = time.Now().Unix()
	jwtPayload["exp"] = time.Now().Add(4 * time.Hour).Unix()
	jwtPayload["use"] = "refresh"

	tok, err := newToken(jwtPayload, []byte(secret))
	if err != nil {
		return JWT{}, fmt.Errorf("newToken: %v", err)
	}

	return tok, nil
}

// jsend helpers
type JsendError struct {
	Status  string                 `json:"status"`
	Message string                 `json:"message"`
	Code    int                    `json:"code"`
	Data    map[string]interface{} `json:"data"`
}

func (j JsendError) String() string {
	str, err := json.Marshal(j)
	if err != nil {
		return "{\"status\":\"error\",\"message\":\"Error generating error\", \"code\":500}"
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

	return jsendErr.String()
}

func writeJsendError(w http.ResponseWriter, message string, code int, data map[string]interface{}) {
	errMsg := jsendError(message, code, data)
	io.WriteString(w, errMsg)
}

type JsendSuccess struct {
	Status string                 `json:"status"`
	Data   map[string]interface{} `json:"data"`
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
	Status string                 `json:"status"`
	Data   map[string]interface{} `json:"data"`
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

// ditto the JsendSuccess comment
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

// JSON request parsing functions
// courtesy of https://www.alexedwards.net/blog/how-to-properly-parse-a-json-request-body

type malformedRequest struct {
	status int
	msg    string
}

func (mr *malformedRequest) Error() string {
	return mr.msg
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}) error {
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" && contentType != "" {
		msg := "Content-Type header is not application/json"
		return &malformedRequest{status: http.StatusUnsupportedMediaType, msg: msg}
	}

	// this will result in a case where a non-JSend error is returned; for now that's ok
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&dst)
	if err != nil {
		var syntaxError *json.SyntaxError
		var unmarshalTypeError *json.UnmarshalTypeError

		switch {
		case errors.As(err, &syntaxError):
			msg := fmt.Sprintf("Request body contains badly-formed JSON (at position %d)", syntaxError.Offset)
			return &malformedRequest{status: http.StatusBadRequest, msg: msg}
		case errors.Is(err, io.ErrUnexpectedEOF):
			msg := "Request body contains badly-formed JSON"
			return &malformedRequest{status: http.StatusBadRequest, msg: msg}
		case errors.As(err, &unmarshalTypeError):
			msg := fmt.Sprintf("Request body contains an invalid value for the %q field(at position %d)", unmarshalTypeError.Field, unmarshalTypeError.Offset)
			return &malformedRequest{status: http.StatusBadRequest, msg: msg}
		case strings.HasPrefix(err.Error(), "json: unknown field "):
			fieldName := strings.TrimPrefix(err.Error(), "json: unknown field ")
			msg := fmt.Sprintf("Request body contains unknown field %s", fieldName)
			return &malformedRequest{status: http.StatusBadRequest, msg: msg}
		case errors.Is(err, io.EOF):
			msg := "Request body must not be empty"
			return &malformedRequest{status: http.StatusBadRequest, msg: msg}
		case err.Error() == "http: request body too large":
			msg := "Request body must not be larger than 1MB"
			return &malformedRequest{status: http.StatusRequestEntityTooLarge, msg: msg}

		default:
			return err
		}
	}

	err = dec.Decode(&struct{}{})
	if err != io.EOF {
		msg := "Request body must only contain a single JSON object"
		return &malformedRequest{status: http.StatusBadRequest, msg: msg}
	}

	return nil
}
