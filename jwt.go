package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type JWT struct {
	Raw       string
	Header    map[string]interface{}
	Payload   map[string]interface{}
	Signature string
	Valid     bool
}

func (jwt JWT) String() string {
	return jwt.Raw
}

func parseToken(token string, secret []byte) (JWT, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return JWT{}, fmt.Errorf("token has more or less than 3 parts: %d, %+v", len(parts), parts)
	}

	headerPart := parts[0]
	payloadPart := parts[1]
	signaturePart := parts[2]

	header := make(map[string]interface{})
	headerBytes, err := base64.RawURLEncoding.DecodeString(headerPart)
	if err != nil {
		return JWT{}, fmt.Errorf("base64.DecodeString header: %v", err)
	}

	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return JWT{}, fmt.Errorf("json.Unmarshal: %v", err)
	}

	payload := make(map[string]interface{})
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		return JWT{}, fmt.Errorf("base64.DecodeString payload: %v", err)
	}

	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return JWT{}, fmt.Errorf("json.Unmarshal: %v", err)
	}

	signatureBytes, err := base64.RawURLEncoding.DecodeString(signaturePart)
	if err != nil {
		return JWT{}, fmt.Errorf("base64.DecodeString signature: %v", err)
	}
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(headerPart + "." + payloadPart))
	expected := h.Sum(nil)
	valid := hmac.Equal(signatureBytes, expected)

	return JWT{
		Raw:       token,
		Header:    header,
		Payload:   payload,
		Signature: string(signaturePart),
		Valid:     valid,
	}, nil
}

func newToken(payload map[string]interface{}, secret []byte) (JWT, error) {
	header := map[string]interface{}{"alg": "HS256", "typ": "JWT"}
	headerJson, err := json.Marshal(header)
	if err != nil {
		return JWT{}, fmt.Errorf("json.Marshal header: %v", err)
	}
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJson)

	payloadJson, err := json.Marshal(payload)
	if err != nil {
		return JWT{}, fmt.Errorf("json.Marhsal payload: %v", err)
	}
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadJson)

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(headerEncoded + "." + payloadEncoded))
	signature := mac.Sum(nil)
	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)

	return JWT{
		Raw:       headerEncoded + "." + payloadEncoded + "." + signatureEncoded,
		Header:    header,
		Payload:   payload,
		Signature: signatureEncoded,
		Valid:     true,
	}, nil
}
