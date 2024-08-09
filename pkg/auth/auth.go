package auth

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtIssuer       = "jwt_service"
	refreshAudience = "jwt_service/api/auth/refresh"
)

type tokenAuthority struct {
	accessKey, refreshKey []byte
	// todo: move durations up into main
	accessDuration, refreshDuration time.Duration
	audience                        []string
}

// NewTokenAuthority returns a struct responsible for generating and validating both access and refresh tokens.
// All operations are concurrency safe.
func NewTokenAuthority(accessKey string, refreshKey string) *tokenAuthority {
	return &tokenAuthority{
		accessKey:       []byte(accessKey),
		refreshKey:      []byte(refreshKey),
		accessDuration:  60 * time.Second,
		refreshDuration: 60 * time.Minute,
	}
}

func (ta *tokenAuthority) AddAudience(audience ...string) {
	ta.audience = append(ta.audience, audience...)
}

// jwt.NewNumericDate should use UTC under the hood. This is added as an additional peace of mind.
// See: https://datatracker.ietf.org/doc/html/rfc7519#section-2
func now() time.Time {
	return time.Now().UTC()
}

func (ta *tokenAuthority) NewAccess(userId uuid.UUID) (string, error) {
	claims := jwt.RegisteredClaims{
		Issuer:    jwtIssuer,
		Subject:   userId.String(),
		Audience:  ta.audience,
		ExpiresAt: jwt.NewNumericDate(now().Add(ta.accessDuration)),
		IssuedAt:  jwt.NewNumericDate(now()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	packed, err := token.SignedString(ta.accessKey)

	return packed, err
}

func (ta *tokenAuthority) AccessExpiresIn() time.Duration {
	return ta.accessDuration
}

func (ta *tokenAuthority) ParseAccess(token string, audience string) (uuid.UUID, error) {
	keyFunc := func(*jwt.Token) (interface{}, error) { return ta.accessKey, nil }
	jwt, err := jwt.Parse(token, keyFunc,
		jwt.WithValidMethods([]string{"HS512"}),
		jwt.WithIssuer(jwtIssuer),
		jwt.WithAudience(audience),
		jwt.WithIssuedAt())

	if err != nil || !jwt.Valid {
		return uuid.Nil, fmt.Errorf("auth: jwt is invalid, %w", err)
	}

	sub, err := jwt.Claims.GetSubject()
	if err != nil {
		return uuid.Nil, err
	}

	out, err := uuid.FromString(sub)
	return out, err
}

func (ta *tokenAuthority) NewRefresh() (string, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return "", err
	}

	packed := base64.StdEncoding.EncodeToString(id.Bytes())

	return packed, nil
}

func (ta *tokenAuthority) HashRefresh(refresh string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(refresh), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func (ta *tokenAuthority) RefreshExpiresAt() time.Time {
	return now().Add(ta.refreshDuration)
}

func (ta *tokenAuthority) CompareRefreshHashes(refresh string, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(refresh))
}

// type RefreshToken struct {
// }

// func (ta *tokenAuthority) RefreshToken(userId uuid.UUID) (string, error) {
// 	claims := jwt.RegisteredClaims{
// 		Issuer:    jwtIssuer,
// 		Audience:  []string{refreshAudience},
// 		Subject:   userId.String(),
// 		ExpiresAt: jwt.NewNumericDate(now().Add(ta.refreshDuration)),
// 		IssuedAt:  jwt.NewNumericDate(now()),
// 	}

// 	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
// 	signed, err := token.SignedString(ta.refreshKey)

// 	return signed, err
// }

// func (ta *tokenAuthority) ValidRefresh(token string, userId uuid.UUID) error {
// 	keyFunc := func(*jwt.Token) (interface{}, error) { return ta.refreshKey, nil }

// 	jwt, err := jwt.Parse(token, keyFunc,
// 		jwt.WithValidMethods([]string{"HS512"}),
// 		jwt.WithIssuer(jwtIssuer),
// 		jwt.WithAudience(refreshAudience),
// 		jwt.WithSubject(userId.String()),
// 		jwt.WithIssuedAt())

// 	if err != nil || !jwt.Valid {
// 		return fmt.Errorf("auth: jwt is invalid, %w", err)
// 	}
// 	return nil
// }
