package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/starnuik/golang_jwt_service/pkg/model"
	"github.com/starnuik/golang_jwt_service/pkg/schema"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtIssuer       = "jwt_service"
	refreshAudience = "jwt_service/api/auth/refresh"
)

type tokenAuthority struct {
	accessKey, refreshKey           []byte
	accessDuration, refreshDuration time.Duration
	audience                        []string
}

// NewTokenAuthority returns a struct responsible for generating and validating both access and refresh tokens.
// All operations are concurrency safe.
func NewTokenAuthority(accessKey string, refreshKey string) *tokenAuthority {
	return &tokenAuthority{
		accessKey:       []byte(accessKey),
		refreshKey:      []byte(refreshKey),
		accessDuration:  5 * time.Second,
		refreshDuration: 30 * time.Second,
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

type TokenPair struct {
	Response   schema.TokenPairResponse
	RefreshRow model.RefreshToken
}

type tokenClaims struct {
	jwt.RegisteredClaims
	UserId  uuid.UUID `json:"sui,omitempty"`
	TokenId uuid.UUID `json:"tki,omitempty"`
}

func (ta *tokenAuthority) NewPair(userId uuid.UUID) (*TokenPair, error) {
	refreshId, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	refresh, err := ta.newRefresh(refreshId, userId)
	if err != nil {
		return nil, err
	}

	row, err := ta.newRefreshRow(refreshId, userId, refresh)
	if err != nil {
		return nil, err
	}

	access, err := ta.newAccess(userId)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		RefreshRow: *row,
		Response: schema.TokenPairResponse{
			AccessToken:  access,
			ExpiresIn:    int(ta.accessDuration.Seconds()),
			RefreshToken: refresh,
		},
	}, nil
}

func (ta *tokenAuthority) newRefreshRow(refreshId uuid.UUID, userId uuid.UUID, refresh string) (*model.RefreshToken, error) {
	hash, err := ta.hashRefresh(refresh)
	if err != nil {
		return nil, err
	}

	return &model.RefreshToken{
		Id:        refreshId,
		Hash:      hash,
		UserId:    userId,
		ExpiresAt: now().Add(ta.refreshDuration),
		Active:    true,
	}, nil
}

func (ta *tokenAuthority) newAccess(userId uuid.UUID) (string, error) {
	return ta.packClaims(ta.accessKey, tokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    jwtIssuer,
			Audience:  ta.audience,
			ExpiresAt: jwt.NewNumericDate(now().Add(ta.accessDuration)),
			IssuedAt:  jwt.NewNumericDate(now()),
		},
		UserId: userId,
	})
}

func (ta *tokenAuthority) newRefresh(refreshId uuid.UUID, userId uuid.UUID) (string, error) {
	return ta.packClaims(ta.refreshKey, tokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    jwtIssuer,
			Audience:  []string{refreshAudience},
			ExpiresAt: jwt.NewNumericDate(now().Add(ta.refreshDuration)),
			IssuedAt:  jwt.NewNumericDate(now()),
		},
		UserId:  userId,
		TokenId: refreshId,
	})
}

func (ta *tokenAuthority) packClaims(key []byte, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	packed, err := token.SignedString(key)
	return packed, err
}

func (ta *tokenAuthority) prehashRefresh(refresh string) []byte {
	// todo: this is probably a security vulnerability
	compact := sha256.Sum256([]byte(refresh))
	// bcrypt doesn't handle \0-s or other special ASCII symbols very well
	based := base64.StdEncoding.EncodeToString(compact[:])
	return []byte(based)
}

func (ta *tokenAuthority) hashRefresh(refresh string) (string, error) {
	prehash := ta.prehashRefresh(refresh)
	hash, err := bcrypt.GenerateFromPassword(prehash, bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func (ta *tokenAuthority) ParseAccess(token string, audience string) (uuid.UUID, error) {
	claims, err := unpackClaims(ta.accessKey, token, audience)
	if err != nil {
		return uuid.Nil, err
	}

	userId := claims.UserId
	return userId, err
}

func (ta *tokenAuthority) ParseRefresh(token string) (uuid.UUID, error) {
	claims, err := unpackClaims(ta.refreshKey, token, refreshAudience)
	if err != nil {
		return uuid.Nil, err
	}

	return claims.TokenId, nil
}

func unpackClaims(key []byte, packed string, audience string) (*tokenClaims, error) {
	out := tokenClaims{}
	keyFunc := func(*jwt.Token) (interface{}, error) { return key, nil }
	token, err := jwt.ParseWithClaims(packed, &out, keyFunc, jwt.WithValidMethods([]string{"HS512"}),
		jwt.WithIssuer(jwtIssuer),
		jwt.WithAudience(audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt())
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("auth: jwt is invalid, %w", err)
	}
	return &out, nil
}

func (ta *tokenAuthority) CompareRefresh(client string, server *model.RefreshToken) error {
	if !server.Active {
		return fmt.Errorf("auth: the token is out of rotation")
	}
	if server.ExpiresAt.Before(now()) {
		return fmt.Errorf("auth: the token has expired")
	}
	prehash := ta.prehashRefresh(client)
	err := bcrypt.CompareHashAndPassword([]byte(server.Hash), prehash)
	return err
}

// func (ta *tokenAuthority) CompareRefreshHashes(refresh string, hash string) error {
// 	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(refresh))
// }

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
