package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/netip"
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

type TokenAuthority struct {
	accessKey, refreshKey           []byte
	accessDuration, refreshDuration time.Duration
	audience                        []string
}

type BuilderOption func(ta *TokenAuthority)

func WithAccessTokenDuration(in time.Duration) BuilderOption {
	return func(ta *TokenAuthority) {
		ta.accessDuration = in
	}
}

func WithRefreshTokenDuration(in time.Duration) BuilderOption {
	return func(ta *TokenAuthority) {
		ta.refreshDuration = in
	}
}

func WithAudience(audience ...string) BuilderOption {
	return func(ta *TokenAuthority) {
		ta.audience = audience
	}
}

// NewTokenAuthority returns a struct responsible for generating and validating both access and refresh tokens.
// All operations are concurrency safe.
func NewTokenAuthority(accessKey string, refreshKey string, options ...BuilderOption) *TokenAuthority {
	out := TokenAuthority{
		accessKey:       []byte(accessKey),
		refreshKey:      []byte(refreshKey),
		accessDuration:  5 * time.Minute,
		refreshDuration: 60 * time.Minute,
		audience:        nil,
	}
	for _, opt := range options {
		if opt != nil {
			opt(&out)
		}
	}
	return &out
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

// type tokenClaims struct {
// 	jwt.RegisteredClaims
// 	UserId  uuid.UUID `json:"sui,omitempty"`
// 	TokenId uuid.UUID `json:"tki,omitempty"`
// }

type accessTokenClaims struct {
	jwt.RegisteredClaims
	UserId uuid.UUID `json:"sui"`
}

type refreshTokenClaims struct {
	jwt.RegisteredClaims
	refreshPayload
}

type refreshPayload struct {
	TokenId     uuid.UUID  `json:"tki"`
	UserAddress netip.Addr `json:"adr"`
}

func (ta *TokenAuthority) NewPair(userId uuid.UUID, userAddress netip.Addr) (*TokenPair, error) {
	refreshId, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	refresh, err := ta.newRefresh(refreshId, userAddress)
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

func (ta *TokenAuthority) newRefreshRow(refreshId uuid.UUID, userId uuid.UUID, refresh string) (*model.RefreshToken, error) {
	hash, err := hashRefresh(refresh)
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

func (ta *TokenAuthority) newAccess(userId uuid.UUID) (string, error) {
	return packClaims(ta.accessKey, accessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    jwtIssuer,
			Audience:  ta.audience,
			ExpiresAt: jwt.NewNumericDate(now().Add(ta.accessDuration)),
			IssuedAt:  jwt.NewNumericDate(now()),
		},
		UserId: userId,
	})
}

func (ta *TokenAuthority) newRefresh(refreshId uuid.UUID, userAddress netip.Addr) (string, error) {
	return packClaims(ta.refreshKey, refreshTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    jwtIssuer,
			Audience:  []string{refreshAudience},
			ExpiresAt: jwt.NewNumericDate(now().Add(ta.refreshDuration)),
			IssuedAt:  jwt.NewNumericDate(now()),
		},
		refreshPayload: refreshPayload{
			TokenId:     refreshId,
			UserAddress: userAddress,
		},
	})
}

func packClaims(key []byte, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	packed, err := token.SignedString(key)
	return packed, err
}

func prehashRefresh(refresh string) []byte {
	// todo: this is probably a security vulnerability
	compact := sha256.Sum256([]byte(refresh))
	// bcrypt doesn't handle \0-s or other special ASCII symbols very well
	based := base64.StdEncoding.EncodeToString(compact[:])
	return []byte(based)
}

func hashRefresh(refresh string) (string, error) {
	prehash := prehashRefresh(refresh)
	hash, err := bcrypt.GenerateFromPassword(prehash, bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func (ta *TokenAuthority) ParseAccess(token string, audience string) (uuid.UUID, error) {
	claims := accessTokenClaims{}
	err := unpackClaims(ta.accessKey, token, audience, &claims)
	if err != nil {
		return uuid.Nil, err
	}

	userId := claims.UserId
	return userId, err
}

func (ta *TokenAuthority) ParseRefresh(token string) (*refreshPayload, error) {
	claims := refreshTokenClaims{}
	err := unpackClaims(ta.refreshKey, token, refreshAudience, &claims)
	if err != nil {
		return nil, err
	}

	return &claims.refreshPayload, nil
}

func unpackClaims(key []byte, packed string, audience string, into jwt.Claims) error {
	keyFunc := func(*jwt.Token) (interface{}, error) { return key, nil }
	token, err := jwt.ParseWithClaims(packed, into, keyFunc, jwt.WithValidMethods([]string{"HS512"}),
		jwt.WithIssuer(jwtIssuer),
		jwt.WithAudience(audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt())
	if err != nil || !token.Valid {
		return fmt.Errorf("auth: jwt is invalid, %w", err)
	}
	return nil
}

var ErrTokenReused = fmt.Errorf("auth: out of rotation token reused")

func (ta *TokenAuthority) CompareRefresh(clientRefresh string, storedRefresh *model.RefreshToken) error {
	// outdated token: no worries
	if storedRefresh.ExpiresAt.Before(now()) {
		return fmt.Errorf("auth: token has expired")
	}

	// the token has been tampered with (token.Id matches, but the body doesn't): there is a possibility of an attack, but the user hasn't been compromised yet
	prehash := prehashRefresh(clientRefresh)
	err := bcrypt.CompareHashAndPassword([]byte(storedRefresh.Hash), prehash)
	if err != nil {
		return err
	}

	// token matches, but was already used: the user may have been compromised
	if !storedRefresh.Active {
		return ErrTokenReused
	}

	return nil
}
