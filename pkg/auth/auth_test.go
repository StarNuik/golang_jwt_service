package auth_test

import (
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/starnuik/golang_jwt_service/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccessRoundtrip(t *testing.T) {
	require := require.New(t)

	key := "salty-bacon"
	wantId, _ := uuid.FromString("12345678-1234-1234-1234-123456789abc")

	tokens := auth.NewTokenAuthority(key, "")
	tokens.AddAudience("aud-1", "aud-2")

	packed, err := tokens.NewAccessToken(wantId)
	require.Nil(err)

	haveId, err := tokens.ParseAccess(packed, "aud-1")
	require.Nil(err)
	require.Equal(wantId, haveId)

	haveId, err = tokens.ParseAccess(packed, "aud-2")
	require.Nil(err)
	require.Equal(wantId, haveId)

	_, err = tokens.ParseAccess(packed, "aud-3")
	require.NotNil(err)
}

// im overdoing it, the jwt lib should have already tested for this
func TestParseAccessClaims(t *testing.T) {
	assert := assert.New(t)

	key := "salty-bacon"
	wantId, _ := uuid.FromString("12345678-1234-1234-1234-123456789abc")

	tokens := auth.NewTokenAuthority(key, "")
	tokens.AddAudience("aud-1", "aud-2")

	packed, _ := tokens.NewAccessToken(wantId)

	original, _ := jwt.ParseWithClaims(packed, jwt.RegisteredClaims{}, func(*jwt.Token) (interface{}, error) { return key, nil })

	tt := make([]jwt.RegisteredClaims, 5)
	for idx := range tt {
		tt[idx] = original.Claims.(jwt.RegisteredClaims)
	}
	tt[0].Issuer = "h4ck3r"
	tt[1].Subject = uuid.Nil.String()
	tt[2].Audience = []string{"admin-resource"}
	tt[3].ExpiresAt = jwt.NewNumericDate(time.Now())
	tt[4].IssuedAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))

	for _, claims := range tt {
		token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
		packed, _ := token.SignedString(key)

		_, err := tokens.ParseAccess(packed, "aud-1")
		assert.NotNil(err)
		_, err = tokens.ParseAccess(packed, "admin-resource")
		assert.NotNil(err)
	}
}
