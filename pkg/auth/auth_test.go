package auth_test

import (
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/starnuik/golang_jwt_service/pkg/auth"
	"github.com/stretchr/testify/require"
)

func TestAccessRoundtrip(t *testing.T) {
	require := require.New(t)

	key := "salty-bacon"
	wantId, _ := uuid.FromString("12345678-1234-1234-1234-123456789abc")

	tokens := auth.NewTokenAuthority(key, "")
	tokens.AddAudience("aud-1", "aud-2")

	pair, err := tokens.NewPair(wantId)
	require.Nil(err)

	// received an access token
	access := pair.Response.AccessToken

	haveId, err := tokens.ParseAccess(access, "aud-1")
	require.Nil(err)
	require.Equal(wantId, haveId)

	haveId, err = tokens.ParseAccess(access, "aud-2")
	require.Nil(err)
	require.Equal(wantId, haveId)

	_, err = tokens.ParseAccess(access, "aud-3")
	require.NotNil(err)
}

func TestRefreshRoundtrip(t *testing.T) {
	require := require.New(t)

	key := "salty-bacon"
	userId, _ := uuid.FromString("12345678-1234-1234-1234-123456789abc")

	tokens := auth.NewTokenAuthority("", key)

	pair, err := tokens.NewPair(userId)
	require.Nil(err)

	wantToken := &pair.RefreshRow
	wantId := pair.RefreshRow.Id

	// received a refresh token
	refresh := pair.Response.RefreshToken

	haveId, err := tokens.ParseRefresh(refresh)
	require.Nil(err)
	require.Equal(wantId, haveId)

	err = tokens.CompareRefresh(refresh, wantToken)
	require.Nil(err)

	wantToken.Active = false
	err = tokens.CompareRefresh(refresh, wantToken)
	require.NotNil(err)

	wantToken.Active = true
	wantToken.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour)
	err = tokens.CompareRefresh(refresh, wantToken)
	require.NotNil(err)
}
