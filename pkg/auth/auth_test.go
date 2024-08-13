package auth_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/starnuik/golang_jwt_service/pkg/auth"
	"github.com/stretchr/testify/require"
)

func TestAccessRoundtrip(t *testing.T) {
	require := require.New(t)

	wantId, _ := uuid.FromString("12345678-1234-1234-1234-123456789abc")

	tokens := auth.NewTokenAuthority("salty-bacon", "",
		auth.WithAudience("aud-1", "aud-2"))

	pair, err := tokens.NewPair(wantId, netip.Addr{})
	require.Nil(err)

	// http.Post(access)
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

	userId, _ := uuid.FromString("12345678-1234-1234-1234-123456789abc")
	userAddr := netip.AddrFrom4([4]byte{12, 34, 56, 78})

	tokens := auth.NewTokenAuthority("", "bacon-pancakes")

	pair, err := tokens.NewPair(userId, userAddr)
	require.Nil(err)

	wantToken := &pair.RefreshRow
	wantId := pair.RefreshRow.Id

	// http.Post(refresh)
	refresh := pair.Response.RefreshToken

	payload, err := tokens.ParseRefresh(refresh)
	require.Nil(err)
	require.Equal(wantId, payload.TokenId)
	require.Equal(userAddr, payload.UserAddress)

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
