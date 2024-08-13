package model_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/starnuik/golang_jwt_service/pkg/model"
	"github.com/stretchr/testify/require"
)

// these tests require a deployed postgres instance
var pgUrl = "postgres://pg:insecure@localhost:5432/dev"

func token() model.RefreshToken {
	tokenId, _ := uuid.NewV4()
	userId, _ := uuid.NewV4()

	hashBytes := sha256.Sum256(tokenId[:])
	hash := hex.EncodeToString(hashBytes[:])
	return model.RefreshToken{
		Id:        tokenId,
		UserId:    userId,
		Hash:      hash,
		ExpiresAt: time.Now().UTC().Round(time.Millisecond),
		Active:    true,
	}
}

func setup(t *testing.T) (*model.RefreshTokens, func()) {
	require := require.New(t)

	db, err := pgxpool.New(context.Background(), pgUrl)
	require.Nil(err)

	err = db.Ping(context.Background())
	require.Nil(err)

	tokens := model.NewRefreshTokens(db)

	return tokens, func() { db.Close() }
}

func TestRefreshTokenRoundtrip(t *testing.T) {
	require := require.New(t)

	tokens, close := setup(t)
	defer close()
	want := token()

	err := tokens.Insert(context.Background(), want)
	require.Nil(err)

	have, err := tokens.Retrieve(context.Background(), want.Id)
	require.Nil(err)
	require.Equal(want, *have)
}

func TestInvalidateToken(t *testing.T) {
	require := require.New(t)

	tokens, close := setup(t)
	defer close()
	want := token()

	err := tokens.Insert(context.Background(), want)
	require.Nil(err)

	err = tokens.Invalidate(context.Background(), want.Id)
	require.Nil(err)

	have, err := tokens.Retrieve(context.Background(), want.Id)
	require.Nil(err)
	require.Equal(false, have.Active)
}

func TestInvalidateOrphans(t *testing.T) {
	require := require.New(t)

	tokens, close := setup(t)
	defer close()
	wants := []model.RefreshToken{token(), token(), token()}
	userId := wants[0].UserId

	for _, tok := range wants {
		tok.UserId = userId
		tokens.Insert(context.Background(), tok)
	}

	err := tokens.InvalidateAll(context.Background(), userId)
	require.Nil(err)

	for _, tok := range wants {
		have, _ := tokens.Retrieve(context.Background(), tok.Id)
		require.Equal(false, have.Active)
	}
}
