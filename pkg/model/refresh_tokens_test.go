package model_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/joho/godotenv/autoload"
	"github.com/starnuik/golang_jwt_service/pkg/model"
	"github.com/stretchr/testify/require"
)

// these tests require a deployed postgres instance

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

	db, err := pgxpool.New(context.Background(), os.Getenv("TESTING_PG_URL"))
	require.Nil(err)

	err = db.Ping(context.Background())
	require.Nil(err)

	tokens := model.NewRefreshTokens(db)

	return tokens, func() { db.Close() }
}

// these tests require a deployed postgres instance
func TestRefreshTokenRoundtrip(t *testing.T) {
	require := require.New(t)

	tokens, close := setup(t)
	defer close()
	want := token()

	err := tokens.InsertToken(context.Background(), want)
	require.Nil(err)

	have, err := tokens.RetrieveToken(context.Background(), want.Id)
	require.Nil(err)
	require.Equal(want, *have)
}

// these tests require a deployed postgres instance
func TestInvalidateToken(t *testing.T) {
	require := require.New(t)

	tokens, close := setup(t)
	defer close()
	want := token()

	err := tokens.InsertToken(context.Background(), want)
	require.Nil(err)

	err = tokens.InvalidateToken(context.Background(), want.Id)
	require.Nil(err)

	have, err := tokens.RetrieveToken(context.Background(), want.Id)
	require.Nil(err)
	require.Equal(false, have.Active)
}

// these tests require a deployed postgres instance
func TestInvalidateOrphans(t *testing.T) {
	require := require.New(t)

	tokens, close := setup(t)
	defer close()
	wants := []model.RefreshToken{token(), token(), token()}
	userId := wants[0].UserId

	for _, tok := range wants {
		tok.UserId = userId
		tokens.InsertToken(context.Background(), tok)
	}

	err := tokens.InvalidateOrphanTokens(context.Background(), userId)
	require.Nil(err)

	for _, tok := range wants {
		have, _ := tokens.RetrieveToken(context.Background(), tok.Id)
		require.Equal(false, have.Active)
	}
}
