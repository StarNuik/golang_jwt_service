package model

import (
	"context"
	"fmt"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RefreshTokens struct {
	db *pgxpool.Pool
}

type RefreshToken struct {
	Id          uuid.UUID
	UserId      uuid.UUID
	Hash        string
	ExpiresAt   time.Time
	Deactivated bool
}

func NewRefreshTokens(db *pgxpool.Pool) *RefreshTokens {
	return &RefreshTokens{
		db: db,
	}
}

func (m *RefreshTokens) InsertToken(ctx context.Context, token RefreshToken) error {
	tag, err := m.db.Exec(ctx, `
		INSERT INTO RefreshTokens
			(Id, UserId, Hash, ExpiresAt, Deactivated)
		VALUES
			($1, $2, $3, $4, $5)`,
		token.Id, token.UserId, token.Hash, token.ExpiresAt, token.Deactivated)

	if err != nil {
		return err
	}
	if !tag.Insert() {
		return fmt.Errorf("refresh_tokens: %s instead of INSERT", tag.String())
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("refresh_tokens: inserted %d rows", tag.RowsAffected())
	}

	return nil
}

func (m *RefreshTokens) RetrieveToken(ctx context.Context, tokenId uuid.UUID) (*RefreshToken, error) {
	out := RefreshToken{
		Id: tokenId,
	}

	row := m.db.QueryRow(ctx, `
		SELECT UserId, Hash, ExpiresAt, Deactivated
		FROM RefreshTokens
		WHERE Id = $1`,
		tokenId)

	err := row.Scan(&out.UserId, &out.Hash, &out.ExpiresAt, &out.Deactivated)
	if err != nil {
		return nil, err
	}

	return &out, nil
}

func (m *RefreshTokens) InvalidateToken(ctx context.Context, tokenId uuid.UUID) error {
	tag, err := m.db.Exec(ctx, `
		UPDATE RefreshTokens
		SET Deactivated = false
		WHERE Id = $1`,
		tokenId)
	if err != nil {
		return err
	}
	if !tag.Update() {
		return fmt.Errorf("refresh_tokens: %s instead of UPDATE", tag.String())
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("refresh_tokens: updated %d rows", tag.RowsAffected())
	}
	return nil
}
