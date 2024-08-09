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
	Hash      string
	UserId    uuid.UUID
	ExpiresAt time.Time
	IsValid   bool
}

func NewRefreshTokens(db *pgxpool.Pool) *RefreshTokens {
	return &RefreshTokens{
		db: db,
	}
}

func (m *RefreshTokens) InsertToken(ctx context.Context, token RefreshToken) error {
	if len(token.Hash) != 60 {
		return fmt.Errorf("refresh_tokens: token hash length must be 60 bytes")
	}
	if token.ExpiresAt.Before(time.Now().UTC()) {
		return fmt.Errorf("refresh_tokens: the token has already expired")
	}

	tag, err := m.db.Exec(ctx, `
		INSERT INTO refresh_tokens
			(rt_hash, rt_user_id, rt_expires_at, rt_valid)
		VALUES
			($1, $2, $3, true)`,
		token.Hash, token.UserId, token.ExpiresAt)

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

func (m *RefreshTokens) RetrieveToken(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	if len(tokenHash) != 60 {
		return nil, fmt.Errorf("refresh_tokens: token hash length must be 60 bytes")
	}

	out := RefreshToken{
		Hash: tokenHash,
	}

	row := m.db.QueryRow(ctx, `
		SELECT rt_user_id, rt_expires_at, rt_valid
		FROM refresh_tokens
		WHERE rt_hash = $1`,
		tokenHash)

	err := row.Scan(&out.UserId, &out.ExpiresAt, &out.IsValid)
	if err != nil {
		return nil, err
	}

	return &out, nil
}

func (m *RefreshTokens) InvalidateToken(ctx context.Context, tokenHash string) error {
	if len(tokenHash) != 60 {
		return fmt.Errorf("refresh_tokens: token hash length must be 60 bytes")
	}

	tag, err := m.db.Exec(ctx, `
		UPDATE refresh_tokens
		SET rt_valid = false
		WHERE rt_hash = $1`,
		tokenHash)
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
