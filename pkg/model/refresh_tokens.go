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
	Id        uuid.UUID
	UserId    uuid.UUID
	Hash      string
	ExpiresAt time.Time
	Active    bool
}

func NewRefreshTokens(db *pgxpool.Pool) *RefreshTokens {
	return &RefreshTokens{
		db: db,
	}
}

func (m *RefreshTokens) Insert(ctx context.Context, token RefreshToken) error {
	tag, err := m.db.Exec(ctx, `
		INSERT INTO RefreshTokens
			(Id, UserId, Hash, ExpiresAt, Active)
		VALUES
			($1, $2, $3, $4, $5)`,
		token.Id, token.UserId, token.Hash, token.ExpiresAt, token.Active)

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

func (m *RefreshTokens) Retrieve(ctx context.Context, tokenId uuid.UUID) (*RefreshToken, error) {
	out := RefreshToken{
		Id: tokenId,
	}

	row := m.db.QueryRow(ctx, `
		SELECT UserId, Hash, ExpiresAt, Active
		FROM RefreshTokens
		WHERE Id = $1`,
		tokenId)

	err := row.Scan(&out.UserId, &out.Hash, &out.ExpiresAt, &out.Active)
	if err != nil {
		return nil, err
	}

	return &out, nil
}

func (m *RefreshTokens) Invalidate(ctx context.Context, tokenId uuid.UUID) error {
	tag, err := m.db.Exec(ctx, `
		UPDATE RefreshTokens
		SET Active = false
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

func (m *RefreshTokens) InvalidateAll(ctx context.Context, userId uuid.UUID) error {
	tag, err := m.db.Exec(ctx, `
		UPDATE RefreshTokens
		SET Active = false
		WHERE UserId = $1`,
		userId)
	if err != nil {
		return err
	}
	if !tag.Update() {
		return fmt.Errorf("refresh_tokens: %s instead of UPDATE", tag.String())
	}
	return nil
}
