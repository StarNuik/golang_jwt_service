package model

import (
	"context"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Users struct {
	db *pgxpool.Pool
}

type User struct {
	Id    uuid.UUID
	Name  string
	Email string
}

func NewUsers(db *pgxpool.Pool) *Users {
	return &Users{
		db: db,
	}
}

func (m *Users) GetUser(ctx context.Context, userId uuid.UUID) (*User, error) {
	out := User{}
	row := m.db.QueryRow(ctx, `
		select Id, Name, Email
		from Users
		where Id = $1`,
		userId)
	err := row.Scan(&out.Id, &out.Name, &out.Email)
	if err != nil {
		return nil, err
	}
	return &out, nil
}
