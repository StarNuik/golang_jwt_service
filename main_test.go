package main_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/starnuik/golang_jwt_service/pkg/schema"
	"github.com/stretchr/testify/require"
)

// these tests require the full compose.yaml deployed
var (
	jwtServiceUrl = "http://localhost:8000"
	pgUrl         = "postgres://pg:insecure@localhost:5432/dev"
	smtpHostname  = "localhost"
	smtpUrl       = smtpHostname + ":2525"
	smtpWeb       = "http://" + smtpHostname + ":8001"
)

func TestRoundtrip(t *testing.T) {
	require := require.New(t)
	userId := getUserId(t)
	userAddr := netip.AddrFrom4([4]byte{0, 0, 0, 0})

	tokens, err := login(userId, userAddr)
	require.Nil(err)

	err = pingProtected(tokens.AccessToken)
	require.Nil(err)

	for err == nil {
		err = pingProtected(tokens.AccessToken)
		time.Sleep(250 * time.Millisecond)
	}
	require.Equal("401 Unauthorized", err.Error())

	tokens, err = refresh(tokens.RefreshToken, userAddr)
	require.Nil(err)

	err = pingProtected(tokens.AccessToken)
	require.Nil(err)
}

func TestIpChange(t *testing.T) {
	require := require.New(t)
	userId := getUserId(t)
	lastSeen := smtpLastSeen()

	tokens, _ := login(userId, netip.AddrFrom4([4]byte{12, 34, 56, 78}))

	var err error
	for err == nil {
		err = pingProtected(tokens.AccessToken)
		time.Sleep(250 * time.Millisecond)
	}

	_, err = refresh(tokens.RefreshToken, netip.AddrFrom4([4]byte{98, 76, 54, 32}))
	require.Nil(err)

	mailCount := smtpCountNew(lastSeen)
	require.Equal(1, mailCount)
}

func TestTokenResuse(t *testing.T) {
	require := require.New(t)
	userId := getUserId(t)
	userAddr := netip.AddrFrom4([4]byte{0, 0, 0, 0})
	lastSeen := smtpLastSeen()

	tokens, _ := login(userId, userAddr)

	var err error
	for err == nil {
		err = pingProtected(tokens.AccessToken)
		time.Sleep(250 * time.Millisecond)
	}

	oldRefresh := tokens.RefreshToken
	tokens, _ = refresh(tokens.RefreshToken, userAddr)

	err = pingProtected(tokens.AccessToken)
	require.Nil(err)

	// attacker
	_, err = refresh(oldRefresh, userAddr)
	require.NotNil(err)

	mailCount := smtpCountNew(lastSeen)
	require.Equal(1, mailCount)
}

func getUserId(t *testing.T) uuid.UUID {
	require := require.New(t)

	db, err := sql.Open("pgx", pgUrl)
	require.Nil(err)

	row := db.QueryRow("select Id from Users limit 1;")
	require.Nil(row.Err())

	userId := uuid.Nil
	err = row.Scan(&userId)
	require.Nil(err)
	require.NotEqual(uuid.Nil, userId)

	return userId
}

func parseTokenPair(resp *http.Response) (*schema.TokenPairResponse, error) {
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%s", resp.Status)
	}

	pair := schema.TokenPairResponse{}
	err := json.NewDecoder(resp.Body).Decode(&pair)
	if err != nil {
		return nil, err
	}
	return &pair, nil
}

func login(userId uuid.UUID, addr netip.Addr) (*schema.TokenPairResponse, error) {
	body := bytes.NewBuffer([]byte(fmt.Sprintf("{\"UserId\": \"%s\"}", userId.String())))

	req, err := http.NewRequest("POST", jwtServiceUrl+"/api/auth/login", body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Forwarded-For", addr.String())

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return parseTokenPair(resp)
}

func pingProtected(accessToken string) error {
	body := bytes.NewBuffer([]byte(fmt.Sprintf("{\"AccessToken\": \"%s\"}", accessToken)))
	resp, err := http.Post(jwtServiceUrl+"/api/verify_token", "application/json", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s", resp.Status)
	}
	return nil
}

func refresh(refreshToken string, addr netip.Addr) (*schema.TokenPairResponse, error) {
	body := bytes.NewBuffer([]byte(fmt.Sprintf("{\"RefreshToken\": \"%s\"}", refreshToken)))

	req, err := http.NewRequest("POST", jwtServiceUrl+"/api/auth/refresh", body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Forwarded-For", addr.String())

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return parseTokenPair(resp)
}

func smtpLastSeen() string {
	url := fmt.Sprintf("%s/api/Messages/new?pageSize=1", smtpWeb)
	resp, _ := http.Get(url)

	defer resp.Body.Close()

	into := []struct {
		Id string `json:"id"`
	}{}
	json.NewDecoder(resp.Body).Decode(&into)
	if len(into) == 0 {
		return ""
	}
	return into[0].Id
}

func smtpCountNew(lastSeen string) int {
	// mail sending doesn't block the response, so we need to wait a bit
	time.Sleep(500 * time.Millisecond)

	url := fmt.Sprintf("%s/api/Messages/new?pageSize=100&lastSeenMessageId=%s", smtpWeb, lastSeen)
	resp, _ := http.Get(url)

	defer resp.Body.Close()

	into := []struct {
		Id string `json:"id"`
	}{}
	json.NewDecoder(resp.Body).Decode(&into)
	return len(into)
}
