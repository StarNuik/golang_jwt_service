package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/starnuik/golang_jwt_service/pkg/auth"
	"github.com/starnuik/golang_jwt_service/pkg/email"
	"github.com/starnuik/golang_jwt_service/pkg/model"
	"github.com/starnuik/golang_jwt_service/pkg/schema"
)

var (
	tokAuth *auth.TokenAuthority
	tokens  *model.RefreshTokens
	users   *model.Users
	mail    *email.Sender
)

func errStatus(ctx *gin.Context, status int, err error) {
	log.Println(err)
	ctx.Status(status)
}

// https://stackoverflow.com/a/55738279
func readUserAddress(r *http.Request) netip.Addr {
	addr := r.Header.Get("X-Real-Ip")
	if addr == "" {
		addr = r.Header.Get("X-Forwarded-For")
	}
	if addr == "" {
		addr = r.RemoteAddr
	}

	portIdx := strings.Index(addr, ":")
	if portIdx >= 0 {
		addr = addr[:portIdx]
	}

	out, err := netip.ParseAddr(addr)
	if err != nil {
		out = netip.AddrFrom4([4]byte{0, 0, 0, 0})
		log.Println("main: could not parse ip:", err)
	}

	return out
}

func login(ctx *gin.Context) {
	var req schema.NewTokenRequest

	err := ctx.BindJSON(&req)
	if err != nil {
		errStatus(ctx, http.StatusBadRequest, err)
		return
	}

	userId, err := uuid.FromString(req.UserId)
	if err != nil {
		errStatus(ctx, http.StatusBadRequest, err)
		return
	}

	_, err = users.GetUser(context.TODO(), userId)
	if err != nil {
		errStatus(ctx, http.StatusUnauthorized, err)
		return
	}

	err = tokens.InvalidateAll(context.TODO(), userId)
	if err != nil {
		errStatus(ctx, http.StatusInternalServerError, err)
		return
	}

	returnNewPair(ctx, userId)
}

func returnNewPair(ctx *gin.Context, user uuid.UUID) {
	addr := readUserAddress(ctx.Request)
	pair, err := tokAuth.NewPair(user, addr)
	if err != nil {
		errStatus(ctx, http.StatusInternalServerError, err)
		return
	}

	err = tokens.Insert(context.TODO(), pair.RefreshRow)
	if err != nil {
		errStatus(ctx, http.StatusInternalServerError, err)
		return
	}

	ctx.IndentedJSON(http.StatusOK, pair.Response)
}

// https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation
func refreshToken(ctx *gin.Context) {
	var req schema.RefreshTokenRequest

	err := ctx.BindJSON(&req)
	if err != nil {
		errStatus(ctx, http.StatusBadRequest, err)
		return
	}

	payload, err := tokAuth.ParseRefresh(req.RefreshToken)
	if err != nil {
		errStatus(ctx, http.StatusBadRequest, err)
		return
	}

	token, err := tokens.Retrieve(context.TODO(), payload.TokenId)
	if err != nil {
		errStatus(ctx, http.StatusInternalServerError, err)
		return
	}

	addr := readUserAddress(ctx.Request)
	notifyIfAddressChanged(token.UserId, payload.UserAddress, addr)

	err = tokAuth.CompareRefresh(req.RefreshToken, token)
	if errors.Is(err, auth.ErrTokenReused) {
		errStatus(ctx, http.StatusUnauthorized, err)

		err = tokens.InvalidateAll(context.Background(), token.UserId)
		if err != nil {
			log.Printf("main: could not invalidate tokens after a token reuse: %v\n", err)
		}

		notifyTokenStolen(token.UserId)
		return
	}
	if err != nil {
		errStatus(ctx, http.StatusUnauthorized, err)
		return
	}

	err = tokens.Invalidate(context.TODO(), payload.TokenId)
	if err != nil {
		errStatus(ctx, http.StatusInternalServerError, err)
		return
	}

	returnNewPair(ctx, token.UserId)
}

func notifyTokenStolen(userId uuid.UUID) {
	go func() {
		user, err := users.GetUser(context.TODO(), userId)
		if err != nil {
			log.Printf("main: could not send a token reuse email: %v\n", err)
			return
		}

		err = mail.TokenStolen(user)
		if err != nil {
			log.Printf("main: could not send a token reuse email: %v\n", err)
			return
		}
	}()
}

func notifyIfAddressChanged(userId uuid.UUID, lastAddr netip.Addr, requestAddr netip.Addr) {
	if lastAddr == requestAddr {
		return
	}

	// 700ms -> 170ms fix (on my testing setup)
	go func() {
		user, err := users.GetUser(context.TODO(), userId)
		if err != nil {
			log.Printf("main: could not send an address change email: %v\n", err)
			return
		}

		err = mail.AddressChanged(user, lastAddr, requestAddr)
		if err != nil {
			log.Printf("main: could not send an address change email: %v\n", err)
			return
		}
	}()
}

func verifyToken(ctx *gin.Context) {
	var req schema.VerifyTokenRequest

	err := ctx.BindJSON(&req)
	if err != nil {
		errStatus(ctx, http.StatusBadRequest, err)
		return
	}

	_, err = tokAuth.ParseAccess(req.AccessToken, "jwt_service/api/verify_token")
	if err != nil {
		errStatus(ctx, http.StatusUnauthorized, err)
		return
	}

	ctx.Status(http.StatusOK)
}

func setupTokens() {
	accessKey := os.Getenv("ACCESS_TOKEN_KEY")
	refreshKey := os.Getenv("REFRESH_TOKEN_KEY")

	var withAccessDuration, withRefreshDuration auth.BuilderOption
	accessSeconds, err := strconv.Atoi(os.Getenv("ACCESS_TOKEN_SECONDS"))
	if err == nil {
		dur := time.Second * time.Duration(accessSeconds)
		withAccessDuration = auth.WithAccessTokenDuration(dur)
	}
	refreshMinutes, err := strconv.Atoi(os.Getenv("REFRESH_TOKEN_SECONDS"))
	if err == nil {
		dur := time.Second * time.Duration(refreshMinutes)
		withRefreshDuration = auth.WithRefreshTokenDuration(dur)
	}

	tokAuth = auth.NewTokenAuthority(accessKey, refreshKey,
		auth.WithAudience("jwt_service/api/verify_token"),
		withAccessDuration, withRefreshDuration)
}

func setupMail() {
	smtpUrl := os.Getenv("SMTP_URL")
	mail = email.NewSender(smtpUrl)
}

func setupModels() func() {
	dbUrl := os.Getenv("PG_URL")

	pool, err := pgxpool.New(context.Background(), dbUrl)
	if err != nil {
		log.Panicf("main: %v\n", err)
	}

	err = pool.Ping(context.Background())
	if err != nil {
		log.Panicf("main: %v\n", err)
	}

	tokens = model.NewRefreshTokens(pool)
	users = model.NewUsers(pool)

	return pool.Close
}

func main() {
	closeDb := setupModels()
	defer closeDb()

	setupMail()
	setupTokens()

	r := gin.Default()

	r.POST("/api/auth/login", login)
	r.POST("/api/auth/refresh", refreshToken)
	r.POST("/api/verify_token", verifyToken)

	r.Run()
}
