package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/gofrs/uuid/v5"
	_ "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/joho/godotenv/autoload"
	"github.com/starnuik/golang_jwt_service/pkg/auth"
	"github.com/starnuik/golang_jwt_service/pkg/model"
	"github.com/starnuik/golang_jwt_service/pkg/schema"
)

var (
	jwtKey  = os.Getenv("JWT_KEY")
	dbUrl   = os.Getenv("PG_URL")
	tokAuth = auth.NewTokenAuthority(jwtKey, jwtKey)
	tokens  *model.RefreshTokens
	users   *model.Users
)

func errStatus(ctx *gin.Context, status int, err error) {
	log.Println(err)
	ctx.Status(status)
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

	returnNewPair(ctx, userId)
}

func returnNewPair(ctx *gin.Context, user uuid.UUID) {
	pair, err := tokAuth.NewPair(user)
	if err != nil {
		errStatus(ctx, http.StatusInternalServerError, err)
		return
	}

	err = tokens.InsertToken(context.TODO(), pair.RefreshRow)
	if err != nil {
		errStatus(ctx, http.StatusInternalServerError, err)
		return
	}

	// todo: "MUST include the HTTP "Cache-Control" response header field [RFC2616] with a value of "no-store" in any response containing tokens, credentials, or other sensitive information..."
	// todo: (MUST include) "the "Pragma" response header field [RFC2616] with a value of "no-cache"."
	ctx.IndentedJSON(http.StatusOK, pair.Response)
}

// ? https://stackoverflow.com/a/67386228
// ? https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation
func refreshToken(ctx *gin.Context) {
	var req schema.RefreshTokenRequest

	err := ctx.BindJSON(&req)
	if err != nil {
		errStatus(ctx, http.StatusBadRequest, err)
		return
	}

	tokenId, err := tokAuth.ParseRefresh(req.RefreshToken)
	if err != nil {
		errStatus(ctx, http.StatusBadRequest, err)
		return
	}

	token, err := tokens.RetrieveToken(context.TODO(), tokenId)
	if err != nil {
		errStatus(ctx, http.StatusInternalServerError, err)
		return
	}

	err = tokAuth.CompareRefresh(req.RefreshToken, token)
	if err != nil {
		errStatus(ctx, http.StatusUnauthorized, err)
		return
	}

	returnNewPair(ctx, token.UserId)
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

func main() {
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

	tokAuth.AddAudience("jwt_service/api/verify_token")

	r := gin.Default()

	r.POST("/api/auth/login", login)
	r.POST("/api/auth/refresh", refreshToken)
	r.POST("/api/verify_token", verifyToken)

	r.Run()
}
