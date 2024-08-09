package main

import (
	"context"
	"fmt"
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
	tokens  = auth.NewTokenAuthority(jwtKey, jwtKey)
	rtModel *model.RefreshTokens
)

func newToken(ctx *gin.Context) {
	var req schema.NewTokenRequest

	err := ctx.BindJSON(&req)
	if err != nil {
		ctx.Status(http.StatusBadRequest)
		return
	}

	//todo: test that such a user exists

	userId, err := uuid.FromString(req.UserId)
	if err != nil {
		ctx.Status(http.StatusBadRequest)
		return
	}

	access, err := tokens.NewAccess(userId)
	if err != nil {
		ctx.Status(http.StatusInternalServerError)
		return
	}

	refresh, err := tokens.NewRefresh()
	if err != nil {
		ctx.Status(http.StatusInternalServerError)
		return
	}

	refreshHash, err := tokens.HashRefresh(refresh)
	if err != nil {
		ctx.Status(http.StatusInternalServerError)
		return
	}

	rt := model.RefreshToken{
		Hash:      refreshHash,
		UserId:    userId,
		ExpiresAt: tokens.RefreshExpiresAt(),
	}
	err = rtModel.InsertToken(context.TODO(), rt)
	if err != nil {
		ctx.Status(http.StatusInternalServerError)
		return
	}

	res := schema.TokenPairResponse{}
	res.AccessToken = access
	res.ExpiresIn = int(tokens.AccessExpiresIn().Seconds())
	res.RefreshToken = refresh

	// todo: "MUST include the HTTP "Cache-Control" response header field [RFC2616] with a value of "no-store" in any response containing tokens, credentials, or other sensitive information..."
	// todo: (MUST include) "the "Pragma" response header field [RFC2616] with a value of "no-cache"."
	ctx.IndentedJSON(http.StatusOK, res)
}

// ? https://stackoverflow.com/a/67386228
// ? https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation
func refreshToken(ctx *gin.Context) {
	// var req schema.RefreshTokenRequest

	// err := ctx.BindJSON(&req)
	// if err != nil {
	// 	ctx.Status(http.StatusBadRequest)
	// 	return
	// }

	// hash, err := tokens.HashRefresh(req.RefreshToken)

	// token, err := rtModel.RetrieveToken(context.TODO(), hash)
	// if err != nil {
	// 	// todo: better error response, ref [RFC6750]
	// 	ctx.Status(http.StatusBadRequest)
	// 	return
	// }

	// if token.ExpiresAt.Before(time.Now().UTC()) {
	// 	// todo: better error response, ref [RFC6750]
	// 	ctx.Status(http.StatusUnauthorized)
	// 	return
	// }

	// err = rtModel.InvalidateToken(context.TODO(), hash)

	ctx.Status(http.StatusNotFound)
}

func verifyToken(ctx *gin.Context) {
	var req schema.VerifyTokenRequest

	err := ctx.BindJSON(&req)
	if err != nil {
		ctx.Status(http.StatusBadRequest)
		return
	}

	fmt.Println(req)

	userId, err := tokens.ParseAccess(req.AccessToken, "jwt_service/api/verify_token")
	if err != nil {
		ctx.Status(http.StatusUnauthorized)
		return
	}

	res := schema.VerifyTokenResponse{
		UserId: userId.String(),
	}

	ctx.JSON(http.StatusOK, res)
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

	rtModel = model.NewRefreshTokens(pool)

	tokens.AddAudience("jwt_service/api/verify_token")

	r := gin.Default()

	r.POST("/api/auth/new", newToken)
	r.POST("/api/auth/refresh", refreshToken)
	r.POST("/api/verify_token", verifyToken)

	r.Run()
}
