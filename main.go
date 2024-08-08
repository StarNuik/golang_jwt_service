package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/joho/godotenv/autoload"
	"github.com/starnuik/golang_jwt_service/pkg/api"
)

var (
	jwtKey      = os.Getenv("JWT_KEY")
	jwtDuration = 60 * time.Second
)

func jwtKeyFunc(*jwt.Token) (interface{}, error) {
	return []byte(jwtKey), nil
}

func newToken(ctx *gin.Context) {

	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(jwtDuration)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	signed, _ := token.SignedString([]byte(jwtKey))

	res := api.TokenResponse{}
	res.AccessToken = signed
	res.TokenType = "example"
	res.ExpiresIn = int(jwtDuration.Seconds())
	res.RefreshToken = "nil"

	// todo: "MUST include the HTTP "Cache-Control" response header field [RFC2616] with a value of "no-store" in any response containing tokens, credentials, or other sensitive information..."
	// todo: (MUST include) "the "Pragma" response header field [RFC2616] with a value of "no-cache"."
	ctx.IndentedJSON(http.StatusOK, res)
}

func refreshToken(ctx *gin.Context) {
	ctx.Status(http.StatusNotFound)
}

func verifyToken(ctx *gin.Context) {
	var req api.TestTokenRequest

	err := ctx.BindJSON(&req)
	if err != nil {
		ctx.Status(http.StatusBadRequest)
		return
	}

	fmt.Println(req)

	signed := req.AccessToken
	token, err := jwt.Parse(signed, jwtKeyFunc, jwt.WithValidMethods([]string{"HS512"}))

	if err == nil && token.Valid {
		ctx.Status(http.StatusOK)
		return
	}

	ctx.Status(http.StatusUnauthorized)
}

func main() {
	fmt.Println("Hello, Go!")

	r := gin.Default()

	r.GET("/api/auth/new", newToken)
	r.POST("/api/auth/refresh", refreshToken)
	r.POST("/api/verify_token", verifyToken)

	r.Run()
}
