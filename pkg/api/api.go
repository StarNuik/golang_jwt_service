package api

// ? https://datatracker.ietf.org/doc/html/rfc6749#section-5.1

type TokenResponse struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int
	RefreshToken string
}

type TestTokenRequest struct {
	AccessToken string
}
