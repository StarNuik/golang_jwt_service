package api

// ? https://datatracker.ietf.org/doc/html/rfc6749#section-5.1

type tokenResponse struct {
	AccessToken  string
	ExpiresIn    int
	RefreshToken string
}

type NewTokenRequest struct {
	UserId string
}

type NewTokenResponse struct {
	tokenResponse
}

type RefreshTokenRequest struct {
	RefreshToken string
}

type RefreshTokenResponse struct {
	tokenResponse
}

type VerifyTokenRequest struct {
	AccessToken string
}

type VerifyTokenResponse struct {
	UserId string
}
