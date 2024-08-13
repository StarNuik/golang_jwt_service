package schema

type NewTokenRequest struct {
	UserId string
}

// https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
type TokenPairResponse struct {
	AccessToken  string
	ExpiresIn    int
	RefreshToken string
}

type RefreshTokenRequest struct {
	RefreshToken string
}

type VerifyTokenRequest struct {
	AccessToken string
}

type VerifyTokenResponse struct {
	UserId string
}
