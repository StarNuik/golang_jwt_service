# Jwt Auth Service

## Deployment
```
git clone https://github.com/StarNuik/golang_jwt_service.git
cd golang_jwt_service
mv example.env .env
docker-compose pull
DOCKER_BUILDKIT=1 docker-compose build
docker-compose up (-d)
go test ./... -count 1 (-v)
```

## Api
`POST /api/auth/login`: login, accepts a user's uuid, returns an access-refresh token pair<br>
`POST /api/auth/refresh`: regenerate auth tokens, accepts a refresh token, returns a new access-refresh pair<br>
`POST /api/verify_token`: protected endpoint, accepts an access token, returns a status code<br>

## Service components
* pkg/auth - access & refresh token generation, parsing, validation
* pkg/email - mail sending & templates
* pkg/model - database interactions and struct-s
* pkg/schema - Json Api struct-s

## Containers
* jwt-service - authorization service
* PostgreSql - database
* pgmigrate - database migrations
* smtp4dev - mock mail server