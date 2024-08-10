#! /bin/bash

curl -v localhost:8080/api/verify_token \
    --data "{\"AccessToken\":\"$1\"}" \
    --header "Content-Type: application/json" \

# $2a$10$rDqSDB.NibTlXmYMGQpADuFvvslAsq.TIzH4jKdYDQ0/zOK24ZgD.