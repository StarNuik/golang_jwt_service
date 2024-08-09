#! /bin/bash

# 12345678-1234-1234-1234-123456789abc
curl -v localhost:8080/api/auth/new \
    --data "{\"UserId\":\"12345678-1234-1234-1234-123456789abc\"}" \
    --header "Content-Type: application/json" \