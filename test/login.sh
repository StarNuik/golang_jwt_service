#! /bin/bash

# 12345678-1234-1234-1234-123456789abc
# 616032ea-a023-4f91-99f4-704f00e1e03d
curl -v localhost:8080/api/auth/new \
    --data "{\"UserId\":\"$1\"}" \
    --header "Content-Type: application/json" \