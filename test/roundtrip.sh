#! /bin/bash

tmp=$(mktemp)

status=$(curl -s \
    -w "%{http_code}" \
    -o $tmp \
    localhost:8080/api/auth/login \
    --header "Content-Type: application/json" \
    --data "{\"UserId\":\"$1\"}" \
)
if [ $status != "200" ]
then
    echo $status
    rm $tmp
    exit 1
fi

access=$(cat $tmp | jq .AccessToken)
refresh=$(cat $tmp | jq .RefreshToken)
#? https://gist.github.com/angelo-v/e0208a18d455e2e6ea3c40ad637aac53?permalink_comment_id=3150988#gistcomment-3150988
printf "access:\n"
jq -R 'split(".") | .[1] | @base64d | fromjson' <<< $access
printf "refresh: %s\n" $refresh

for ((;;))
do
    status=$(curl -sw "%{http_code}" localhost:8080/api/verify_token \
        --header "Content-Type: application/json" \
        --data "{\"AccessToken\":$access}" \
    )
    printf "%s " $status

    sleep 1

    if [ $status != "200" ]
    then
        printf "\n"
        status=$(curl -s \
            -w "%{http_code}" \
            -o $tmp \
            localhost:8080/api/auth/refresh \
            --header "Content-Type: application/json" \
            --data "{\"RefreshToken\":$refresh}" \
        )
        if [ $status != "200" ]
        then
            echo $status
            rm $tmp
            exit 1
        fi

        access=$(cat $tmp | jq .AccessToken)
        refresh=$(cat $tmp | jq .RefreshToken)
        #? https://gist.github.com/angelo-v/e0208a18d455e2e6ea3c40ad637aac53?permalink_comment_id=3150988#gistcomment-3150988
        printf "access:\n"
        jq -R 'split(".") | .[1] | @base64d | fromjson' <<< $access
        printf "refresh: %s\n" $refresh

        sleep 1
    fi
done

trap 'rm $tmp'