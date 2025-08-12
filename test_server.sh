#!/usr/bin/env bash

set -eEuo pipefail

cd "$(dirname "$0")"

{
    make && ./server_app
} &

pid=$!
trap 'kill $pid' EXIT TERM INT
trap 'exit 0' EXIT

call_svr() {
    local path="$1"
    shift
    curl "$@" "http://localhost:1234/$path"
}

call_svr_get() {
    call_svr "$@" -X GET
}
call_svr_post() {
    call_svr "$@" -X POST
}

get_status() {
    call_svr_get "status"
}

set_master_key(){
    call_svr_post "set-masterkey" --data "$1"
}

main() {
    status_json="$(get_status)"
    if [[ "$(jq ".init_require" <<<"$status_json")" == "true" ]]; then
        local master_key
        printf "%s" "Please enter the master key to initialize the server: "
        read -r master_key
        if [[ -z "$master_key" ]]; then
            echo "Master key cannot be empty."
            exit 1
        fi

        # set_master_key "$master_key"
    fi
}
