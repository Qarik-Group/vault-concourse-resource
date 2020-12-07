#!/bin/bash -e

eval $(safe env --bash)
mkdir -p $(pwd)/tmp

echo -e "\nTesting check\n"
jq -n '{source: {url: "'${VAULT_ADDR}'", token: "'${VAULT_TOKEN}'", paths: ["secret"]}}' \
    | go run ./cmd/check

echo -e "\n\nTesting in\n"
jq -n '{source: {url: "'${VAULT_ADDR}'", token: "'${VAULT_TOKEN}'", paths: ["secret"]}}' \
    | go run ./cmd/in $(pwd)/tmp/in

echo -e "\n\nTesting out\n"

safe set secret/handshake knock=knock
mkdir -p $(pwd)/tmp/out/concourse_input_dir/resource_or_task_dir/secret
jq -n '{ping: "pong"}' > $(pwd)/tmp/out/concourse_input_dir/resource_or_task_dir/secret/handshake
jq -n '{source: {url: "'${VAULT_ADDR}'", token: "'${VAULT_TOKEN}'", paths: ["secret"]}, params: {path: "resource_or_task_dir"}}' \
    | go run ./cmd/out $(pwd)/tmp/out/concourse_input_dir

safe get secret/handshake
rm -r $(pwd)/tmp
