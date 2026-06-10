#!/usr/bin/env bash

set -euo pipefail

expected_root_name="jiraworklog"
project_name="jiraworklog"
compose_file="deploy/stage/docker-compose.yml"

if ! command -v git >/dev/null 2>&1; then
  echo "git not found" >&2
  exit 1
fi

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "${repo_root}" ]]; then
  echo "run this script from inside the ${expected_root_name} git working copy" >&2
  exit 1
fi

repo_name="$(basename "${repo_root}")"
if [[ "${repo_name}" != "${expected_root_name}" ]]; then
  echo "refusing to deploy from ${repo_root}; expected repo directory name ${expected_root_name}" >&2
  exit 1
fi

if [[ ! -f "${repo_root}/${compose_file}" ]]; then
  echo "missing compose file: ${repo_root}/${compose_file}" >&2
  exit 1
fi

if [[ ! -f "${repo_root}/deploy/stage/app.env" ]]; then
  echo "missing runtime env file: ${repo_root}/deploy/stage/app.env" >&2
  exit 1
fi

if [[ ! -f "${repo_root}/deploy/stage/htpasswd" ]]; then
  echo "missing basic auth file: ${repo_root}/deploy/stage/htpasswd" >&2
  exit 1
fi

cd "${repo_root}"

echo "== git pull =="
git pull --ff-only

echo
echo "== docker compose up =="
HOST_PORT=8082 docker compose -p "${project_name}" -f "${compose_file}" up -d --build

echo
echo "== docker ps =="
docker compose -p "${project_name}" -f "${compose_file}" ps

echo
echo "== healthcheck =="
curl -fsS --max-time 10 -u "$(cut -d: -f1 deploy/stage/htpasswd):${DEPLOY_BASIC_AUTH_PASS:?set DEPLOY_BASIC_AUTH_PASS before running deploy}" \
  http://127.0.0.1:8082/healthz
