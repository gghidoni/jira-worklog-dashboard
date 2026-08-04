---
name: jira-worklog-deploy
description: Access, inspect, publish, verify, and troubleshoot the Jira Worklog dashboard stage server over SSH. Use for Jira Worklog server discovery, Docker/Compose status checks, commit and push workflows, stage deploys, container rebuilds, exposed-port checks, Nginx publishing checks, healthchecks, or deployment incident diagnosis for this repository.
---

# Jira Worklog Deploy

Deploy the Jira Worklog dashboard predictably while protecting runtime files and requiring explicit authorization before server mutations.

## Connection

Use:

```bash
ssh -p 2222 -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes ubuntu@185.216.64.97
```

Add `-o StrictHostKeyChecking=accept-new` only when the host key must be accepted on first access. Never print, copy, or inspect the private key.

## Safety gate

Before changing the server:

1. Run only readonly discovery commands.
2. Identify the working copy, stack, containers, exposed ports, and publishing method.
3. Report the planned mutation.
4. Continue only after the user explicitly authorizes deploy or another server modification. A direct request such as “fai il deploy” counts as authorization for the described deploy workflow after discovery.

Without authorization, do not pull, edit files, build images, recreate or stop containers, restart services, or change networking. Never use `docker compose down`. Do not perform rollback or cleanup unless separately authorized.

## Readonly discovery

Start with:

```bash
ssh -p 2222 -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes ubuntu@185.216.64.97 'hostname
pwd
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
docker compose ls
ss -lntp
find /home/ubuntu -maxdepth 3 -type f \( -name docker-compose.yml -o -name docker-compose.yaml -o -name compose.yml -o -name compose.yaml -o -name deploy.sh \) -print'
```

Then inspect the application without reading secrets:

```bash
ssh -p 2222 -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes ubuntu@185.216.64.97 'cd /home/ubuntu/jiraworklog
git status --short
git branch --show-current
git remote -v
git log -1 --oneline
docker compose -p jiraworklog -f deploy/stage/docker-compose.yml ps
sed -n "1,240p" deploy/stage/docker-compose.yml
sed -n "1,220p" deploy/stage/nginx.conf'
```

Known stage layout:

- Working copy: `/home/ubuntu/jiraworklog`
- Compose project: `jiraworklog`
- Compose file: `deploy/stage/docker-compose.yml`
- App container/service: `jiraworklog-app-1` / `app`, internal port `8080`
- Proxy container/service: `jiraworklog-nginx-1` / `nginx`
- Published host port: `8082 -> nginx:80`
- Runtime-only files: `deploy/stage/app.env` and `deploy/stage/htpasswd`
- Canonical helper: `scripts/deploy-stage.sh`, which requires `DEPLOY_BASIC_AUTH_PASS` for its public healthcheck

Treat the two runtime-only files as expected untracked files. Never add, modify, delete, display, or commit them. Stop and ask if other unexpected server changes would prevent a fast-forward pull.

## Prepare local changes

When commit and push are requested:

1. Run `go test ./...`, `go build ./...`, and `git diff --check`.
2. Review `git status --short` and preserve unrelated or user-owned files such as `outputs/`.
3. Stage only the intended files explicitly.
4. Commit with a focused message and push the current `main` branch to `origin`.
5. Record the commit hash that must be deployed.

## Deploy after authorization

Prefer the repository helper only when `DEPLOY_BASIC_AUTH_PASS` is already supplied through an approved secure mechanism. Never expose the password in logs or output.

Otherwise run the equivalent deployment directly:

```bash
ssh -p 2222 -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes ubuntu@185.216.64.97 'cd /home/ubuntu/jiraworklog
git pull --ff-only
HOST_PORT=8082 docker compose -p jiraworklog -f deploy/stage/docker-compose.yml up -d --build
docker compose -p jiraworklog -f deploy/stage/docker-compose.yml ps
git rev-parse --short HEAD'
```

This should recreate the app only when required and leave Nginx running. Do not separately restart Nginx unless the requested change requires it and the user authorizes it.

## Verify

Verify the application from the Compose network:

```bash
ssh -p 2222 -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes ubuntu@185.216.64.97 'docker exec jiraworklog-nginx-1 curl -fsS --max-time 10 http://app:8080/healthz
curl -sS -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8082/healthz
docker logs --tail 30 jiraworklog-app-1'
```

Expected results:

- Internal healthcheck returns `ok`.
- Public local endpoint returns `401` because Nginx Basic Auth is active.
- App logs show it listening on `:8080` without startup errors.
- Server `HEAD` matches the pushed commit.

Do not use the app container bridge IP for healthchecks; direct host-to-bridge access can time out on this VM.

## Report completion

Report the deployed commit, pull/build result, container status, internal healthcheck, expected public `401`, and any warnings. Mention that `app.env` and `htpasswd` remained untouched when relevant.
