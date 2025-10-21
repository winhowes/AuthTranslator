# Running with Docker Compose

This guide shows how to spin up **AuthTranslator** together with a Redis instance (optional) using a single `docker‑compose.yml` file. It’s perfect for local integration tests or a small‑scale staging environment.

> **Prerequisites**  Docker ≥ 24 and Compose v2 (`docker compose …`).

---

## 1  Example `docker‑compose.yml`

A ready-made Compose file lives at [`../examples/docker-compose.yml`](../examples/docker-compose.yml).

```yaml
version: "3.9"
services:
  authtranslator:
    image: ghcr.io/winhowes/authtranslator:latest
    container_name: authtranslator
    ports:
      - "8080:8080"               # → host http://localhost:8080
    environment:
      # Secret URIs resolve env: …
      SLACK_TOKEN: "xoxb‑REPLACE"
      # Optional: enable Redis-backed rate limits
    volumes:
      - ./conf:/conf:ro            # bind‑mount configs for hot reload
    command: |
      -config /conf/config.yaml \
      -allowlist /conf/allowlist.yaml \
      -denylist /conf/denylist.yaml \
      -redis-addr redis://redis:6379/0 \
      -watch                       # reload on file change
    depends_on:
      - redis

  redis:
    image: redis:7-alpine
    container_name: redis
    restart: unless-stopped
    expose:
      - "6379"
    volumes:
      - redis-data:/data

volumes:
  redis-data:
```

**Folder layout** (repo root):

```
conf/
  ├── config.yaml      # integrations
  ├── allowlist.yaml   # caller permissions
  └── denylist.yaml    # hard blocks
docker-compose.yml
```

The bind mount makes it easy to tweak YAML in your editor and have the container reload automatically.

---

## 2  Bringing the stack up

```bash
# Start in detached mode
docker compose up -d

# View logs
docker compose logs -f authtranslator
```

Navigate to:

* Health: [http://localhost:8080/\_at\_internal/healthz](http://localhost:8080/_at_internal/healthz)
* Metrics: [http://localhost:8080/\_at\_internal/metrics](http://localhost:8080/_at_internal/metrics)

Docker will keep hitting the health URL above using the image's `HEALTHCHECK`. The `authtranslator` service shows as `healthy` once the endpoint responds with `200 OK`.

---

## 3  Customising

| Task                    | How                                                                                           |
| ----------------------- | --------------------------------------------------------------------------------------------- |
| Change the exposed port | Edit `ports:` → `- "9000:8080"`.                                                              |
| Disable Redis           | Remove the `redis` service and drop the `-redis-addr` flag. The proxy falls back to in‑memory limits. |
| Add extra env secrets   | Append under `environment:` (`STRIPE_KEY=…`).                                                 |
| Mount PEM certificates  | Add another entry under `volumes:` and reference with `file:/` secret URIs.                   |

---

## 4  Tearing down

```bash
docker compose down -v   # removes containers and named volume
```

---

*Last updated*: 2024-05-01
