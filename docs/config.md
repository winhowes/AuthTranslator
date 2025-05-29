# `config.yaml` Basics

Each integration block tells AuthTranslator where to forward requests and how to authenticate both incoming and outgoing traffic.

```yaml
integrations:
  slack:
    destination: https://slack.com
    incoming_auth:
      - type: token
        params:
          header: X-Auth
          secrets:
            - vault:/old/token
            - vault:/new/token
    outgoing_auth:
      type: bearer_static
      params:
        header: Authorization
        secrets:
          - env:APP_TOKEN_1
          - env:APP_TOKEN_2
    transport:
      timeout: 10s
    rate_limit:
      window: 1m
      requests: 800
```

The integration name (`slack` above) is referenced by the allowlist. Incoming plugins run in order until one succeeds, producing the caller ID. Outgoing plugins modify each request before forwarding it to the `destination` URL.

## Multiple secrets

Both incoming and outgoing plugin configs accept a list of `secrets:`. Incoming plugins try each secret until one matches, ignoring errors so callers aren’t blocked by a bad entry. Outgoing plugins pick one secret at random for every request, spreading traffic evenly across all configured secrets.

This allows for seamless rotation during credential changes and can help distribute load when upstream services rate-limit by token.
