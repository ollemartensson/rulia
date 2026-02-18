# Troubleshooting

## Podman rootless notes

### macOS

1. Ensure machine exists and is running:

```bash
podman machine init || true
podman machine start
```

2. Verify socket for compose integrations:

```bash
podman system connection list
podman info --format '{{.Host.RemoteSocket.Path}}'
```

3. If Traefik cannot reach provider socket, set compose/docker compatibility envs, or use Podman's docker API compatibility layer.

### Linux

- Ensure user lingering and rootless network setup are healthy.
- Verify `slirp4netns` is available.

## Common issues

### Port collisions

Adjust in `.env`:
- `TRAEFIK_HTTP_PORT`
- `TRAEFIK_DASHBOARD_PORT`
- `REDPANDA_EXTERNAL_PORT`
- `REDPANDA_CONSOLE_PORT`

### Volume permissions

If services cannot write:

```bash
chmod -R u+rwX demo/volumes
```

### Redpanda not healthy yet

Wait and tail logs:

```bash
podman-compose --env-file .env logs -f redpanda
```

### Workflow run missing after `make seed`

1. Check bridge logs:

```bash
podman-compose --env-file .env logs --tail=200 mf-outbox-bridge-julia
```

2. Confirm outbox file was moved to processed directory:

```bash
ls -la demo/volumes/tk4/processed
```

3. Check workflow host logs:

```bash
podman-compose --env-file .env logs --tail=200 workflow-host-julia
```
