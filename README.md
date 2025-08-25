# Stack Starter (Hot Reload, 4xxx ports)

Dev setup with hot reload across all services. External ports are on 4xxx.

- Client: http://localhost:4173
- Relay:  http://localhost:4001
- Gateway: http://localhost:4002
- Target: http://localhost:4003

## Run
```bash
docker compose up --build
```

## Notes
- `npm install` used in Dockerfiles to avoid lockfile requirement.
- Bind mounts for live editing; anonymous volume for `/app/node_modules` to preserve container deps.
