# Simple API Server

Simple API Server for some testing.

Each configured endpoint returns `{"API":"<path>","Version":"<api version>"}` as JSON.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `SIMPLE_API_SERVER_LISTEN_ADDR` | `localhost:8080` | Address to listen on. The container image sets `0.0.0.0:8080`. A value without a port, such as `0.0.0.0` or `0.0.0.0:`, listens on port `8080`. |
| `SIMPLE_API_SERVER_API_VERSION` | `v1` | First segment of every endpoint path. |
| `SIMPLE_API_SERVER_PATH_LIST` | `api` | Endpoint paths, separated by commas. |
| `SIMPLE_API_SERVER_LOG_EXCLUDE_PATH_LIST` | (empty) | Paths to keep out of the access log, separated by commas. |

A single entry of either list may span several path segments, written with `/`, as in `admin/users`. The API version is read the same way. A segment must not be empty and must not contain whitespace, control characters, or any of `{`, `}`, `?`, `#`. An invalid value stops the server at startup with an `invalid configuration` message.

## Usage

### Local Run

```sh
go run .
curl http://localhost:8080/v1/api
```

Several endpoints at once:

```sh
SIMPLE_API_SERVER_PATH_LIST='api,admin/users' go run .
# /v1/api and /v1/admin/users
```

### Docker

```sh
docker build -t simple-api-server .
docker run --rm -p 8080:8080 simple-api-server
curl http://localhost:8080/v1/api
```

### Kubernetes

```sh
kubectl apply -f ./k8s/
kubectl port-forward svc/simple-api-server 8080:8080
curl http://localhost:8080/v1/payment
```

The manifests in `k8s/` serve `payment`, `inventory`, `shipping` and `healthz`, and pull the image from `ghcr.io`.
