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
| `SIMPLE_API_SERVER_TLS_CERT_FILE` | (empty) | PEM certificate file. Serving TLS needs it together with the key file. |
| `SIMPLE_API_SERVER_TLS_KEY_FILE` | (empty) | PEM private key file for the certificate above. |

A single entry of either list may span several path segments, written with `/`, as in `admin/users`. The API version is read the same way. A segment must not be empty and must not contain whitespace, control characters, or any of `{`, `}`, `?`, `#`. An invalid value stops the server at startup with an `invalid configuration` message.

### TLS

With both `SIMPLE_API_SERVER_TLS_CERT_FILE` and `SIMPLE_API_SERVER_TLS_KEY_FILE` set, the server serves HTTPS on `SIMPLE_API_SERVER_LISTEN_ADDR` and nothing else; with neither set, it serves plain HTTP there. Setting only one of the two stops the server at startup, as does a key pair that cannot be read or does not match. The negotiated protocol is TLS 1.2 or above, and the certificate chain is whatever the certificate file holds.

The listen address keeps its own default of port `8080`, so a TLS run usually sets it as well, for example to `0.0.0.0:8443`.

A TLS listener also offers HTTP/2 over ALPN, so a client that supports it is served over HTTP/2 and the access log records `HTTP/2.0`. The plain HTTP listener stays on HTTP/1.1.

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

Over TLS, with a self signed certificate. `.gitignore` excludes the `tls/` directory that the examples keep the key pair in:

```sh
mkdir -p tls
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout tls/tls.key -out tls/tls.crt \
  -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
```

Then point the server at it:

```sh
SIMPLE_API_SERVER_LISTEN_ADDR=localhost:8443 \
SIMPLE_API_SERVER_TLS_CERT_FILE=tls/tls.crt \
SIMPLE_API_SERVER_TLS_KEY_FILE=tls/tls.key \
  go run .
curl --cacert tls/tls.crt https://localhost:8443/v1/api
```

### Docker

```sh
docker build -t simple-api-server .
docker run --rm -p 8080:8080 simple-api-server
curl http://localhost:8080/v1/api
```

Over TLS, with a self signed certificate mounted at `/tls`:

```sh
mkdir -p tls
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout tls/tls.key -out tls/tls.crt \
  -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
```

The container runs as uid `65532`, so both files need to stay readable for others:

```sh
chmod 0444 tls/tls.crt tls/tls.key
docker run --rm -p 8443:8443 \
  -v "$PWD/tls:/tls:ro" \
  -e SIMPLE_API_SERVER_LISTEN_ADDR=0.0.0.0:8443 \
  -e SIMPLE_API_SERVER_TLS_CERT_FILE=/tls/tls.crt \
  -e SIMPLE_API_SERVER_TLS_KEY_FILE=/tls/tls.key \
  simple-api-server
curl --cacert tls/tls.crt https://localhost:8443/v1/api
```

### Kubernetes

```sh
kubectl apply -f ./k8s/
kubectl port-forward svc/simple-api-server 8080:8080
curl http://localhost:8080/v1/payment
```

The manifests in `k8s/` serve `payment`, `inventory`, `shipping` and `healthz`, and pull the image from `ghcr.io`.

`k8s/tls/` holds the same endpoints over HTTPS on port `8443`, under the separate name `simple-api-server-tls`. The Pod mounts a `kubernetes.io/tls` secret of that name, which is not part of the manifests. Its certificate needs the service name among its subject alternative names:

```sh
mkdir -p tls
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout tls/tls.key -out tls/tls.crt \
  -subj '/CN=simple-api-server-tls' \
  -addext 'subjectAltName=DNS:simple-api-server-tls,DNS:simple-api-server-tls.default.svc,DNS:localhost,IP:127.0.0.1'
```

Then create the secret and apply the manifests:

```sh
kubectl create secret tls simple-api-server-tls --cert=tls/tls.crt --key=tls/tls.key
kubectl apply -f ./k8s/tls/
kubectl port-forward svc/simple-api-server-tls 8443:8443
curl --cacert tls/tls.crt https://localhost:8443/v1/payment
```
