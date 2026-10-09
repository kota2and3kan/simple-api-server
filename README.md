# Simple API Server

Simple API Server for some testing.

Each configured endpoint returns `{"API":"<path>","status":<code>}` as JSON, with `<code>` as the HTTP status code of the response itself. A YAML config file replaces that body with any JSON of your own.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `SIMPLE_API_SERVER_LISTEN_ADDR` | `localhost:8080` | Address to listen on. The container image sets `0.0.0.0:8080`. A value without a port, such as `0.0.0.0` or `0.0.0.0:`, listens on port `8080`. |
| `SIMPLE_API_SERVER_PATH_LIST` | `api` | Endpoints, separated by commas. Each one is a path, optionally followed by `:` and the status code it answers with. |
| `SIMPLE_API_SERVER_API_CONFIG_FILE` | (empty) | YAML file defining the endpoints, including their response bodies. It replaces `SIMPLE_API_SERVER_PATH_LIST`, which must be left unset alongside it. |
| `SIMPLE_API_SERVER_LOG_EXCLUDE_PATH_LIST` | (empty) | Paths to keep out of the access log, separated by commas. Paths only, with no status code. |
| `SIMPLE_API_SERVER_TLS_CERT_FILE` | (empty) | PEM certificate file. Serving TLS needs it together with the key file. |
| `SIMPLE_API_SERVER_TLS_KEY_FILE` | (empty) | PEM private key file for the certificate above. |

A single entry of either list may span several path segments, written with `/`, as in `admin/users`. An endpoint that carries a version is written the same way, as in `v1/api`. A segment must not be empty and must not contain whitespace, control characters, or any of `{`, `}`, `?`, `#`, `:`. An invalid value stops the server at startup with an `invalid configuration` message.

### Status codes

An entry of `SIMPLE_API_SERVER_PATH_LIST` answers with the status code written after its `:`, as in `v1/bar:404`. An entry without one answers with `200`. The code must be an integer between `200` and `599`; anything else stops the server at startup.

A path listed more than once is registered once. Where the repeated entries disagree on the status code, as in `healthz,healthz:503`, the server stops at startup rather than pick one of them.

```sh
SIMPLE_API_SERVER_PATH_LIST='v1/foo:200,v1/bar:404,v1/baz:503' go run .
curl -i http://localhost:8080/v1/bar
# HTTP/1.1 404 Not Found
# {"API":"v1/bar","status":404}
```

A `204` or a `304` endpoint sends no body and no `Content-Type`, since those responses carry none.

### Response bodies

`SIMPLE_API_SERVER_API_CONFIG_FILE` points at a YAML file that defines the endpoints together with the JSON each one answers with. It holds a single YAML document with an `apis` list, and every entry carries a `path` plus an optional `statusCode` and `respBody`:

```yaml
apis:
  - path: v1/foo
    statusCode: 200
    respBody: {"k1": "v1", "k2": {"k3": "v3"}}
  - path: v1/bar
    statusCode: 404
    respBody: |
      {
        "k1": "v1",
        "k2": {
          "k3": "v3"
        }
      }
  - path: v1/baz
    respBody:
      k4: v4
      k5: [1, 2.5, true, null]
  - path: healthz
```

```sh
SIMPLE_API_SERVER_API_CONFIG_FILE=api.yaml go run .
curl -i http://localhost:8080/v1/bar
# HTTP/1.1 404 Not Found
# {"k1":"v1","k2":{"k3":"v3"}}
```

`respBody` is written either as JSON or as plain YAML, and both forms above are accepted. Written as a string, as the block scalar with `|` is, its text is parsed as a JSON document. Written as a YAML mapping or sequence, which the one line `{"k1": "v1"}` also is, it is converted to JSON and keeps the key order of the file. Either way the body is sent as compact JSON with a trailing newline, under `Content-Type: application/json`.

An entry without a `respBody`, like `healthz` above, answers with the default `{"API":"<path>","status":<code>}`. An entry without a `statusCode` answers with `200`.

A whole body is reused with a YAML anchor and alias, as in `respBody: *base`. The merge key `<<`, which would fold one mapping into another, is rejected rather than served as a literal `<<` key.

The file is read once at startup, and anything it gets wrong stops the server there: a path that is invalid or listed twice, a status code outside `200` to `599`, a `respBody` that is not valid JSON, a duplicate key inside one written as YAML, a `respBody` on a `204` or `304` entry, an unknown field, or a second YAML document. A body written as YAML is also rejected where aliases nest it deeper than 100 levels or expand it beyond 10 MiB, so that a runaway alias stops the server with a message rather than exhausting its memory. `SIMPLE_API_SERVER_PATH_LIST` set alongside the file stops the server as well, rather than one of the two being ignored.

### TLS

With both `SIMPLE_API_SERVER_TLS_CERT_FILE` and `SIMPLE_API_SERVER_TLS_KEY_FILE` set, the server serves HTTPS on `SIMPLE_API_SERVER_LISTEN_ADDR` and nothing else; with neither set, it serves plain HTTP there. Setting only one of the two stops the server at startup, as does a key pair that cannot be read or does not match. The negotiated protocol is TLS 1.2 or above, and the certificate chain is whatever the certificate file holds.

The listen address keeps its own default of port `8080`, so a TLS run usually sets it as well, for example to `0.0.0.0:8443`.

A TLS listener also offers HTTP/2 over ALPN, so a client that supports it is served over HTTP/2 and the access log records `HTTP/2.0`. The plain HTTP listener stays on HTTP/1.1.

## Usage

### Local Run

```sh
go run .
curl http://localhost:8080/api
```

Several endpoints at once:

```sh
SIMPLE_API_SERVER_PATH_LIST='api,admin/users' go run .
# /api and /admin/users
```

A version lives in the path itself:

```sh
SIMPLE_API_SERVER_PATH_LIST='v1/api,v2/api' go run .
# /v1/api and /v2/api
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
curl --cacert tls/tls.crt https://localhost:8443/api
```

### Docker

```sh
docker build -t simple-api-server .
docker run --rm -p 8080:8080 simple-api-server
curl http://localhost:8080/api
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
curl --cacert tls/tls.crt https://localhost:8443/api
```

### Kubernetes

```sh
kubectl apply -f ./k8s/
kubectl port-forward svc/simple-api-server 8080:8080
curl http://localhost:8080/payment
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
curl --cacert tls/tls.crt https://localhost:8443/payment
```
