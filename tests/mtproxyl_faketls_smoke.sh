#!/usr/bin/env bash
# Offline runtime test of a real FakeTLS handshake through original/patched nginx.
# Public Docker images and Go modules are fetched during setup/build only. Runtime
# nginx, mtg, and clients share a `--network none` namespace without egress.
# The only secret and certificate are synthetic. No Telegram account is used.
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
nginx_image='nginx:1.27.5@sha256:6784fb0834aa7dbbe12e3d7471e69c290df3e6ba810dc38b34ae33d3c1c05f7d'
mtg_image='nineseconds/mtg@sha256:c082586a19886e4822f92aa8c1949a771df3519053d64b1b5505a9a280a3929d'
go_image='golang:1.25.3@sha256:6d4e5e74f47db00f7f24da5f53c1b4198ae46862a47395e30477365458347bf2'
python_image='python@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a'
work=$(mktemp -d "${TMPDIR:-/tmp}/dohdns-faketls.XXXXXXXX")
nginx_id='' mtg_id=''
cleanup() {
  if [[ -n "$mtg_id" ]]; then docker stop --timeout 2 "$mtg_id" >/dev/null 2>&1 || :; fi
  if [[ -n "$nginx_id" ]]; then docker stop --timeout 2 "$nginx_id" >/dev/null 2>&1 || :; fi
  rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

# Image pulls and public Go dependency download are the only external network use.
for image in "$nginx_image" "$mtg_image" "$go_image" "$python_image"; do
  if ! docker image inspect "$image" >/dev/null 2>&1; then docker pull "$image"; fi
done
cp "$repo"/tests/fixtures/faketls-client/{main.go,go.mod,go.sum} "$work/"
mkdir "$work/cert"
docker run --rm --pull never --user "$(id -u):$(id -g)" -e HOME=/work -e GOCACHE=/work/.go-build -e GOPATH=/work/.go -v "$work:/work" -w /work "$go_image" \
  sh -c 'CGO_ENABLED=0 go build -mod=readonly -o client main.go'
docker run --rm --pull never --network none --user "$(id -u):$(id -g)" -v "$work:/work" -w /work "$go_image" \
  openssl req -x509 -newkey rsa:2048 -nodes -keyout cert/privkey.pem -out cert/fullchain.pem \
  -days 1 -subj /CN=dns.example.com >/dev/null 2>&1

# Render with the project's real patch function in an offline Python container.
python_common=(--rm --pull never --network none --user "$(id -u):$(id -g)" -v "$repo:/repo:ro" -v "$work:/work")
docker run "${python_common[@]}" "$python_image" python -B /repo/tests/fixtures/faketls-client/fixture.py prepare
docker run "${python_common[@]}" "$python_image" python -B /repo/tests/fixtures/faketls-client/fixture.py verify
# Validate the exact patched file with the same image used to run nginx.
docker run --rm --pull never --network none -v "$work:/work:ro" \
  -v "$work/includes:/etc/adguardhome-doh:ro" --entrypoint nginx "$nginx_image" -t -c /work/runtime.conf

run_case() {
  local config=$1 mode
  echo "config: $config"
  nginx_id=$(docker run -d --rm --pull never --network none --log-driver none \
    -v "$work:/work:ro" -v "$work/includes:/etc/adguardhome-doh:ro" --entrypoint nginx \
    "$nginx_image" -c "/work/$config" -g 'daemon off;')
  mode=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$nginx_id")
  [[ "$mode" == none ]] || { echo 'nginx network is not isolated' >&2; exit 1; }
  mtg_id=$(docker run -d --rm --pull never --network "container:$nginx_id" --log-driver none \
    -v "$work/mtg.toml:/config/config.toml:ro" "$mtg_image")
  mode=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$mtg_id")
  [[ "$mode" == "container:$nginx_id" ]] || { echo 'mtg network is not isolated' >&2; exit 1; }
  docker run --rm --pull never --network "container:$nginx_id" "$python_image" python -c \
    'import socket,time; end=time.monotonic()+10
for port in (443,15443):
 while True:
  try:
   s=socket.create_connection(("127.0.0.1",port),timeout=1); s.close(); break
  except OSError:
   if time.monotonic()>end: raise
   time.sleep(.1)'
  for mode in correct tamper wrong; do
    docker run --rm --pull never --network "container:$nginx_id" -v "$work:/work:ro" \
      --entrypoint /work/client "$go_image" "$mode"
  done
  docker run --rm --pull never --network "container:$nginx_id" -v "$repo:/repo:ro" "$python_image" \
    python -B /repo/tests/fixtures/faketls-client/fixture.py probe 443
  docker stop --timeout 2 "$mtg_id" >/dev/null
  mtg_id=''
  docker stop --timeout 2 "$nginx_id" >/dev/null
  nginx_id=''
}
run_case vendor.conf
run_case runtime.conf
docker run "${python_common[@]}" "$python_image" python -B /repo/tests/fixtures/faketls-client/fixture.py verify
