#!/usr/bin/env bash
# Local WordPress fixture for the wp_* browser helpers.
#
# The browser zone routes everything through Tor by contract, and Tor cannot
# reach a loopback service — so the tests that use this fixture must run with
# TALLOW_ALLOW_DIRECT=1. That opt-in is the operator's call, not a test's, which
# is why the tests are #[ignore]d by default.
#
#   scripts/wordpress_fixture.sh up      # start db + wordpress, install core
#   scripts/wordpress_fixture.sh down    # stop (keeps data)
#   scripts/wordpress_fixture.sh purge   # stop and delete the volume
#
# Prints URL / admin user / admin password on success.
set -euo pipefail

PORT="${WP_PORT:-8099}"
NAME_DB=tallow-wp-db
NAME_WP=tallow-wp
NET=tallow-wp-net
VOL=tallow-wp-data
ADMIN_USER=admin
ADMIN_PASS=Adm1nPass2026

case "${1:-up}" in
  up)
    docker network create "$NET" >/dev/null 2>&1 || true
    docker rm -f "$NAME_WP" "$NAME_DB" >/dev/null 2>&1 || true
    docker run -d --name "$NAME_DB" --network "$NET" \
      -e MARIADB_DATABASE=wordpress -e MARIADB_USER=wp \
      -e MARIADB_PASSWORD=wppass -e MARIADB_ROOT_PASSWORD=rootpass \
      mariadb:11 >/dev/null
    docker run -d --name "$NAME_WP" --network "$NET" -p "127.0.0.1:${PORT}:80" \
      -v "$VOL:/var/www/html" \
      -e WORDPRESS_DB_HOST="$NAME_DB" -e WORDPRESS_DB_USER=wp \
      -e WORDPRESS_DB_PASSWORD=wppass -e WORDPRESS_DB_NAME=wordpress \
      wordpress:6-php8.2-apache >/dev/null

    for _ in $(seq 1 40); do
      docker exec "$NAME_DB" mariadb -uroot -prootpass -e "select 1" >/dev/null 2>&1 && break
      sleep 2
    done

    # WordPress needs its entrypoint to copy core, wait for mariadb and run the
    # installer; on a cold CI runner that is tens of seconds after `docker run`
    # returns. Poll instead of probing once — the first CI run failed here
    # because the single curl landed before the container was serving.
    ready=0
    for _ in $(seq 1 60); do
      if curl -sf -o /dev/null "http://127.0.0.1:${PORT}/wp-login.php"; then
        ready=1
        break
      fi
      sleep 2
    done

    if [ "$ready" -ne 1 ]; then
      echo "wordpress did not answer on 127.0.0.1:${PORT} after 120s" >&2
      docker logs --tail 40 "$NAME_WP" >&2 || true
      exit 1
    fi

    # Install only once: a volume that already has wp-config.php is installed.
    if ! docker run --rm --network "$NET" -v "$VOL:/var/www/html" \
        -e WORDPRESS_DB_HOST="$NAME_DB" -e WORDPRESS_DB_USER=wp \
        -e WORDPRESS_DB_PASSWORD=wppass -e WORDPRESS_DB_NAME=wordpress \
        wordpress:cli wp core is-installed >/dev/null 2>&1; then
      docker run --rm --network "$NET" -v "$VOL:/var/www/html" \
        -e WORDPRESS_DB_HOST="$NAME_DB" -e WORDPRESS_DB_USER=wp \
        -e WORDPRESS_DB_PASSWORD=wppass -e WORDPRESS_DB_NAME=wordpress \
        wordpress:cli wp core install \
          --url="http://127.0.0.1:${PORT}" --title=TallowFixture \
          --admin_user="$ADMIN_USER" --admin_password="$ADMIN_PASS" \
          --admin_email=admin@example.invalid --skip-email >/dev/null
    fi

    echo "url=http://127.0.0.1:${PORT}"
    echo "admin_user=${ADMIN_USER}"
    echo "admin_pass=${ADMIN_PASS}"
    ;;
  down)
    docker stop "$NAME_WP" "$NAME_DB" >/dev/null 2>&1 || true
    echo "stopped (data kept in volume $VOL)"
    ;;
  purge)
    docker rm -f "$NAME_WP" "$NAME_DB" >/dev/null 2>&1 || true
    docker volume rm "$VOL" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    echo "removed containers, volume and network"
    ;;
  *)
    echo "usage: $0 up|down|purge" >&2
    exit 64
    ;;
esac
