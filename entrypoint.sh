#!/bin/sh
# The box's entrypoint.
#
# Two phases, in this order:
#   1. init — mint or load the box's identity, sign the subscriber
#      allowlist, write /data/client.link. Idempotent: a restart must not
#      re-mint the keys, or the customer's artefact would stop matching.
#   2. run  — build the control plane from the chain spec and serve.
#
# The customer's installer reads /data/client.link once, right after
# `docker compose up -d`, so the artefact has to exist BEFORE the listeners
# are bound. That is why init is a separate phase and runs first.
set -eu

DATA_DIR="${M1R4G3_DATA_DIR:-/data}"
ENV_FILE="${M1R4G3_ENV_FILE:-/opt/m1r4g3/server.env}"

mkdir -p "$DATA_DIR" /run/mirage

# A bind mount whose source does not exist becomes a DIRECTORY in the
# container. That is not a config file, and reading it must not be fatal:
# the box still starts with its defaults.
if [ -d "$ENV_FILE" ]; then
  echo "m1r4g3: $ENV_FILE is a directory, not a config file; starting with defaults" >&2
  ENV_FILE=/dev/null
elif [ ! -f "$ENV_FILE" ]; then
  echo "m1r4g3: $ENV_FILE is missing; starting with defaults" >&2
  ENV_FILE=/dev/null
fi

case "${1:-run}" in
  init)
    exec m1r4g3-server init --dir "$DATA_DIR" --env "$ENV_FILE"
    ;;
  run)
    m1r4g3-server init --dir "$DATA_DIR" --env "$ENV_FILE"
    exec m1r4g3-server run --dir "$DATA_DIR" --env "$ENV_FILE"
    ;;
  *)
    exec m1r4g3-server "$@" --dir "$DATA_DIR" --env "$ENV_FILE"
    ;;
esac
