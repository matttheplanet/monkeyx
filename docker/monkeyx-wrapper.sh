#!/bin/bash
# MonkeyX CLI wrapper — runs monkeyx inside Docker, behaves like a native command.
# Install: copy to /usr/local/bin/monkeyx (or run docker/install-wrapper.sh)

set -euo pipefail

IMAGE="${MONKEYX_IMAGE:-monkeyx:latest}"

# Resolve paths — we mount cwd so relative paths work inside the container
HOST_CWD="$(pwd)"

# Build docker run args
DOCKER_ARGS=(
    --rm
    -it
    --cap-add=NET_RAW
    -v "${HOST_CWD}:/work"
    -w /work
)

# Mount Axiom config (SSH keys, account profiles)
if [[ -d "${HOME}/.axiom" ]]; then
    DOCKER_ARGS+=(-v "${HOME}/.axiom:/root/.axiom")
fi

# Mount MonkeyX credentials
if [[ -d "${HOME}/.monkeyx" ]]; then
    DOCKER_ARGS+=(-v "${HOME}/.monkeyx:/root/.monkeyx")
fi

# Mount AWS credentials if present
if [[ -d "${HOME}/.aws" ]]; then
    DOCKER_ARGS+=(-v "${HOME}/.aws:/root/.aws:ro")
fi

# Pass through cloud provider env vars if set
[[ -n "${IBMCLOUD_API_KEY:-}" ]]         && DOCKER_ARGS+=(-e "IBMCLOUD_API_KEY=${IBMCLOUD_API_KEY}")
[[ -n "${IBMCLOUD_REGION:-}" ]]          && DOCKER_ARGS+=(-e "IBMCLOUD_REGION=${IBMCLOUD_REGION}")
[[ -n "${AWS_ACCESS_KEY_ID:-}" ]]        && DOCKER_ARGS+=(-e "AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}")
[[ -n "${AWS_SECRET_ACCESS_KEY:-}" ]]    && DOCKER_ARGS+=(-e "AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}")
[[ -n "${AWS_SESSION_TOKEN:-}" ]]        && DOCKER_ARGS+=(-e "AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN}")
[[ -n "${AWS_DEFAULT_REGION:-}" ]]       && DOCKER_ARGS+=(-e "AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}")
[[ -n "${DO_TOKEN:-}" ]]                 && DOCKER_ARGS+=(-e "DO_TOKEN=${DO_TOKEN}")
[[ -n "${AXIOM_ACCOUNT:-}" ]]            && DOCKER_ARGS+=(-e "AXIOM_ACCOUNT=${AXIOM_ACCOUNT}")

# Pass through MonkeyX-specific env vars
[[ -n "${MONKEYX_AI_PROVIDER:-}" ]]      && DOCKER_ARGS+=(-e "MONKEYX_AI_PROVIDER=${MONKEYX_AI_PROVIDER}")
[[ -n "${MONKEYX_AI_API_KEY:-}" ]]       && DOCKER_ARGS+=(-e "MONKEYX_AI_API_KEY=${MONKEYX_AI_API_KEY}")
[[ -n "${MONKEYX_AI_MODEL:-}" ]]         && DOCKER_ARGS+=(-e "MONKEYX_AI_MODEL=${MONKEYX_AI_MODEL}")
[[ -n "${ANTHROPIC_API_KEY:-}" ]]        && DOCKER_ARGS+=(-e "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}")
[[ -n "${OPENAI_API_KEY:-}" ]]           && DOCKER_ARGS+=(-e "OPENAI_API_KEY=${OPENAI_API_KEY}")

# Setup mode — interactive shell for first-time config
if [[ "${1:-}" == "setup" ]]; then
    mkdir -p "${HOME}/.monkeyx" "${HOME}/.axiom"
    DOCKER_ARGS=(
        --rm -it --cap-add=NET_RAW
        -v "${HOST_CWD}:/work" -w /work
        -v "${HOME}/.monkeyx:/root/.monkeyx"
        -v "${HOME}/.axiom:/root/.axiom"
    )
    [[ -d "${HOME}/.aws" ]] && DOCKER_ARGS+=(-v "${HOME}/.aws:/root/.aws")
    echo "=== MonkeyX Setup ==="
    echo "All changes persist to your host via bind mounts."
    echo ""
    echo "  ~/.monkeyx/credentials.yaml  — API keys (AI, Shodan, etc.)"
    echo "  ~/.monkeyx/monkeyx.config    — module settings (ports, wordlists, AI depth)"
    echo "  ~/.axiom/                    — fleet provider config + SSH keys"
    echo ""
    echo "Quick start:"
    echo "  cp /opt/monkeyx/credentials.yaml.example /root/.monkeyx/credentials.yaml"
    echo "  cp /opt/monkeyx/monkeyx.config /root/.monkeyx/monkeyx.config"
    echo "  nano /root/.monkeyx/credentials.yaml"
    echo "  nano /root/.monkeyx/monkeyx.config"
    echo ""
    echo "Type 'exit' when done."
    echo "==========================================="
    exec docker run "${DOCKER_ARGS[@]}" "${IMAGE}" bash
fi

exec docker run "${DOCKER_ARGS[@]}" "${IMAGE}" "$@"
