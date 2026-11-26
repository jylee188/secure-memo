#!/usr/bin/env bash

set -Eeuo pipefail

cd "$(dirname "$0")"

NEW_IMAGE="${1:?Docker image is required}"

# Prevent concurrent deployments

exec 9>runtime/deploy.lock

flock -n 9 || {
    echo "Another deployment is running"
    exit 1
}

echo "=================================="
echo "Blue-Green Deployment"
echo "Image: $NEW_IMAGE"
echo "=================================="

ACTIVE_FILE="runtime/active.inc"

OLD_CONFIG=$(cat "$ACTIVE_FILE")


# ==========================================
# 1. Select inactive service
# ==========================================

if grep -q "was-blue:8000" "$ACTIVE_FILE"; then

    TARGET="was-green"
    TARGET_SLOT="green"

elif grep -q "was-green:8000" "$ACTIVE_FILE"; then

    TARGET="was-blue"
    TARGET_SLOT="blue"

else

    echo "Invalid upstream configuration"
    exit 1

fi

echo "Target service: $TARGET"

export APP_IMAGE="$NEW_IMAGE"


# ==========================================
# 2. Pull new Docker image
# ==========================================

docker compose pull "$TARGET"


# ==========================================
# 3. Start inactive WAS
# ==========================================

docker compose up \
    -d \
    --no-deps \
    --wait \
    --wait-timeout 120 \
    "$TARGET"

echo "Target health check passed"


# ==========================================
# 4. Rollback function
# ==========================================

rollback() {

    echo "Deployment failed. Restoring upstream."

    printf '%s\n' "$OLD_CONFIG" \
        > runtime/active.tmp

    mv runtime/active.tmp "$ACTIVE_FILE"

    docker compose exec -T web nginx -t

    docker compose exec -T web nginx -s reload

}


# ==========================================
# 5. Switch upstream
# ==========================================

printf 'server %s:8000;\n' "$TARGET" \
    > runtime/active.tmp

mv runtime/active.tmp "$ACTIVE_FILE"

if ! docker compose exec -T web nginx -t; then

    rollback
    exit 1

fi

if ! docker compose exec -T web nginx -s reload; then

    rollback
    exit 1

fi


# ==========================================
# 6. Verify public-facing service
# ==========================================

EXPECTED_VERSION="${NEW_IMAGE##*:}"

SUCCESS=0

for i in $(seq 1 20); do

    if curl -kfsS \
        --max-time 5 \
        https://127.0.0.1/health \
        | jq -e \
            --arg slot "$TARGET_SLOT" \
            --arg version "$EXPECTED_VERSION" \
            '.status == "healthy"
             and .slot == $slot
             and .version == $version' \
        > /dev/null
    then

        SUCCESS=1
        break

    fi

    sleep 2

done

if [ "$SUCCESS" -ne 1 ]; then

    rollback
    exit 1

fi

echo "=================================="
echo "Deployment successful"
echo "Active service: $TARGET"
echo "Version: $EXPECTED_VERSION"
echo "=================================="

docker compose ps