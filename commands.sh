#!/bin/bash

set -euo pipefail

PORT=/dev/cu.usbmodemML2200011
# PORT=/dev/cu.usbmodemM43210051
SECRETS_FILE=./global.secrets
BUILD_IMAGE_NAME=build-hsm

build_image() {
    local attempt

    for attempt in 1 2 3; do
        # macOS /bin/bash is 3.2; under `set -u`, expanding an empty array as
        # "${arr[@]}" can raise "unbound variable". Keep this branch explicit.
        if [[ "${DOCKER_NO_CACHE:-0}" == "1" ]]; then
            if docker build --no-cache -t "$BUILD_IMAGE_NAME" ./firmware; then
                return 0
            fi
        else
            if docker build -t "$BUILD_IMAGE_NAME" ./firmware; then
                return 0
            fi
        fi

        if [[ "$attempt" -eq 3 ]]; then
            return 1
        fi

        echo "docker build failed on attempt ${attempt}; retrying in 5 seconds..." >&2
        sleep 5
    done
}

if [[ -f "$SECRETS_FILE" ]]; then
    rm -f "$SECRETS_FILE"
fi

uv venv && source .venv/bin/activate && uv pip install -e ./ectf26_design/ && uv pip install cryptography && uv run secrets ./global.secrets '1' '0x4321' && echo "file" > somefile.txt &&
build_image &&
docker run --rm -v ./firmware:/hsm -v ./global.secrets:/secrets/global.secrets:ro -v ./build:/out -e HSM_PIN='123abc' -e PERMISSIONS='1234=R--:4321=RWC' "$BUILD_IMAGE_NAME" &&
uvx ectf hw $PORT reflash ./build/hsm.bin -n hsm &&
sleep 2 &&
uvx ectf tools  $PORT list 123abc &&
uvx ectf tools $PORT write 123abc 0 0x4321 ./somefile.txt  &&
rm -rf ./readback && mkdir -p ./readback &&
uvx ectf tools $PORT read --force 123abc 0 ./readback
