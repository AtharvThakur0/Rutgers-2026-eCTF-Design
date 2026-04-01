# Dockerfile for the 2026 eCTF
# Make any changes here to set up your build environment (e.g., installing crypto
# libraries, dependencies, the compiler for a different language)

FROM ubuntu:24.04

LABEL version="0.2"
LABEL description="Example HSM Docker Container for the 2026 eCTF"

ARG DEBIAN_FRONTEND=noninteractive
ARG UBUNTU_PORTS_MIRROR=http://mirror.fmt-2.serverforge.org/ubuntu-ports
WORKDIR /root

# Install Requisite Packages.
# Ubuntu mirrors occasionally serve mismatched package indexes during sync; clear
# the apt caches and retry the full update/install transaction instead of
# reusing the same bad metadata.
RUN set -eux; \
    sed -Ei "s|https?://ports\\.ubuntu\\.com/ubuntu-ports|${UBUNTU_PORTS_MIRROR}|g" /etc/apt/sources.list.d/ubuntu.sources; \
    for attempt in 1 2 3 4 5; do \
        apt-get clean; \
        rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/* /var/cache/apt/archives/partial/*; \
        if apt-get \
            -o Acquire::Retries=3 \
            -o Acquire::BrokenProxy=true \
            -o Acquire::http::No-Cache=true \
            -o Acquire::http::Pipeline-Depth=0 \
            -o Acquire::https::No-Cache=true \
            update \
            && apt-get \
                -o Acquire::Retries=3 \
                -o Acquire::BrokenProxy=true \
                -o Acquire::http::No-Cache=true \
                -o Acquire::http::Pipeline-Depth=0 \
                -o Acquire::https::No-Cache=true \
                install -y --no-install-recommends \
                python3 \
                make \
                wget \
                ca-certificates \
                build-essential \
                unzip; then \
            rm -rf /var/lib/apt/lists/*; \
            break; \
        fi; \
        if [ "$attempt" -eq 5 ]; then \
            echo "apt install failed after ${attempt} attempts" >&2; \
            exit 1; \
        fi; \
        sleep 5; \
    done

RUN wget -q https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.7.6-stable.tar.gz && \
    tar -xzf v5.7.6-stable.tar.gz && \
    mv wolfssl-5.7.6-stable /opt/wolfssl && \
    rm -f v5.7.6-stable.tar.gz

ENV MSPM0_SDK_INSTALL_DIR=/opt/mspm0-sdk-mspm0_sdk_2_06_00_05
ENV TICLANG_ARMCOMPILER=/opt/ti-cgt-armllvm_4.0.3.LTS

# Install MSPM0 SDK
RUN wget https://github.com/TexasInstruments/mspm0-sdk/archive/refs/tags/mspm0_sdk_2_06_00_05.zip && \
    unzip mspm0_sdk_2_06_00_05.zip -d /opt && \
    rm -f -r mspm0_sdk_2_06_00_05.zip ${MSPM0_SDK_INSTALL_DIR}/docs ${MSPM0_SDK_INSTALL_DIR}/examples

# Install TI-Clang for curr machine's arch
RUN if [ $(uname -m) = "x86_64" ]; then \
    wget -O ti_cgt_armllvm_4.0.3.LTS_linux_installer.bin https://dr-download.ti.com/software-development/ide-configuration-compiler-or-debugger/MD-ayxs93eZNN/4.0.3.LTS/ti_cgt_armllvm_4.0.3.LTS_linux-x64_installer.bin --ca-certificate=SSLCerts/mitre-chain.pem; \
    elif [ $(uname -m) = "aarch64" ] || [ $(uname -m) = "arm64" ]; then \
    wget -O ti_cgt_armllvm_4.0.3.LTS_linux_installer.bin https://dr-download.ti.com/software-development/ide-configuration-compiler-or-debugger/MD-ayxs93eZNN/4.0.3.LTS/ti_cgt_armllvm_4.0.3.LTS_linux-arm64_installer.bin --ca-certificate=SSLCerts/mitre-chain.pem; \
    else \
    $(false); \
    fi && \
    chmod +x ti_cgt_armllvm_4.0.3.LTS_linux_installer.bin && \
    ./ti_cgt_armllvm_4.0.3.LTS_linux_installer.bin --mode unattended --prefix /opt && \
    rm -f ti_cgt_armllvm_4.0.3.LTS_linux_installer.bin

WORKDIR /hsm

ENTRYPOINT ["bash", "/hsm/build.sh"]
