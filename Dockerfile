# MonkeyX — multi-stage Docker build (public / CLI-only)
# Stage 1: compile Go-based security tools
# Stage 2: runtime with all scanning + validation tools

# ---------------------------------------------------------------------------
# Stage 1: Go tools
# ---------------------------------------------------------------------------
FROM golang:1.24-bookworm AS go-builder

# Pin the toolchain to the one in the base image (no silent auto-upgrade at build).
ENV GOTOOLCHAIN=local

RUN go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/d3mondev/puredns/v2@latest && \
    go install github.com/sensepost/gowitness@latest && \
    go install github.com/ffuf/ffuf/v2@latest

# ---------------------------------------------------------------------------
# Stage 2: Runtime
# ---------------------------------------------------------------------------
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/usr/local/bin:${PATH}"

# System packages — scanning + validation tools + build deps for Python packages
RUN apt-get update -qq && apt-get install -y -qq \
    curl \
    git \
    jq \
    masscan \
    nmap \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    libxml2-dev \
    libxslt1-dev \
    libffi-dev \
    libpcap-dev \
    unzip \
    wget \
    whois \
    dnsutils \
    whatweb \
    snmp \
    smbclient \
    netcat-openbsd \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Chromium for gowitness screenshots. Optional (gowitness can fetch its own), so a
# failure here is tolerated — but apt-list cleanup always runs.
RUN apt-get update -qq; \
    apt-get install -y -qq chromium-browser 2>/dev/null || \
    apt-get install -y -qq chromium 2>/dev/null || \
    echo "[!] Chromium not available via apt — gowitness will attempt its own download"; \
    rm -rf /var/lib/apt/lists/*

# Go tool binaries from builder stage
COPY --from=go-builder /go/bin/ /usr/local/bin/

# testssl.sh
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh && \
    ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl

# ssh-audit via pip
RUN pip3 install --no-cache-dir ssh-audit

# feroxbuster (Rust prebuilt binary)
RUN FEROX_URL=$(curl -sL https://api.github.com/repos/epi052/feroxbuster/releases/latest \
        | jq -r '.assets[] | select(.name | test("x86_64.*linux.*musl")) | .browser_download_url' | head -1) && \
    if [ -n "$FEROX_URL" ]; then \
        wget -q "${FEROX_URL}" -O /tmp/feroxbuster.tar.gz && \
        tar -xzf /tmp/feroxbuster.tar.gz -C /usr/local/bin/ feroxbuster && \
        chmod +x /usr/local/bin/feroxbuster && \
        rm -f /tmp/feroxbuster.tar.gz; \
    else \
        echo "[!] feroxbuster download failed (GitHub rate limit?) — skipping"; \
    fi

# Axiom — clone as fallback; at runtime the user's ~/.axiom is mounted over this
RUN git clone --quiet https://github.com/pry0cc/axiom /opt/axiom-fallback
ENV PATH="/root/.axiom/interact:/opt/axiom-fallback/interact:${PATH}"

# IBM Cloud CLI (for IBM VPC fleet provider).
# Download to a file first (rather than piping straight to a root shell) so a
# truncated/failed download is caught by set -e instead of being executed.
RUN curl -fsSL https://clis.cloud.ibm.com/install/linux -o /tmp/ibmcloud-install.sh && \
    sh /tmp/ibmcloud-install.sh && \
    rm -f /tmp/ibmcloud-install.sh && \
    ibmcloud plugin install vpc-infrastructure -f

# AWS CLI
RUN curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip && \
    unzip -q /tmp/awscliv2.zip -d /tmp && \
    /tmp/aws/install && \
    rm -rf /tmp/aws /tmp/awscliv2.zip

# Wordlists
RUN mkdir -p /home/op/lists && \
    git clone --quiet --depth 1 https://github.com/danielmiessler/SecLists.git /home/op/lists/seclists && \
    wget -q https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -O /home/op/lists/resolvers.txt

# ---------------------------------------------------------------------------
# MonkeyX application code
# ---------------------------------------------------------------------------
WORKDIR /opt/monkeyx

# Python deps
COPY requirements.txt /opt/monkeyx/requirements.txt
RUN pip3 install --no-cache-dir -r /opt/monkeyx/requirements.txt

# Application code
COPY core/ /opt/monkeyx/core/
COPY modules/ /opt/monkeyx/modules/
COPY utils/ /opt/monkeyx/utils/
COPY workflows/ /opt/monkeyx/workflows/
COPY workflows.py /opt/monkeyx/workflows.py
COPY monkeyx.py /opt/monkeyx/monkeyx.py
COPY monkeyx.config /opt/monkeyx/monkeyx.config
COPY credentials.yaml.example /opt/monkeyx/credentials.yaml.example

# Entrypoint script
COPY docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Axiom path override
ENV AXIOM_PATH="/root/.axiom/"

ENTRYPOINT ["docker-entrypoint.sh"]
