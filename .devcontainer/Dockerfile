FROM mcr.microsoft.com/devcontainers/python:3.12-bookworm

# Avoid pip warnings about running as root
ENV PIP_ROOT_USER_ACTION=ignore

# ─── Zscaler TLS Inspection Fix ──────────────────────────────
# Altus Group uses Zscaler as SASE/cloud proxy which performs
# TLS MITM inspection on all HTTPS traffic. The container's
# Linux CA store doesn't trust Zscaler's Root CA by default,
# causing SSL errors for apt, curl, pip, etc.
#
# Step 1: Add Zscaler Root CA to system trust store
#   - This fixes: curl, wget, apt, and anything using OpenSSL
#     system CA bundle
ADD .devcontainer/Zscaler_Root_CA.crt /usr/local/share/ca-certificates/Zscaler_Root_CA.crt
RUN chmod 644 /usr/local/share/ca-certificates/Zscaler_Root_CA.crt \
    && update-ca-certificates

# Step 2: Fix pip specifically
#   - pip uses its own CA bundle (certifi), NOT the system store
#   - pip_system_certs monkey-patches pip to use system CA store
#   - --trusted-host is needed here because pip doesn't trust
#     Zscaler yet at this point (chicken-and-egg problem)
RUN pip install \
    --trusted-host pypi.org \
    --trusted-host pypi.python.org \
    --trusted-host files.pythonhosted.org \
    pip_system_certs
# ─── End Zscaler Fix ─────────────────────────────────────────

COPY .devcontainer/install-aws-commandlines.sh /tmp/install-aws-commandlines.sh
RUN echo ">>> Install AWS CLIs <<<" \
    && chmod +x /tmp/install-aws-commandlines.sh \
    && /tmp/install-aws-commandlines.sh

ADD  --chown=vscode:vscode .devcontainer/amazon-root-ca-1.pem /home/vscode/.aws/amazon-root-ca-1.pem
ADD  --chown=vscode:vscode .devcontainer/aws-sso-profiles-config /home/vscode/.aws/config
ENV AWS_CA_BUNDLE=/home/vscode/.aws/amazon-root-ca-1.pem
