# show CPU architecture
LinuxARCH=$(uname -m) && \
    DebianARCH=$(dpkg --print-architecture) && \
    echo "Linux: $LinuxARCH, Debian: $DebianARCH"

###### My own scripts: ########
echo ">>> awscli2 installing <<<" \
    && if [ "$LinuxARCH" = "aarch64" ]; then \
        URL="https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip"; \
       else \
        URL="https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip"; \
       fi \
    && curl "$URL" -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && sudo ./aws/install --update \
    && rm -rf aws awscliv2.zip \
    && aws --version \
    && echo "complete -C '/usr/local/bin/aws_completer' aws" | tee -a ~/.bashrc

echo ">>> AWS Session Manager Cli Plugin Installing <<<" \
    && if [ "$DebianARCH" = "arm64" ]; then \
        URL="https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_arm64/session-manager-plugin.deb"; \
       else \
        URL="https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_64bit/session-manager-plugin.deb"; \
       fi \
    && curl "$URL" -o "session-manager-plugin.deb" \
    && sudo dpkg -i session-manager-plugin.deb \
    && rm -f session-manager-plugin.deb

echo ">>> AWS SAM Cli Installing <<<" \
    && if [ "$DebianARCH" = "arm64" ]; then \
        URL="https://github.com/aws/aws-sam-cli/releases/latest/download/aws-sam-cli-linux-arm64.zip"; \
       else \
        URL="https://github.com/aws/aws-sam-cli/releases/latest/download/aws-sam-cli-linux-x86_64.zip"; \
       fi \
    && curl -L "$URL" -o aws-sam-cli-linux.zip  \
    && unzip aws-sam-cli-linux.zip -d sam-installation \
    && sudo ./sam-installation/install --update \
    && rm -rf aws-sam-cli-linux.zip ./sam-installation \
    && sam --version