FROM ubuntu:22.04

# Install Packages
RUN apt-get update && apt-get install -y \
    nmap \
    git \
    wget \
    curl \
    python3-pip \
    jq \
    bash \
    unzip \
 && rm -rf /var/lib/apt/lists/*

# Setup Folder
RUN mkdir -p /tools/.bin && mkdir -p /tools/nuclei-sap-templates
ENV PATH="${PATH}:/tools/.bin"

# Setup ERPScan Nmap
RUN git clone --depth=1 https://github.com/randomstr1ng/nmap-erpscan /tools/nmap-erpscan

# Setup nuclei & install default templates
RUN VERSION=$(curl -s https://api.pdtm.sh/api/v1/tools/nuclei | jq '.tools[0]["version"]' | tr -d '"') && \
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v$VERSION/nuclei_$(echo $VERSION)_linux_amd64.zip" -O /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /tools/.bin/ && rm /tmp/nuclei.zip && rm -rf /tools/.bin/*.md && nuclei -ut

# Final Setup
RUN echo "alias ll='ls -alF'" > /root/.bashrc
ENV PS1='\e[0;32m\u@sap-attack-surface\e[m:\e[1;33m\w\e[m\n\$ '
WORKDIR /work
ENTRYPOINT ["/bin/bash"]
