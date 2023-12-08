FROM alpine:latest

# Install Packages
RUN apk add --no-cache nmap nmap-scripts wget bash py3-pip git libcap jq curl

# Setup Folder
RUN mkdir -p /tools/.bin && mkdir -p /tools/nuclei-sap-templates
ENV PATH="${PATH}:/tools/.bin"

# Setup Nmap permissions
RUN setcap cap_net_admin=ie $(which nmap)

# Setup ERPScan Nmap
RUN git clone --depth=1 https://github.com/randomstr1ng/nmap-erpscan /tools/nmap-erpscan

# Setup nuclei & install default templates
RUN VERSION=$(curl -s https://api.pdtm.sh/api/v1/tools/nuclei | jq '.tools[0]["version"]' | tr -d '"') && \
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v$VERSION/nuclei_$(echo $VERSION)_linux_amd64.zip" -O /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /tools/.bin/ && rm /tmp/nuclei.zip && rm -rf /tools/.bin/*.md && nuclei -ut

# Setup nuclei-sap-templates
ADD ./nuclei-sap-templates/ /tools/nuclei-sap-templates
ADD ./tools/ /tools
# Install tools requirements
RUN pip3 install -r /tools/requirements.txt --break-system-packages && rm /tools/requirements.txt && chmod +x /tools/*.py

# Install & setup SAPstart service enumeration tool
RUN git clone --depth=1 https://github.com/randomstr1ng/sapstartsrv-enumeration/ /tools/sapstartsrv-enumeration && \
    chmod +x /tools/sapstartsrv-enumeration/*.py && \
    pip3 install -r /tools/sapstartsrv-enumeration/requirements.txt --break-system-packages

# Final Setup
ENV PS1='\e[0;32m\u@sap-attack-surface\e[m:\e[1;33m\w\e[m\n\$ '
WORKDIR /work
ENTRYPOINT ["/bin/bash"]
