FROM alpine:latest

# Install Packages
RUN apk add --no-cache nmap nmap-scripts wget bash py3-pip git libcap

# Setup Folder
RUN mkdir -p /tools/.bin && mkdir -p /tools/nuclei-sap-templates
ENV PATH="${PATH}:/tools/.bin"

# Setup Nmap permissions
RUN setcap cap_net_admin=ie $(which nmap)

# Setup ERPScan Nmap
RUN git clone --depth=1 https://github.com/gelim/nmap-erpscan.git /tools/nmap-erpscan

# Setup nuclei & install default templates
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.0.1/nuclei_3.0.1_linux_amd64.zip -O /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /tools/.bin/ && rm /tmp/nuclei.zip && nuclei -ut

# Setup nuclei-sap-templates
ADD ./nuclei-sap-templates/ /tools/nuclei-sap-templates

# Final Setup
RUN alias ll='ls -la'
ENV PS1='sap-attack-surface:\w\$ '
WORKDIR /work
ENTRYPOINT ["/bin/bash"]