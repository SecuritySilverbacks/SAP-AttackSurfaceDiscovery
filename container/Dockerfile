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
    python2-dev \
    ffuf \
    vim \
    masscan \
    sudo \
    && curl https://apt.metasploit.com/metasploit-framework.gpg.key | gpg --dearmour -o /etc/apt/trusted.gpg.d/metasploit.gpg \
    && curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall \
    && bash /tmp/msfinstall && rm -rf /tmp/msfinstall && rm -rf /var/lib/apt/lists/*

# Setup Folder
RUN mkdir -p /tools/.bin && mkdir -p /tools/nuclei-sap-templates && mkdir -p /tools/wordlists
ENV PATH="${PATH}:/tools/.bin"

# Setup ERPScan Nmap
RUN git clone --depth=1 https://github.com/gelim/nmap-sap /tools/nmap-erpscan

# Setup nuclei & install default templates
RUN VERSION=$(curl -s https://api.pdtm.sh/api/v1/tools/nuclei | jq '.tools[0]["version"]' | tr -d '"') && \
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v$VERSION/nuclei_$(echo $VERSION)_linux_amd64.zip" -O /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /tools/.bin/ && rm /tmp/nuclei.zip && rm -rf /tools/.bin/*.md && nuclei -ut && rm -rf /tmp/*

# Setup nuclei-sap-templates
ADD ./nuclei-sap-templates/ /tools/nuclei-sap-templates
ADD ./tools/ /tools/

# Install tools requirements
RUN pip3 install -r /tools/requirements.txt && rm /tools/requirements.txt && chmod +x /tools/*.py

# Install python2 pip
RUN wget -q https://bootstrap.pypa.io/pip/2.7/get-pip.py -O /tmp/get-pip.py && python2 /tmp/get-pip.py && rm -rf /tmp/get-pip.py && rm -rf /tmp/*

# Install & setup SAPstart service enumeration tool
RUN git clone --depth=1 https://github.com/randomstr1ng/sapstartsrv-enumeration/ /tools/sapstartsrv-enumeration && \
    chmod +x /tools/sapstartsrv-enumeration/*.py && \
    pip3 install -r /tools/sapstartsrv-enumeration/requirements.txt && mv /tools/sapstartsrv-enumeration/*.py /tools/ && rm -rf /tools/sapstartsrv-enumeration

# Install SAP Web Service Bruteforce
RUN mkdir -p /root/.msf4/modules/auxiliary/scanner/sap/ && wget -q https://raw.githubusercontent.com/randomstr1ng/sap-webgui-bruteforce/main/metasploit-module/sap_web_bruteforce.py -O /root/.msf4/modules/auxiliary/scanner/sap/sap_web_bruteforce.py && chmod +x /root/.msf4/modules/auxiliary/scanner/sap/sap_web_bruteforce.py \
    && python3 -m pip install lxml bs4 argparse requests \
    && wget -q https://raw.githubusercontent.com/randomstr1ng/sap-webgui-bruteforce/main/sap_webgui_brute.py -O /tools/sap_webgui_brute.py && chmod +x /tools/sap_webgui_brute.py

# Download SAP ICM wordlist
RUN wget -q https://raw.githubusercontent.com/rapid7/metasploit-framework/master/data/wordlists/sap_icm_paths.txt -O /tools/wordlists/sap_icm_paths.txt && rm -rf /tmp/*

# Setup SNCSCAN
RUN python3 -m pip install pysap@git+https://github.com/usdAG/pysap_sncscan.git@main-sncscan && git clone --depth=1 https://github.com/usdAG/sncscan /tools/sncscan  \
    && cd /tools/sncscan && python3 setup.py install && chmod +x /tools/sncscan/sncscan.py && ln -s /tools/sncscan/sncscan.py /tools/.bin/sncscan && rm -rf /tmp/*

# Install additional tools
RUN python3 -m pip install shodan
RUN python2 -m pip install pysap[examples] && git clone --depth=1 https://github.com/OWASP/pysap.git /tmp/pysap && mv /tmp/pysap/examples/*.py /tools/.bin/ && mv /tmp/pysap/examples/* /tools/wordlists/ && rm -rf /tmp/pysap
RUN wget https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz -O /tmp/gobuster.tar.gz && tar -xvf /tmp/gobuster.tar.gz -C /tools/.bin/ && rm -rf /tmp/gobuster.tar.gz

# Final Setup
RUN echo "alias ll='ls -al --color=auto'" > /root/.bashrc
RUN echo "export PS1='\e[0;32m\u@sap-attack-surface\e[m:\e[1;33m\w\e[m\n\$ '" >> /root/.bashrc
WORKDIR /work
ENTRYPOINT ["/bin/bash"]
