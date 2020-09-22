# SAP Internet Research

*__Make sure you have the appropriate permissions to actively scan and test applications. Without doing so, you might face legal implications__*

The SAP Internet Research project aims to help organization and security professionals to identify and discover open SAP services facing the internet. This allows individuals to further test these services for any potential threat that might affect SAP applications in their organizations.  

### Objectives:

- To allow security professional to be able to identify and discover SAP internet facing applications being used by their organization
- To be able to demonstrate to organizations the risk that can exist from SAP applications facing the internet
- Aligning the results of the research to a single organization to demonstrate SAP technology risk
-	To allow contribution to the SAP Internet Research project

### WIIFM (Whats In It For Me)

Below is a list of how you can benefit from the different research areas of the project:

- Using different port scanners to discover your organizations open SAP services that are published to the internet, below are the services included in the project:
 - SAPouter [product info](https://support.sap.com/en/tools/connectivity-tools/saprouter.html) is a reverse proxy for the SAP proprietary RFC protocol. Insecurely configured SAProuter can allow an attacker to discover SAP installations behind the reverse proxy and forcing unencrypted communication. Unpatched versions are known to be vulnerable against denial of service attacks and compromise of configuration [CVE's](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=SAProuter)
 - SAP RFC Gateway is a gateway service which standalone, or as part of an SAP ABAP system provides service for the proprietary RFC protocol. Unpatched, or misconfigured installations can yield to full system compromise. Up to unauthenticated remote code execution vulnerabilities. By default the RFC protocol is not encrypted. Communication encryption has to be setup by the use of [SNC](https://help.sap.com/viewer/e73bba71770e4c0ca5fb2a3c17e8e229/LATEST/en-US/e656f466e99a11d1a5b00000e835363f.html)
 - SAP Internet Graphic Server (IGS) provides services to generate web graphics. It can run standalone or intergrated in an SAP system. When certain patches are missing the IGS can be vulnerable to various [attacks](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=SAP+IGS) yielding for example to arbitrary remote file manipulation or denial of service
 - SAP Message Server Internal Port provides cluster management services between the application servers of an SAP system cluster. When exposed to malicious actors it can be [misused](https://github.com/gelim/sap_ms) to bypass protection configurations of the SAP RFC Gateway to allow full system compromise even when the gateway is properly configured.
 - HANA Database

- Conducting further analysis on the discovered services
- Aligning discovery with the Core Business Application Security (CBAS) – Security Aptitude Assessment.
- Monitoring services within your organizations IP block that might get published due to misconfiguration

### OWASP CBAS project:

Three areas within the __NO MONKEY Security Matrix__ can benefit from the SAP Internet Research project:
1. Identify – NIST Security Functions
2. Detect - NIST Security Functions
3. Integration – IPAC Model

#### Identify | Integration

When applied to a single organization, the results from the SAP Internet Research project can aid organizations to further concentrate their efforts in the IDENTIFY and INTEGRATION quadrant of the NO MONKEY Security Matrix.

#### Detect | Integration

Another potential area of benefit will be under the DETECT and INTEGRATION quadrant, this will allow organizations to automate their monitoring capabilities when it comes to publishing SAP application to the internet. If publishing these applications is not a requirement and have been done due to misconfiguration then the organization would be able to properly detect it.
