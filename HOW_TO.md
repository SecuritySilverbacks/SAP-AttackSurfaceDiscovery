# Requirements
We have conducted our tests using __Ubuntu 20.04__, but the tools installation can be done on any linux distribution, or Windows OS (installation steps on Windows are not mentioned)


|Tool Name| Installation| Additional Notes|
|:--------|:------------|:----------------|
|NMAP     |*$ sudo apt install nmap* |Scan tool|
|NMAP ERPSCAN|*$ git clone git://github.com/gelim/nmap-erpscan*|Improves nmap capabilities when detecting SAP Services|
|ZMAP     |*$ sudo apt install zmap* |Scan tool. Used for large scale analysis|
|Masscan  |*$ sudo apt install masscan* |Scan tool. Used for large scale analysis|
|IFSTAT   |*$ sudo apt install ifstat*|Tool used to check bandwidth|
|SAPROUTER Utilities|SAP Download Manager|Need an S-User to download the utilities|
|GIT   |*$ sudo apt install git*|Content tracker|
|Python   |*$ sudo apt install python*|Can be used for automating detection mechanisms|

## Initial steps

After installing the appropriate tools, we start by detecting SAP services that can present a risk to your organization if misused or misconfigured.

Use NMAP-ERPSCAN service probes to find open SAP services for your organization. (External and internal testing is recommended)

> *$ git clone git://github.com/gelim/nmap-erpscan*
>
> *$ cd nmap-erpscan*
>
> *$ nmap -n --open --datadir . -sV -p $(./sap_ports.py) $TARGET*
>> __Changing the data directory (--datadir) helps to better identify SAP services as they are not added to the default data directory of NMAP__


### SAPRouter

|Port | Used Tools| Additional Notes|
|:--------|:------------|:----------------|
|3299 | NMAP, SAPRouter Utilities|

If the initial scan has not identified any open ports for the SAPRouter, you can try to scan with below command specifying the SAPRouter port if it is not the default one.

> $ nmap -sV -n -p 3299 -Pn $TARGET -oX output_nmap_3299.txt
>
> Identifying SAPRouter. *Yellow circle mark shown in the image below*

<img src="saprouter_identify.png" /><br>


In order to further test the SAPRouter and determine whether access is allowed or denied, you will require to download the SAPRouter utilities from the SAP download manager using you S-USER. (The S-USER is given to organizations that have deployed or is currently implementing any SAP applications)

In order to determine whether the access is allowed or not, use the below command.

> $ saprouter -L -H <target>

##### Access denied
<img src="saprouter_denied.png" /><br>

##### Access allowed
<img src="saprouter_allowed.png" /><br>

The above reply shows the SAProuter connection list, this information can be very critical as it may allow routing from the internet to the internal local network, this information is usually available in and can be retrieved from the SAPROUTTAB file.

### SAP Gateway

|Port | Used Tools| Additional Notes|
|:--------|:------------|:----------------|
|3300 | NMAP, NMAP erpscan|

If the initial scan has not identified any open ports for the SAP Gateway, you can try to scan with below command specifying the SAP Gateway port if it is not the default one.

> $ nmap -sV -R -p 3300 -Pn <target>



### SAP Internet Graphic Server

|Port | Used Tools| Additional Notes|
|:--------|:------------|:----------------|
|40080 | NMAP, NMAP erpscan|

If the initial scan has not identified any open ports for the SAP Internet Graphic Server, you can try to scan with below command specifying the SAP Internet Graphic Server port if it is not the default one.

> $ nmap -sV -R -p 40080 -Pn <target>

### SAP Message Server Internal Port

|Port | Used Tools| Additional Notes|
|:--------|:------------|:----------------|
|3900 | NMAP, NMAP erpscan|

If the initial scan has not identified any open ports for the SAP Message Server Internal, you can try to scan with below command specifying the SAP Message Server Internal port if it is not the default one.

> $ nmap -sV -R -p 3900 -Pn <target>

### HANA Database

|Port | Used Tools| Additional Notes|
|:--------|:------------|:----------------|
|30015 | NMAP, NMAP erpscan|

If the initial scan has not identified any open ports for the HANA Database, you can try to scan with below command specifying the HANA Database port if it is not the default one.

> $ nmap -sV -R -p 30015 -Pn <target>
