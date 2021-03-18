# ECE 9069 Hacking Companion Notes on Apache Struts 		    CVE-2017-5638

![alt text][equifax]

[equifax]:  https://github.com/jye64/Hacking2/blob/main/equifax.jpg

## Background

### Equifax Data Breach

* Between May and July 2017, massive data breach affecting over 140 million users
* Stolen files contain critical personal information, credit card number, SIN, driver's license numbers 
* Equifax paid up to $ 575 million
* Caused by 0-day attack on Apache Struts


### CVE-2017-5638

* The Jakarta Multipart parser, that is typically used for file uploads, in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10 has incorrect exception handling and error-message generation during file uploading attempts
* Allows remote arbitary commands executions via a crefted Content-Type, Content-Disposition, or Content-Length HTTP header containing a #cmd = string

![alt text][normal HTTP header]

[normal HTTP header]: https://github.com/jye64/Hacking2/blob/main/normal-http-header.png

### Attack Vector

* CVSS Base Score: 10.0 CRITICAL
* Attack Vector: Network
* Attack Complexity: Low
* Privileged Required: None
* User Interaction: None
* Scopes: Changed
* Confidentiality: High
* Integrity: High
* Availability: High


### Remote Command Execution

* Execution of arbitary commands on the host operating system via a vulnerable application
* Typically happens when unsafe user-supplied data (forms, cookies, HTTP headers, etc) is passed to a system call
* Primarily due to insufficient input validation


## Exploits

### Simple Exploit

![alt text][exploit1]

[exploit1]: https://github.com/jye64/Hacking2/blob/main/exploit1.png

* Simple probing by Linux-based commands
* whoami - identify valuable users and come back with more aggressive exploits
* ifconfig - gather network configurations


### Exploit with malicious payload

![alt text][exploit2]

[exploit2]: https://github.com/jye64/Hacking2/blob/main/exploit2.png

* Disable Linux firewall and the SUSE firewall
* Download malicious payload and execute on the server


### Exploit with persistence

![alt text][exploit3]

[exploit3]: https://github.com/jye64/Hacking2/blob/main/exploit3.png

* Copy the file to a benign directory
* Ensure both the executable runs and disable the firewall service when the system boots


## Analysis & Mitigation

![alt text][attack flow]

[attack flow]:  https://github.com/jye64/Hacking2/blob/main/attack-flow.png


### Analysis

* The developer failed to validate and sanitize user-input data properly
	* Length checking by setting the "max_header_length" parameter should be able to catch
	* Keyword check
* Permission management issues
	* Initially 3 permissions, finally up to 51
	* Authentication and authorization
* Poor breach detection ability
	* Slow reation lead to more severe damage

### Mitigation

* Apache recommended immediate upgrade to Struts 2.3.32 or 2.5.10.1 after
* Alternatively, implement a Servlet filter which acts as a workaround

## What now

* Equifax still facing lawsuits and spent at least $1.5 billion
* They claimed have invested over $200 million on cybersecurity after the breach


# References

* **[https://nvd.nist.gov/vuln/detail/CVE-2017-5638](https://nvd.nist.gov/vuln/detail/CVE-2017-5638)**

* **[https://www.securezoo.com/2017/09/equifax-data-breach/](https://www.securezoo.com/2017/09/equifax-data-breach/)**

* **[https://blog.talosintelligence.com/2017/03/apache-0-day-exploited.html](https://blog.talosintelligence.com/2017/03/apache-0-day-exploited.html)**

* **[https://dewcode.medium.com/remote-code-execution-vs-command-execution-df75707aed91](https://dewcode.medium.com/remote-code-execution-vs-command-execution-df75707aed91)**

* **[https://isc.sans.edu/diary/22169](https://isc.sans.edu/diary/22169)**

* **[https://cwiki.apache.org/confluence/display/WW/S2-045](https://cwiki.apache.org/confluence/display/WW/S2-045)**






