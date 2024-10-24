# Bug Bounty

To perform a successful bug bounty, you need a structured workflow that covers reconnaissance, vulnerability identification, exploitation, and reporting. Here's a detailed step-by-step guide for an effective bug bounty workflow:

### 1. **Understanding the Scope**

- **Read the program’s rules and scope**: Carefully review the target's scope, including what systems, domains, and vulnerabilities are allowed. Understand any legal implications and rules around testing (e.g., restricted areas, production vs. test environments).
- **Focus on out-of-scope exclusions**: Some bounty programs explicitly restrict certain types of tests (e.g., denial-of-service, physical attacks). Avoid these.

### 2. **Reconnaissance (Recon)**

Start by gathering as much information as possible about the target.

### 2.1 **Passive Reconnaissance**

- **Subdomain Enumeration**:
    - Tools: `Amass`, `Sublist3r`, `Assetfinder`
    - Command: `amass enum -passive -d example.com`
- **DNS Enumeration**:
    - Tools: `dnsrecon`, `dnsenum`
    - Command: `dnsrecon -d example.com`
- **Google Dorking**: Use Google search queries to find exposed resources or interesting files.
    - Example: `site:example.com filetype:pdf`

### 2.2 **Active Reconnaissance**

- **Port Scanning**:
    - Tools: `Nmap`
    - Command: `nmap -sS -p- -T4 example.com`
- **Service Enumeration**: Identify services running on open ports.
    - Command: `nmap -sV -p 80,443,22 example.com`
- **Directory Brute Forcing**:
    - Tools: `Gobuster`, `Dirbuster`
    - Command: `gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt`

### 3. **Vulnerability Identification**

Look for vulnerabilities using both automated tools and manual testing.

### 3.1 **Automated Scanning**

- **Vulnerability Scanners**:
    - Tools: `Nikto`, `OpenVAS`, `Nessus`
    - Command: `nikto -host http://example.com`

### 3.2 **Manual Testing**

- **Test for Common Vulnerabilities**:
    - **SQL Injection**:
        - Tools: `SQLMap`
        - Command: `sqlmap -u "http://example.com/page?id=1" --batch --risk=3`
    - **Cross-Site Scripting (XSS)**:
        - Test input fields with payloads like `<script>alert('XSS')</script>`.
    - **Cross-Site Request Forgery (CSRF)**:
        - Test if forms can be submitted by third-party sites.
    - **Command Injection**:
        - Tools: Manual payloads like `; ls` or `| whoami`.

### 4. **Exploitation**

After identifying a vulnerability, the next step is to exploit it to confirm its impact.

### 4.1 **Exploiting Web Vulnerabilities**

- **XSS**: If you find an XSS vulnerability, try to steal cookies or execute scripts in the victim’s browser.
- **SQL Injection**: Use `SQLMap` to exploit the SQL injection for data extraction, database dumps, or even system-level access if possible.
- **Remote Code Execution (RCE)**: If code execution is possible, attempt to gain shell access via payloads like reverse shells.

### 4.2 **Privilege Escalation**

- If you gain limited access to a system, try escalating privileges (e.g., from web server access to root).
- Tools: `LinPEAS`, `WinPEAS` (for privilege escalation checks)

### 5. **Post-Exploitation (Optional)**

If allowed by the bug bounty program:

- **Lateral Movement**: Try to pivot through the network to other systems.
- **Data Extraction**: Extract data that demonstrates the impact of the vulnerability.
- **Persistence**: Explore if you can maintain access for further testing.

### 6. **Reporting the Vulnerability**

Craft a detailed report to maximize the chances of receiving a bounty.

### 6.1 **Report Writing**

- **Title**: Clearly state the type of vulnerability and affected component (e.g., "SQL Injection on Login Page").
- **Description**: Explain the vulnerability in detail. Include:
    - Steps to reproduce
    - Payloads used
    - Impact of the vulnerability (e.g., data leakage, account takeover)
- **Proof of Concept (PoC)**: Provide screenshots, videos, or a working PoC demonstrating the exploitation.
- **Recommendations**: Suggest mitigations, such as input validation or proper security headers.

### 6.2 **Submit the Report**

- Submit the report to the bug bounty platform (e.g., HackerOne, Bugcrowd) or the company’s dedicated disclosure channel.
- Be prepared to answer clarifying questions from the program maintainers and potentially test fixes.

### 7. **Post-Report Follow-Up**

- **Respond Promptly**: Be responsive to any questions the program administrators might have.
- **Check Fixes**: If requested, test the implemented fixes and provide feedback.
- **Track Your Reports**: Keep a log of all reports, whether rewarded or not, for learning purposes and future reference.

### 8. **Improve Skills and Tools**

- **Stay Updated**: Vulnerabilities evolve, so stay up-to-date with new attack techniques and security news.
- **Practice on Platforms**: Use platforms like Hack The Box or OWASP Juice Shop to sharpen your skills.
- **Enhance Recon Tools**: Automate recon processes to scale up your testing for larger scopes.

---

### (Recon)

Reconnaissance (Recon) is one of the most critical phases in bug bounty hunting because it helps you discover potential attack surfaces. A thorough recon will give you a complete map of the target's infrastructure, hidden URLs, sensitive parameters, ports, services, and other exploitable points. Below is a more detailed breakdown of the recon phase, focusing on port scanning, URL enumeration, parameters, screenshots, and other techniques to gather information.

### 1. **Subdomain and Domain Enumeration**

Finding subdomains can reveal hidden or forgotten services and entry points that might not be protected as well as the main domain.

### Tools:

- **`Amass`**: Powerful passive and active subdomain enumeration tool.
    - Command: `amass enum -d example.com`
- **`Sublist3r`**: Fast subdomain enumeration.
    - Command: `sublist3r -d example.com`
- **`Assetfinder`**: Quickly finds subdomains using various public sources.
    - Command: `assetfinder --subs-only example.com`

### Techniques:

- **`Passive DNS Enumeration`**: Search DNS records for subdomains without actively pinging the server.
- **`Certificate Transparency Logs`**: Use services like `crt.sh` to find subdomains from SSL/TLS certificates.
- **`Brute Forcing Subdomains`**: Use a wordlist to brute-force potential subdomains.
    - Command: `ffuf -w /path/to/wordlist.txt -u https://FUZZ.example.com`

### 2. **Port Scanning**

Identifying open ports and the services running on them is crucial for discovering vulnerabilities. For instance, finding non-standard services or outdated software on open ports might lead to privilege escalation or other attacks.

### Tools:

- **`Nmap`**: Standard tool for network discovery and port scanning.
- **`Masscan`**: Fastest tool for large-scale port scanning (use cautiously).
- **`RustScan`**: Extremely fast port scanner that integrates with `Nmap`.

### Steps:

- **Scan All Ports**: Ensure you scan all TCP/UDP ports to avoid missing hidden services.
    - Command: `nmap -sS -p- -T4 example.com`
    - Fast alternative: `masscan -p0-65535 --rate=1000 -oL output.txt example.com`
- **Service Version Detection**: Once ports are identified, find the version of services running on those ports.
    - Command: `nmap -sV -p 80,443,22 example.com`
- **Operating System Detection**: Determine the target's operating system.
    - Command: `nmap -O example.com`

### Ports of Interest:

- **Common Ports**: HTTP (80, 443), FTP (21), SSH (22), SMTP (25), DNS (53), SMB (445), RDP (3389), etc.
- **Non-standard Ports**: Services running on uncommon ports might be less secured or overlooked.
- **Hidden Services**: Ports hosting web applications, admin panels (e.g., `:8080`, `:8443`, `:8000`), database management (e.g., MySQL `3306`, PostgreSQL `5432`).

### 3. **Service Enumeration**

Once open ports are identified, the next step is to identify what software versions are running and look for specific vulnerabilities.

### Steps:

- **Banner Grabbing**: Extract banners from services to identify their versions.
    - Command: `nmap -sV --script=banner -p 21,22,80,443 example.com`
- **Service-Specific Tools**: Use tools designed for specific services.
    - **FTP**: `hydra -l admin -P /path/to/passwords.txt ftp://example.com` (Brute-force FTP login)
    - **SMB**: `smbclient -L //example.com -N` (List shares)
    - **HTTP**: `whatweb http://example.com` (Identify web technologies)

### Identifying Vulnerabilities:

- **Search Exploits**: Once the service version is identified, search for known exploits using tools like `Searchsploit` or online databases like `Exploit-DB`.
    - Command: `searchsploit apache 2.4.49`

### 4. **URL and Directory Enumeration**

Enumerating URLs and directories helps you discover hidden pages, admin panels, API endpoints, and login portals.

### Tools:

- **Gobuster**: Directory and file brute-forcing tool.
    - Command: `gobuster dir -u http://example.com -w /path/to/wordlist.txt`
- **Dirsearch**: Another effective tool for directory brute-forcing.
    - Command: `dirsearch -u http://example.com -e php,html,js -w /path/to/wordlist.txt`
- **FFUF**: Highly customizable tool for fuzzing directories, parameters, and virtual hosts.
    - Command: `ffuf -w /path/to/wordlist.txt -u http://example.com/FUZZ`

### Techniques:

- **Brute-force Directories**: Use large wordlists like `SecLists` to find hidden directories.
- **Common Directories**:
    - `/admin`, `/login`, `/backup`, `/wp-admin`, `/api`, `/uploads`, `/config`.
- **API Enumeration**: Use specific wordlists for APIs (e.g., `/v1`, `/users`, `/search`, `/admin`).
- **Web Archives**: Look up old versions of the site in the Wayback Machine to find deprecated or hidden URLs.
    - Tool: `waybackurls example.com`

### 5. **Parameter Discovery**

Finding parameters in URLs is key to testing for vulnerabilities like SQL injection, XSS, and IDOR.

### Tools:

- **`Burp Suite`**: Use the Burp Suite proxy to capture and analyze parameters.
    - Techniques: Identify GET and POST parameters, headers, cookies, and hidden fields.
- **`ParamMiner`**: Burp Suite extension that guesses hidden parameters.
- **`FFUF`**: Use it to brute-force GET parameters.
    - Command: `ffuf -w /path/to/params.txt -u "http://example.com/page?FUZZ=value"`
- **`Arjun`**: A tool designed to discover hidden GET and POST parameters.
    - Command: `python3 arjun.py -u "http://example.com" -m GET`

### Techniques:

- **Parameter Fuzzing**: Identify and test for common parameters like `id`, `user`, `page`, `admin`, `action`.
- **Hidden or Undocumented Parameters**: Use wordlists to discover additional parameters or those left over from development (e.g., `debug=true`).

### 6. **Taking Screenshots**

Automated screenshots help quickly visualize web pages or admin panels, especially when dealing with multiple subdomains or services.

### Tools:

- **`Eyewitness`**: Capture screenshots of web services and identify interesting ports or pages.
    - Command: `eyewitness --web --file subdomains.txt --no-prompt`
- **`Aquatone`**: Take screenshots of websites across subdomains.
    - Command: `cat subdomains.txt | aquatone -ports 80,443`
- **`GoWitness`**: Another simple tool to take screenshots of web pages.
    - Command: `gowitness file -f subdomains.txt`

### When to Use:

- **Subdomain Enumeration**: Automatically take screenshots of subdomains to quickly identify interesting endpoints (login panels, error pages).
- **After URL Enumeration**: Screenshots help in reviewing the output of directory brute-forcing.

### 7. **Content Discovery**

Discovering files like backups, configuration files, and credentials can lead to major breakthroughs.

### Tools:

- **Gobuster / Dirsearch**: Discover content like `.git`, `.htaccess`, `.env`, and backup files (e.g., `index.php.bak`, `config_old.php`).
- **GitDumper**: Extract a `.git` repository from a publicly exposed `.git` folder.
    - Command: `python gitdumper.py http://example.com/.git/ /path/to/save/`
- **Backup File Finder**: Hunt for backup files that could contain sensitive information.
    - Command: `ffuf -w /path/to/backup_files.txt -u http://example.com/FUZZ`

### 8. **Automating Recon**

Automation saves time and effort, especially when dealing with large scopes.

### Tools:

- **ReconFTW**: Automated recon tool that integrates multiple tools like Amass, Nmap, and Aquatone.
    - Command: `./reconftw.sh -d example.com`
- **LazyRecon**: A bash script that automates the entire recon process, including subdomain enumeration, screenshots, and URL discovery.
    - Command: `./lazyrecon.sh example.com`

---

### Summary

By following this comprehensive recon process, you can thoroughly map out the attack surface of your target, including discovering subdomains, open ports, hidden directories, sensitive parameters, and more. Each discovery during recon is a potential entry point or weak spot, so gathering as much information as possible in this phase is crucial for identifying vulnerabilities during the exploitation phase. Automating parts of your recon can also help when dealing with large scopes, making your work more efficient and scalable.
