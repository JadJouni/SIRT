# **Security Intelligence & Reconnaissance Tool (SIRT)**


#### **Description:**

**SIRT (Security Intelligence & Reconnaissance Tool)** is a command-line utility developed as a final project for CS50P. This tool serves two primary purposes: evaluating the security posture of web servers through HTTP header analysis and protecting user identity through credential breach auditing. The results can be saved to a file via a special command.

### **Core Functionalities**

SIRT is built upon three modular pillars:

1. **Input Validation (validate\_input)**: Utilizing the re module, this function ensures that all user-provided data (URLs for web auditing and strings for password checks) conforms to expected formats.
2. **Credential Breach Audit (check\_password\_breach)**: This module implements a privacy-preserving protocol known as **k-anonymity**. By hashing a password locally using SHA-1 and only transmitting the first five characters of that hash to the "Have I Been Pwned" API, SIRT can verify if a password has been leaked in a data breach without ever exposing the original password to the internet.
3. **Web Security Auditor (audit\_web\_headers)**: This function performs a non-invasive scan of a target URL. By requesting only the HTTP headers (using the HEAD method), it evaluates whether the site has enabled critical defenses such as HSTS (Strict-Transport-Security), CSP (Content-Security-Policy),and clickjacking protections. This gives the user an immediate assessment of a site's vulnerability to common web-based attacks.

### **How to use**

When running the file project.py , a list of commands are presented:

*   \-h, \--help         :   show this help message and exit
*   \-u, \--url URL       :  URL to audit web headers
*   \-p, \--password    : Password to check for breaches
*   \-o, \--output  :  Output file to save results

**For example if you wanted to check if a password is breached or not, simply run:**

python project.py \-p \<password\>

**Additionally, if you need to save the report to a file run:**

python project.py \-p \<password\> \-o \<name of the file\>




