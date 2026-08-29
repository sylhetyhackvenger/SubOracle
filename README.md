# Suboracle

<div align="center">

https://img.shields.io/badge/Python-3.6+-blue.svg
https://img.shields.io/badge/License-MIT-green.svg
https://img.shields.io/badge/Status-Active-brightgreen.svg
https://img.shields.io/badge/Version-Complete-red.svg

</div>

---

📖 Description

Suboracle is a comprehensive, feature-rich subdomain reconnaissance and security auditing tool built for cybersecurity professionals, penetration testers, and bug bounty hunters. This complete edition integrates over 25 specialized scanning modules to provide an unprecedented level of intelligence gathering for any target domain.

The tool performs exhaustive enumeration using multiple data sources including the Wayback Machine, HackerTarget API, and custom wordlist-based brute-forcing to discover subdomains that would otherwise remain hidden. It goes far beyond simple subdomain discovery by implementing advanced DNS enumeration across all record types (A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, CAA, DS, DNSKEY, and more), zone transfer attempts, and subdomain permutation generation to ensure maximum coverage.

Suboracle's security assessment capabilities are equally impressive, featuring comprehensive vulnerability scanning for XSS, SQL Injection, Local File Inclusion, Remote Code Execution, and Command Injection. The tool includes an extensive CVE database that automatically identifies known vulnerabilities in detected technologies, while the exploit checking module identifies potential attack vectors. Advanced features include WAF detection and bypass identification, SSL/TLS certificate analysis with security flaw detection, and comprehensive email security verification (SPF, DKIM, DMARC).

The tool excels in asset discovery with automated port scanning across 30+ common ports, technology fingerprinting to identify web servers, programming languages, and frameworks, API endpoint discovery, and hidden path enumeration. It detects cloud assets across major providers (AWS, GCP, Azure, DigitalOcean, Heroku, Vercel, Netlify, Cloudflare, and more), identifies subdomain takeover opportunities with 40+ fingerprint patterns, and maps the complete attack surface.

Modern security concerns are addressed through comprehensive security header analysis including HSTS, CSP, Feature Policy, Permissions Policy, and CORS configuration verification. The tool extracts and analyzes cookies, forms, JS files, CSS files, and images from every discovered subdomain. It can capture screenshots of live services, identify exposed backup files, Git repositories, and SVN folders, extract emails, perform reverse DNS lookups, gather BGP information, and retrieve WHOIS data.

The complete edition includes IP geolocation mapping, DNS history tracking, DNSSEC verification, CAA record analysis, and comprehensive reporting with SQLite database storage. With customizable threading (up to 50 concurrent threads), timeout controls, and verbose output, Suboracle provides security professionals with unparalleled visibility into their attack surface. All findings are stored in a structured database and presented in a beautifully formatted color-coded terminal output, making it an essential tool for any security assessment arsenal.

---

🎯 Complete Capabilities List 

🔍 Subdomain Discovery & Enumeration

· Wayback Machine Archives: Historical subdomain retrieval from 10+ years of web archives
· HackerTarget API: Real-time DNS search integration
· Commonspeak Wordlist: 200+ common subdomain prefixes
· Intelligent DNS Bruteforce: Multi-threaded resolution with custom wordlist
· Subdomain Permutation Generation: Automatic creation of developer, environment, and service subdomains
· Zone Transfer Attempts: AXFR and IXFR zone enumeration
· Live Subdomain Verification: HTTP/HTTPS reachability testing
· DNS Resolution: All record types including A, AAAA, CNAME, MX, TXT, NS, SOA, SRV

🛡️ Advanced Security Scanning

· Vulnerability Detection: XSS, SQL Injection, LFI, RCE, Command Injection, Directory Traversal
· CVE Database: 20+ known vulnerabilities with severity ratings (Critical, High, Medium, Low)
· Exploit Potential Analysis: 12+ exploit patterns with automated checking
· Security Headers Audit: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Feature Policy
· CORS Misconfiguration Detection: Wildcard origins and insecure configurations
· Email Security Verification: SPF, DKIM, DMARC with policy analysis
· WAF Detection: 12+ WAF provider signatures including Cloudflare, AWS WAF, Akamai, F5

🌐 DNS & Network Intelligence

· All DNS Record Types: A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, CAA, DS, DNSKEY, NAPTR, LOC, HINFO, RP, TLSA, SSHFP
· IPv4 & IPv6 Resolution: Dual-stack enumeration
· Reverse DNS Lookup: PTR record resolution
· BGP Information: ASN, prefix, and organization data
· DNS History Tracking: Historical record changes
· DNSSEC Verification: Algorithm and status detection
· CAA Record Analysis: Certificate Authority authorization policies

🖥️ Subdomain & Service Profiling

· Port Scanning: 30+ common ports including web, database, email, and management services
· Technology Fingerprinting: Server, framework, CMS, and programming language detection
· SSL/TLS Analysis: Certificate validation, issuer, validity period, cipher suite analysis
· API Endpoint Discovery: 15+ API path patterns
· Hidden Path Enumeration: 30+ common sensitive paths (.git, .env, admin, backup, etc.)
· Cloud Asset Detection: 12+ cloud providers with signature matching
· Subdomain Takeover Detection: 40+ takeover signatures

📊 Data Extraction & Analysis

· Email Extraction: Regex-based email harvesting from content and DNS records
· JavaScript Collection: Script file enumeration and source extraction
· CSS File Discovery: Style sheet detection and linking
· Image Analysis: Image resource identification and extraction
· Cookie Security Analysis: Secure, HttpOnly, SameSite flag verification
· Redirect Mapping: HTTP redirect chain analysis (301, 302, 303, 307, 308)
· Form Extraction: HTML form detection with method and action analysis

🎨 Enhanced Features

· Screenshot Capture: Visual confirmation using Selenium WebDriver
· IP Geolocation: Country, city, ISP, and organization mapping with Google Maps integration
· WHOIS Information: Registrar, creation date, expiration, nameservers, organization data
· Security.txt Detection: Contact and security policy information
· Robots.txt & Sitemap Analysis: Crawl directives and site structure
· Git/SVN Repository Detection: Source code exposure identification
· Backup File Discovery: Common backup patterns and extensions
· GDPR/Cookie Consent Detection: Privacy policy compliance checking

🗄️ Data Management & Reporting

· SQLite Database: Structured storage of all findings
· Color-Coded Terminal Output: Enhanced readability and visualization
· Detailed Statistics: 40+ metrics including requests, errors, and found items
· Comprehensive Report Generation: Organized summary with all discovered assets
· CSV Export Ready: Database structure supports easy data extraction

---

🛡️ Importance in Gray Hat Cybersecurity

Suboracle serves as a critical asset for gray hat cybersecurity professionals who operate in the ethical space between black and white hat hacking. The tool provides defenders with attacker-like capabilities to identify, analyze, and secure potential vulnerabilities before malicious actors can exploit them.

For Defensive Security Teams, Suboracle enables proactive attack surface management by discovering unknown assets, identifying misconfigurations, and verifying security controls. Regular scanning with the tool helps organizations maintain continuous visibility of their external exposure, ensuring no subdomain becomes an entry point for attackers. The comprehensive vulnerability detection helps prioritize remediation efforts based on severity levels.

Bug Bounty Hunters leverage Suboracle to efficiently map target scopes, identify overlooked subdomains, and discover potential vulnerabilities. The tool's multi-source enumeration approach ensures maximum coverage, while the takeover detection and vulnerability scanning help identify high-value findings that lead to successful bounty submissions.

For Penetration Testers, the tool accelerates reconnaissance phases, providing comprehensive information that guides deeper testing. The DNS enumeration, port scanning, and technology fingerprinting help identify attack surfaces, while the security header analysis and CVE detection highlight immediate risks.

Compliance Auditors benefit from Suboracle's ability to verify security controls across all organizational assets. The tool checks for proper implementation of security headers, email security protocols (SPF, DKIM, DMARC), and SSL/TLS best practices, helping organizations meet regulatory requirements like PCI DSS, HIPAA, and GDPR.

Security Researchers use Suboracle to study attack patterns, identify emerging threats, and understand how modern organizations expose themselves. The DNS history tracking, cloud asset detection, and technology fingerprinting provide valuable data for threat intelligence and research publications.

The tool promotes the gray hat philosophy of using offensive capabilities for defensive purposes, helping create a safer internet ecosystem. By identifying vulnerabilities and securely disclosing them to responsible parties, Suboracle users contribute to global cybersecurity while operating within legal and ethical boundaries.

---

✅ Advantages

Technical Advantages

· Comprehensive Coverage: 25+ scanning modules covering every aspect of subdomain reconnaissance
· High Performance: Configurable threading (up to 50 concurrent threads) for fast scanning
· Multi-Source Intelligence: Combines multiple data sources for maximum discovery
· Real-Time Verification: Every subdomain is validated through DNS resolution and HTTP/HTTPS checks
· Zero False Positives: Live verification ensures only real assets are reported
· Extensible Architecture: Easy to add new wordlists, signatures, and scanning modules
· Intelligent Rate Limiting: Built-in delays and retry mechanisms prevent overwhelming targets
· Session Management: Persistent session handling with automatic cookie management
· Connection Pooling: Efficient network resource utilization
· Error Recovery: Graceful handling of network errors and timeouts

User Experience Advantages

· Beautiful Color Output: Enhanced readability with color-coded results
· Verbose Mode: Complete transparency of all operations
· Progressive Display: Real-time results during scanning
· Customizable Parameters: Thread count, timeout, and verbosity level control
· Database Storage: SQLite for persistent results and easy querying
· Comprehensive Reports: Organized summary with statistics and details
· No External Dependencies (Core): Works with standard Python libraries
· Cross-Platform: Runs on Windows, Linux, and macOS
· Lightweight Installation: Minimal setup requirements
· CLI Focused: Designed for professional security workflows

Security Advantages

· Early Vulnerability Detection: Identifies issues before attackers find them
· Attack Surface Mapping: Complete visibility of external exposure
· Automated Scanning: Consistent and repeatable security checks
· Risk Prioritization: Severity-based vulnerability classification
· Compliance Support: Helps meet security framework requirements
· Takeover Prevention: Identifies vulnerable subdomains that could be hijacked
· Visibility into Shadow IT: Discovers unknown assets deployed by teams
· Secure Configuration Auditing: Verifies proper implementation of security controls

Operational Advantages

· Time-Efficient: Automates hours of manual reconnaissance
· Cost-Effective: Free and open-source with professional-grade features
· Learning Resource: Educational tool for understanding reconnaissance methodologies
· Integration Ready: SQLite database supports integration with other tools
· Continuous Monitoring: Can be scheduled for regular security assessments
· Team Collaboration: Standardized reports facilitate sharing findings
· Scalable: Handles small to enterprise-scale domains efficiently

---

⚠️ Disadvantages

Technical Limitations

· Resource Intensive: CPU and memory usage scales with thread count and domain size
· Network Dependency: Requires stable internet connection for most features
· False Positives (Limited): Some vulnerability detections require manual verification
· No API Key Integration: Some features (DNS history) limited by demo API keys
· Screenshots Setup Complexity: Requires Selenium and Chrome WebDriver installation
· Browser Dependency: Screenshot feature requires Chrome browser
· Limited Exploitation: Identifies potential exploits but doesn't execute them
· No Built-in Proxy Support: Must use system-level proxy configuration
· Rate Limiting Challenges: May trigger target security measures with aggressive settings
· Single Target Processing: Designed for focused domain analysis

Operational Constraints

· Time-Consuming: Comprehensive scans can take 30+ minutes for large domains
· Legal Restrictions: Must have authorization to scan targets
· Ethical Considerations: Requires responsible use and disclosure practices
· Knowledge Requirement: Understanding of reconnaissance principles beneficial
· False Confidence: Automated tools should complement manual analysis
· Environmental Factors: Performance varies based on network conditions

Feature Limitations

· No GUI: Command-line interface may not suit all users
· Limited Deep Scanning: Provides broad coverage but lacks deep application-layer testing
· No Exploitation Framework: Identifies vulnerabilities but doesn't validate through exploitation
· Basic Reporting: Lacks advanced visualization and analytics features
· No Auto-Remediation: Identifies issues but doesn't automatically fix them
· Limited Integration: No built-in integration with vulnerability management platforms
· Basic Authentication Handling: Limited support for authenticated scanning

Usage Challenges

· Noisy Scanning: May trigger IDS/IPS alerts on monitored networks
· IP Reputation Impact: Scanning can affect source IP reputation
· Rate Limiting Vulnerability: Aggressive scanning may cause denial of service
· Legal Documentation: Requires proper authorization documentation
· Skill Curve: Advanced features require understanding of DNS and web security concepts

---

🚀 Quick Start

```bash
# Installation
git clone https://github.com/sylhetyhackvenger/SubOracle 
cd SubOracle 
pip install -r requirements.txt

# Basic Usage
python suboracle.py example.com

# Advanced Usage with Custom Settings
python suboracle.py example.com 50 20

# Screenshots Feature (Optional)
pip install selenium
# Download Chrome WebDriver from: https://chromedriver.chromium.org/
```

Command Line Options

```bash
python suboracle.py <domain> [threads] [timeout]

Arguments:
  domain    Target domain (e.g., example.com)
  threads   Number of concurrent threads (default: 30, max: 50)
  timeout   Request timeout in seconds (default: 15)
```

---

📄 Legal Notice

IMPORTANT: This tool is designed for educational purposes, authorized security testing, and research only.

· ✅ Use only on domains you own
· ✅ Use on domains where you have explicit written permission
· ✅ Use for improving security of legitimate organizations
· ❌ DO NOT use on unauthorized targets
· ❌ DO NOT use for malicious purposes
· ❌ DO NOT use for data exfiltration or exploitation

The author assumes no liability for any misuse of this tool. Users are solely responsible for complying with applicable laws and regulations.

---

🤝 Contributing

We welcome contributions to improve Suboracle! Here's how you can help:

1. Report Bugs: Open an issue with detailed information
2. Suggest Features: Share ideas for new capabilities
3. Submit PRs: Code improvements and new modules
4. Wordlist Contributions: Add new subdomain prefixes and takeover patterns
5. Documentation: Help improve user guides and examples
6. Testing: Test the tool and provide feedback

Development Setup

```bash
git clone https://github.com/sylhetyhackvenger/SubOracle 
cd SubOracle 
pip install -r requirements-dev.txt
```

---

📁 Project Structure

```
SubOracle/
├── suboracle.py          # Main tool script
├── requirements.txt      # Python dependencies
├── README.md            # This file
├── LICENSE              # MIT License
```

---

🌟 Acknowledgments

· Security Community: For continuous feedback and improvements
· Open Source Libraries: requests, dnspython, python-whois, selenium
· API Providers: HackerTarget, Wayback Machine, SecurityTrails
· Bug Bounty Community: For real-world testing and validation
· Ethical Hackers: Who use the tool responsibly to improve security

---

📞 Connect

· Author: SYLHETYHACKVENGER (THE-ERROR808)

---

<div align="center">

Made with ❤️ for the Cybersecurity Community

Secure today, protect tomorrow

</div>
