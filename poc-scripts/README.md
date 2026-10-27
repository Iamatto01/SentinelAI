# 🛡️ SentinelAI — Standalone PoC Exploit & Security Probing Library

Koleksi lengkap **Proof-of-Concept (PoC)** dan skrip probing keselamatan yang diekstrak daripada enjin SentinelAI.
Semua skrip ini boleh dijalankan secara **kendiri (*standalone*)** menggunakan terminal Kali Linux, Ubuntu, atau Git Bash.

## 🚀 Cara Penggunaan (Quick Start)

### 1. Jalankan Skrip Individu
Setiap skrip menerima URL sasaran sebagai parameter pertama:
```bash
# Contoh: Uji pendedahan folder .git
bash poc-scripts/01_information_disclosure/exposed-git-repository.sh https://target.com

# Contoh: Uji SQL Injection (Error-Based)
bash poc-scripts/02_injection_flaws/sql-injection-error-based-probe.sh https://target.com

# Contoh: Uji Admin Panel Discovery
bash poc-scripts/03_access_control_and_auth/admin-panel-discovery.sh https://target.com
```

### 2. Jalankan Kategori Sekaligus Menggunakan Master Runner
```bash
# Jalankan semua skrip dalam satu kategori:
bash poc-scripts/run_all.sh https://target.com 01_information_disclosure

# Jalankan kesemua 103 PoC secara berperingkat:
bash poc-scripts/run_all.sh https://target.com all
```

---

## 📂 Struktur Direktori & Katalog PoC

### 📁 `01_information_disclosure/` — Information & Sensitive Data Disclosure (19 skrip)
| Skrip File | Nama Kelemahan | Keterangan | Tahap Bahaya |
|:---|:---|:---|:---|
| [`backup-archive-file-exposure-25-paths.sh`](01_information_disclosure/backup-archive-file-exposure-25-paths.sh) | **Backup & Archive File Exposure (25 paths)** | Batch-checks for exposed backup files (.bak, .sql, .zip, .tar.gz, .7z) | `HIGH` |
| [`ci-cd-pipeline-exposure-jenkins-gitlab-github-actions-drone.sh`](01_information_disclosure/ci-cd-pipeline-exposure-jenkins-gitlab-github-actions-drone.sh) | **CI/CD Pipeline Exposure (Jenkins/GitLab/GitHub Actions/Drone)** | Detects exposed CI/CD consoles and build systems | `CRITICAL` |
| [`database-dump-sql-file-exposure.sh`](01_information_disclosure/database-dump-sql-file-exposure.sh) | **Database Dump & SQL File Exposure** | Checks for exposed SQL dumps, CSV exports, and data files | `CRITICAL` |
| [`editor-temp-file-exposure.sh`](01_information_disclosure/editor-temp-file-exposure.sh) | **Editor & Temp File Exposure** | Checks for vim swap, emacs backup, nano temp files | `MEDIUM` |
| [`elasticsearch-opensearch-unauthenticated-access.sh`](01_information_disclosure/elasticsearch-opensearch-unauthenticated-access.sh) | **Elasticsearch/OpenSearch Unauthenticated Access** | Direct check for open Elasticsearch cluster — data dump risk | `CRITICAL` |
| [`environment-config-file-exposure-20-paths.sh`](01_information_disclosure/environment-config-file-exposure-20-paths.sh) | **Environment & Config File Exposure (20 paths)** | Batch-checks 20 common config/env file paths for public accessibility | `MEDIUM` |
| [`exposed-.git-repository.sh`](01_information_disclosure/exposed-.git-repository.sh) | **Exposed .git Repository** | Checks for readable .git directory — full source code + history disclosure | `HIGH` |
| [`exposed-.hg-repository-mercurial.sh`](01_information_disclosure/exposed-.hg-repository-mercurial.sh) | **Exposed .hg Repository (Mercurial)** | Checks for readable .hg directory | `MEDIUM` |
| [`exposed-.svn-repository.sh`](01_information_disclosure/exposed-.svn-repository.sh) | **Exposed .svn Repository** | Checks for readable .svn directory — Subversion metadata disclosure | `MEDIUM` |
| [`graphql-introspection-depth-attack.sh`](01_information_disclosure/graphql-introspection-depth-attack.sh) | **GraphQL Introspection & Depth Attack** | Tests GraphQL introspection query and schema dump | `MEDIUM` |
| [`information-disclosure-pages-15-paths.sh`](01_information_disclosure/information-disclosure-pages-15-paths.sh) | **Information Disclosure Pages (15 paths)** | Checks for phpinfo, server-status, actuator, debug pages | `HIGH` |
| [`laravel-security-audit-8-checks.sh`](01_information_disclosure/laravel-security-audit-8-checks.sh) | **Laravel Security Audit (8 checks)** | .env exposure, APP_KEY leak, debug mode, storage symlink, telescope | `HIGH` |
| [`log-file-exposure-deep-scan.sh`](01_information_disclosure/log-file-exposure-deep-scan.sh) | **Log File Exposure (deep scan)** | Checks for exposed log files — credentials, tokens, internal paths | `HIGH` |
| [`next.js-nuxt.js-spa-security-checks.sh`](01_information_disclosure/next.js-nuxt.js-spa-security-checks.sh) | **Next.js/Nuxt.js SPA Security Checks** | Detects build manifests, source maps, and API route exposure | `MEDIUM` |
| [`node.js-source-map-exposure.sh`](01_information_disclosure/node.js-source-map-exposure.sh) | **Node.js Source Map Exposure** | Detects exposed .js.map files — full original source code disclosure | `HIGH` |
| [`os-metadata-file-exposure-.ds_store-thumbs.db-desktop.ini.sh`](01_information_disclosure/os-metadata-file-exposure-.ds_store-thumbs.db-desktop.ini.sh) | **OS Metadata File Exposure (.DS_Store, Thumbs.db, desktop.ini)** | Detects macOS/Windows metadata files that leak directory structure | `MEDIUM` |
| [`robots.txt-sensitive-path-discovery.sh`](01_information_disclosure/robots.txt-sensitive-path-discovery.sh) | **Robots.txt Sensitive Path Discovery** | Parses robots.txt for Disallowed paths that reveal hidden functionality | `INFO` |
| [`spring-boot-actuator-full-audit.sh`](01_information_disclosure/spring-boot-actuator-full-audit.sh) | **Spring Boot Actuator Full Audit** | Deep actuator scan — env, heapdump, mappings, beans, trace endpoints | `CRITICAL` |
| [`package.json-dependency-disclosure.sh`](01_information_disclosure/package.json-dependency-disclosure.sh) | **package.json & Dependency Disclosure** | Checks for exposed package.json, composer.json, Gemfile — dependency enumeration | `LOW` |

### 📁 `02_injection_flaws/` — Injection Flaws (SQLi, XSS, Command, SSTI, XXE) (12 skrip)
| Skrip File | Nama Kelemahan | Keterangan | Tahap Bahaya |
|:---|:---|:---|:---|
| [`command-injection-probe-time-based.sh`](02_injection_flaws/command-injection-probe-time-based.sh) | **Command Injection Probe (time-based)** | Tests for OS command injection via sleep delay detection | `CRITICAL` |
| [`html-injection-via-404-page.sh`](02_injection_flaws/html-injection-via-404-page.sh) | **HTML Injection via 404 Page** | Tests if 404 pages reflect user input without encoding | `MEDIUM` |
| [`http-parameter-pollution-probe.sh`](02_injection_flaws/http-parameter-pollution-probe.sh) | **HTTP Parameter Pollution Probe** | Tests duplicate parameter handling for logic bypass | `MEDIUM` |
| [`host-header-injection.sh`](02_injection_flaws/host-header-injection.sh) | **Host Header Injection** | Tests for host header injection — cache poisoning, password reset poisoning | `MEDIUM` |
| [`insecure-deserialization-probe-php-java-python.sh`](02_injection_flaws/insecure-deserialization-probe-php-java-python.sh) | **Insecure Deserialization Probe (PHP/Java/Python)** | Tests for serialized object injection points | `HIGH` |
| [`local-file-inclusion-probe-10-params.sh`](02_injection_flaws/local-file-inclusion-probe-10-params.sh) | **Local File Inclusion Probe (10 params)** | Tests for LFI via /etc/passwd retrieval | `CRITICAL` |
| [`nosql-injection-probe-mongodb.sh`](02_injection_flaws/nosql-injection-probe-mongodb.sh) | **NoSQL Injection Probe (MongoDB)** | Tests for MongoDB operator injection in JSON endpoints | `HIGH` |
| [`prototype-pollution-probe-client-side.sh`](02_injection_flaws/prototype-pollution-probe-client-side.sh) | **Prototype Pollution Probe (client-side)** | Checks JS for __proto__ handling and DOM XSS sinks | `MEDIUM` |
| [`reflected-xss-probe-12-params.sh`](02_injection_flaws/reflected-xss-probe-12-params.sh) | **Reflected XSS Probe (12 params)** | Sends XSS canary to common parameters and checks for reflection | `HIGH` |
| [`sql-injection-error-based-probe-15-params.sh`](02_injection_flaws/sql-injection-error-based-probe-15-params.sh) | **SQL Injection Error-Based Probe (15 params)** | Sends SQLi payloads to common parameters and checks for database errors | `HIGH` |
| [`ssti-server-side-template-injection-probe.sh`](02_injection_flaws/ssti-server-side-template-injection-probe.sh) | **SSTI (Server-Side Template Injection) Probe** | Tests for template injection via math expression evaluation | `CRITICAL` |
| [`xxe-injection-probe.sh`](02_injection_flaws/xxe-injection-probe.sh) | **XXE Injection Probe** | Tests XML endpoints for external entity injection | `HIGH` |

### 📁 `03_access_control_and_auth/` — Broken Access Control & Authentication (21 skrip)
| Skrip File | Nama Kelemahan | Keterangan | Tahap Bahaya |
|:---|:---|:---|:---|
| [`api-rate-limiting-test.sh`](03_access_control_and_auth/api-rate-limiting-test.sh) | **API Rate Limiting Test** | Burst tests API endpoints for rate limiting | `MEDIUM` |
| [`admin-panel-discovery-30-paths.sh`](03_access_control_and_auth/admin-panel-discovery-30-paths.sh) | **Admin Panel Discovery (30 paths)** | Batch-checks 30 common admin panel URLs | `INFO` |
| [`authentication-timing-side-channel.sh`](03_access_control_and_auth/authentication-timing-side-channel.sh) | **Authentication Timing Side-Channel** | Measures response time differential for valid vs invalid usernames | `MEDIUM` |
| [`cookie-security-audit.sh`](03_access_control_and_auth/cookie-security-audit.sh) | **Cookie Security Audit** | Checks cookies for Secure, HttpOnly, SameSite flags | `MEDIUM` |
| [`cookie-security-deep-audit.sh`](03_access_control_and_auth/cookie-security-deep-audit.sh) | **Cookie Security Deep Audit** | Analyzes all cookies for flags, scope, and session patterns | `MEDIUM` |
| [`coupon-discount-code-enumeration.sh`](03_access_control_and_auth/coupon-discount-code-enumeration.sh) | **Coupon/Discount Code Enumeration** | Tests for predictable or enumerable discount codes | `MEDIUM` |
| [`database-admin-interfaces-exposure.sh`](03_access_control_and_auth/database-admin-interfaces-exposure.sh) | **Database Admin Interfaces Exposure** | Detects phpMyAdmin, Adminer, pgAdmin, Mongo Express, Redis Commander | `CRITICAL` |
| [`docker-api-exposure.sh`](03_access_control_and_auth/docker-api-exposure.sh) | **Docker API Exposure** | Detects unauthenticated Docker daemon — instant host takeover | `CRITICAL` |
| [`graphql-mutation-depth-abuse.sh`](03_access_control_and_auth/graphql-mutation-depth-abuse.sh) | **GraphQL Mutation & Depth Abuse** | Tests for mutations without auth and deep query DoS | `HIGH` |
| [`idor-bola-indicator-probe.sh`](03_access_control_and_auth/idor-bola-indicator-probe.sh) | **IDOR / BOLA Indicator Probe** | Tests sequential resource IDs for access control | `HIGH` |
| [`jwt-algorithm-confusion-none-hs256.sh`](03_access_control_and_auth/jwt-algorithm-confusion-none-hs256.sh) | **JWT Algorithm Confusion (none/HS256)** | Tests JWT for alg:none acceptance and weak HMAC keys | `HIGH` |
| [`jwt-security-analysis.sh`](03_access_control_and_auth/jwt-security-analysis.sh) | **JWT Security Analysis** | Finds JWT tokens in responses and checks for weak configurations | `MEDIUM` |
| [`login-rate-limiting-test.sh`](03_access_control_and_auth/login-rate-limiting-test.sh) | **Login Rate Limiting Test** | Burst of failed logins to check for 429/CAPTCHA/lockout | `MEDIUM` |
| [`management-interface-port-scan.sh`](03_access_control_and_auth/management-interface-port-scan.sh) | **Management Interface Port Scan** | Scans non-standard ports for admin panels and management UIs | `HIGH` |
| [`mass-assignment-probe.sh`](03_access_control_and_auth/mass-assignment-probe.sh) | **Mass Assignment Probe** | Tests if extra fields in registration/update are accepted | `HIGH` |
| [`oauth-oidc-misconfiguration-probe.sh`](03_access_control_and_auth/oauth-oidc-misconfiguration-probe.sh) | **OAuth/OIDC Misconfiguration Probe** | Tests redirect_uri validation and state parameter on OAuth flows | `HIGH` |
| [`password-reset-flow-abuse.sh`](03_access_control_and_auth/password-reset-flow-abuse.sh) | **Password Reset Flow Abuse** | Tests reset tokens for predictability and user enumeration | `HIGH` |
| [`price-amount-manipulation-probe.sh`](03_access_control_and_auth/price-amount-manipulation-probe.sh) | **Price/Amount Manipulation Probe** | Tests for negative, zero, and float amounts in API parameters | `HIGH` |
| [`session-token-entropy-analysis.sh`](03_access_control_and_auth/session-token-entropy-analysis.sh) | **Session Token Entropy Analysis** | Collects session cookies and checks for predictability | `HIGH` |
| [`user-enumeration-via-login-response.sh`](03_access_control_and_auth/user-enumeration-via-login-response.sh) | **User Enumeration via Login Response** | Differential response analysis on login endpoints | `MEDIUM` |
| [`web-cache-deception-probe.sh`](03_access_control_and_auth/web-cache-deception-probe.sh) | **Web Cache Deception Probe** | Tests for cacheable authenticated pages with extension suffixes | `HIGH` |

### 📁 `04_network_and_infra/` — Network, Cloud & Infrastructure Security (10 skrip)
| Skrip File | Nama Kelemahan | Keterangan | Tahap Bahaya |
|:---|:---|:---|:---|
| [`certificate-transparency-subdomain-discovery.sh`](04_network_and_infra/certificate-transparency-subdomain-discovery.sh) | **Certificate Transparency Subdomain Discovery** | Queries crt.sh for all subdomains from certificate logs | `INFO` |
| [`cloud-storage-bucket-discovery.sh`](04_network_and_infra/cloud-storage-bucket-discovery.sh) | **Cloud Storage Bucket Discovery** | Finds S3/Azure/GCS buckets referenced in page source | `HIGH` |
| [`cloud-storage-misconfiguration.sh`](04_network_and_infra/cloud-storage-misconfiguration.sh) | **Cloud Storage Misconfiguration** | Checks for exposed S3 buckets, Azure blobs, GCS via common URL patterns | `HIGH` |
| [`common-service-port-scan-top-20.sh`](04_network_and_infra/common-service-port-scan-top-20.sh) | **Common Service Port Scan (top 20)** | TCP connect scan on high-risk ports — management, DB, mail | `HIGH` |
| [`dns-security-audit-spf-dmarc-dkim.sh`](04_network_and_infra/dns-security-audit-spf-dmarc-dkim.sh) | **DNS Security Audit (SPF/DMARC/DKIM)** | Checks email spoofing protections — SPF, DMARC, DKIM records | `MEDIUM` |
| [`dns-zone-transfer-attempt.sh`](04_network_and_infra/dns-zone-transfer-attempt.sh) | **DNS Zone Transfer Attempt** | Tests for AXFR — full DNS zone disclosure | `HIGH` |
| [`kubernetes-dashboard-api-exposure.sh`](04_network_and_infra/kubernetes-dashboard-api-exposure.sh) | **Kubernetes Dashboard & API Exposure** | Detects open kubelet, dashboard, API server, etcd | `CRITICAL` |
| [`subdomain-takeover-check-cname-based.sh`](04_network_and_infra/subdomain-takeover-check-cname-based.sh) | **Subdomain Takeover Check (CNAME-based)** | Checks dangling CNAMEs pointing to takeover-able services | `HIGH` |
| [`subdomain-takeover-indicators.sh`](04_network_and_infra/subdomain-takeover-indicators.sh) | **Subdomain Takeover Indicators** | Checks CNAME records for takeover-vulnerable services | `HIGH` |
| [`wildcard-dns-detection.sh`](04_network_and_infra/wildcard-dns-detection.sh) | **Wildcard DNS Detection** | Checks if domain resolves arbitrary subdomains — affects subdomain bruteforce validity | `INFO` |

### 📁 `05_misconfigurations/` — Web Server & HTTP Misconfigurations (17 skrip)
| Skrip File | Nama Kelemahan | Keterangan | Tahap Bahaya |
|:---|:---|:---|:---|
| [`cors-preflight-method-abuse.sh`](05_misconfigurations/cors-preflight-method-abuse.sh) | **CORS Preflight & Method Abuse** | Tests preflight handling and method allowlist enforcement | `MEDIUM` |
| [`cors-wildcard-misconfiguration.sh`](05_misconfigurations/cors-wildcard-misconfiguration.sh) | **CORS Wildcard Misconfiguration** | Tests for Access-Control-Allow-Origin: * and credential reflection | `MEDIUM` |
| [`csp-deep-analysis.sh`](05_misconfigurations/csp-deep-analysis.sh) | **CSP Deep Analysis** | Parses CSP header for unsafe directives and bypass vectors | `MEDIUM` |
| [`clickjacking-ui-redressing.sh`](05_misconfigurations/clickjacking-ui-redressing.sh) | **Clickjacking (UI Redressing)** | Tests if the site can be embedded in an iframe | `MEDIUM` |
| [`cross-origin-resource-sharing-preflight-abuse.sh`](05_misconfigurations/cross-origin-resource-sharing-preflight-abuse.sh) | **Cross-Origin Resource Sharing Preflight Abuse** | Deep CORS test — preflight method/header allowlist analysis | `MEDIUM` |
| [`dangerous-http-methods-enabled.sh`](05_misconfigurations/dangerous-http-methods-enabled.sh) | **Dangerous HTTP Methods Enabled** | Tests for TRACE, TRACK, PUT, DELETE, CONNECT methods | `MEDIUM` |
| [`default-installation-pages-12-paths.sh`](05_misconfigurations/default-installation-pages-12-paths.sh) | **Default Installation Pages (12 paths)** | Detects unconfigured software — default Apache/Nginx/IIS pages, installers | `HIGH` |
| [`directory-listing-enabled.sh`](05_misconfigurations/directory-listing-enabled.sh) | **Directory Listing Enabled** | Checks common directories for index listing | `MEDIUM` |
| [`http-request-smuggling-cl.te-probe.sh`](05_misconfigurations/http-request-smuggling-cl.te-probe.sh) | **HTTP Request Smuggling CL.TE Probe** | Tests for Content-Length + Transfer-Encoding desync | `HIGH` |
| [`http-request-smuggling-indicators.sh`](05_misconfigurations/http-request-smuggling-indicators.sh) | **HTTP Request Smuggling Indicators** | Detects CL.TE / TE.CL discrepancies via differential responses | `HIGH` |
| [`https-redirect-tls-enforcement.sh`](05_misconfigurations/https-redirect-tls-enforcement.sh) | **HTTPS Redirect & TLS Enforcement** | Verifies HTTP→HTTPS redirect and HSTS preload readiness | `MEDIUM` |
| [`open-redirect-vulnerability-10-params.sh`](05_misconfigurations/open-redirect-vulnerability-10-params.sh) | **Open Redirect Vulnerability (10 params)** | Tests common redirect parameters for unvalidated redirects | `MEDIUM` |
| [`security-headers-audit-8-headers.sh`](05_misconfigurations/security-headers-audit-8-headers.sh) | **Security Headers Audit (8 headers)** | Checks for 8 critical security headers on the main page | `LOW` |
| [`tls-ssl-security-audit.sh`](05_misconfigurations/tls-ssl-security-audit.sh) | **TLS/SSL Security Audit** | Checks for weak protocols, expired certs, and mixed content | `MEDIUM` |
| [`technology-version-disclosure.sh`](05_misconfigurations/technology-version-disclosure.sh) | **Technology Version Disclosure** | Checks headers and pages for version numbers that aid targeted attacks | `LOW` |
| [`web-cache-poisoning-indicators.sh`](05_misconfigurations/web-cache-poisoning-indicators.sh) | **Web Cache Poisoning Indicators** | Tests unkeyed headers for cache poisoning potential | `HIGH` |
| [`web-server-cdn-fingerprint.sh`](05_misconfigurations/web-server-cdn-fingerprint.sh) | **Web Server & CDN Fingerprint** | Identifies server software, CDN, and hosting from response headers | `INFO` |

### 📁 `06_framework_and_api/` — Framework & API Security (Laravel, WordPress, Spring, GraphQL) (24 skrip)
| Skrip File | Nama Kelemahan | Keterangan | Tahap Bahaya |
|:---|:---|:---|:---|
| [`api-documentation-exposure.sh`](06_framework_and_api/api-documentation-exposure.sh) | **API Documentation Exposure** | Detects unprotected Swagger/OpenAPI/GraphiQL docs | `MEDIUM` |
| [`api-endpoint-discovery-20-paths.sh`](06_framework_and_api/api-endpoint-discovery-20-paths.sh) | **API Endpoint Discovery (20 paths)** | Discovers exposed API endpoints — REST, GraphQL, Swagger, gRPC | `INFO` |
| [`api-gateway-microservice-discovery.sh`](06_framework_and_api/api-gateway-microservice-discovery.sh) | **API Gateway & Microservice Discovery** | Maps API gateways, service meshes, and internal routing | `MEDIUM` |
| [`asp.net-security-checks.sh`](06_framework_and_api/asp.net-security-checks.sh) | **ASP.NET Security Checks** | Detects ASP.NET debug traces, viewstate, and machine key leaks | `HIGH` |
| [`django-debug-mode-static-exposure.sh`](06_framework_and_api/django-debug-mode-static-exposure.sh) | **Django Debug Mode & Static Exposure** | Detects DEBUG=True, exposed settings, collectstatic misconfig | `HIGH` |
| [`email-address-harvesting-from-pages.sh`](06_framework_and_api/email-address-harvesting-from-pages.sh) | **Email Address Harvesting from Pages** | Extracts email patterns from public pages for phishing assessment | `INFO` |
| [`file-upload-content-type-bypass.sh`](06_framework_and_api/file-upload-content-type-bypass.sh) | **File Upload Content-Type Bypass** | Tests if server validates file content vs declared type | `HIGH` |
| [`file-upload-endpoint-discovery.sh`](06_framework_and_api/file-upload-endpoint-discovery.sh) | **File Upload Endpoint Discovery** | Finds file upload forms and endpoints | `INFO` |
| [`file-upload-validation-test.sh`](06_framework_and_api/file-upload-validation-test.sh) | **File Upload Validation Test** | Tests upload endpoints with dangerous file types | `HIGH` |
| [`graphql-field-suggestion-abuse.sh`](06_framework_and_api/graphql-field-suggestion-abuse.sh) | **GraphQL Field Suggestion Abuse** | Exploits GraphQL error suggestions for schema enumeration | `MEDIUM` |
| [`http-protocol-version-features.sh`](06_framework_and_api/http-protocol-version-features.sh) | **HTTP Protocol Version & Features** | Checks HTTP/2 support, connection handling, keep-alive | `INFO` |
| [`java-websphere-jboss-tomcat-exposure.sh`](06_framework_and_api/java-websphere-jboss-tomcat-exposure.sh) | **Java WebSphere/JBoss/Tomcat Exposure** | Detects exposed manager apps, WAR deployers, JMX consoles | `CRITICAL` |
| [`node.js-error-stack-trace-disclosure.sh`](06_framework_and_api/node.js-error-stack-trace-disclosure.sh) | **Node.js Error Stack Trace Disclosure** | Probes for stack traces revealing file paths and framework internals | `MEDIUM` |
| [`php-backdoor-webshell-detection.sh`](06_framework_and_api/php-backdoor-webshell-detection.sh) | **PHP Backdoor & Webshell Detection** | Scans for common webshell filenames | `CRITICAL` |
| [`php-configuration-exposure.sh`](06_framework_and_api/php-configuration-exposure.sh) | **PHP Configuration Exposure** | Checks for exposed .user.ini, .htaccess, php.ini files | `MEDIUM` |
| [`php-info-debug-pages.sh`](06_framework_and_api/php-info-debug-pages.sh) | **PHP Info & Debug Pages** | Detects phpinfo, phpinfo.php, info.php, and debug pages | `HIGH` |
| [`pwa-manifest-metadata-exposure.sh`](06_framework_and_api/pwa-manifest-metadata-exposure.sh) | **PWA Manifest & Metadata Exposure** | Extracts tech stack and internal URLs from manifest files | `INFO` |
| [`python-wsgi-flask-exposure.sh`](06_framework_and_api/python-wsgi-flask-exposure.sh) | **Python WSGI/Flask Exposure** | Detects Flask debug console (Werkzeug), exposed .pyc, console pin attempts | `CRITICAL` |
| [`ruby-on-rails-security-checks.sh`](06_framework_and_api/ruby-on-rails-security-checks.sh) | **Ruby on Rails Security Checks** | Detects Rails footprints, exposed routes, and console | `HIGH` |
| [`ssrf-indicator-probe.sh`](06_framework_and_api/ssrf-indicator-probe.sh) | **SSRF Indicator Probe** | Tests parameters that might fetch URLs server-side | `HIGH` |
| [`service-worker-security-audit.sh`](06_framework_and_api/service-worker-security-audit.sh) | **Service Worker Security Audit** | Checks for exposed service workers and scope issues | `MEDIUM` |
| [`websocket-endpoint-discovery-origin-test.sh`](06_framework_and_api/websocket-endpoint-discovery-origin-test.sh) | **WebSocket Endpoint Discovery & Origin Test** | Finds WebSocket endpoints and tests origin validation | `HIGH` |
| [`websocket-endpoint-security.sh`](06_framework_and_api/websocket-endpoint-security.sh) | **WebSocket Endpoint Security** | Discovers WebSocket endpoints and checks origin validation | `MEDIUM` |
| [`wordpress-security-audit-12-checks.sh`](06_framework_and_api/wordpress-security-audit-12-checks.sh) | **WordPress Security Audit (12 checks)** | wp-config exposure, xmlrpc, wp-cron, readme, version disclosure, user enumeration | `MEDIUM` |

