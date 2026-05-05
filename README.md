# Burp Vulnerability Scanner Plugin

A Burp Suite extension for automated detection of Log4j RCE, Apache Shiro, Fastjson RCE, and Next.js RCE vulnerabilities using both passive and active scanning techniques.

## Features

- **Passive Scanning**: Automatically detects vulnerabilities in HTTP traffic passing through Burp Proxy
- **Active Scanning**: Actively probes targets with specific payloads to confirm vulnerabilities
- **Context Menu Integration**: Right-click on requests to trigger targeted scans
- **Dashboard Panel**: View vulnerability logs and scan results in a dedicated tab
- **Traffic Detail Viewer**: Click on vulnerability entries to view the associated HTTP request/response
- **Configurable Controls**: Enable/disable individual vulnerability detectors and scan modes

## Supported Vulnerabilities

| Vulnerability | Detection Method |
|---------------|------------------|
| Log4j RCE (CVE-2021-44228) | JNDI pattern detection (`${jndi:`) |
| Apache Shiro | rememberMe cookie and fingerprint detection |
| Fastjson RCE | Multi-payload detection (syntax error, AutoCloseable, DNS, version bypass) |
| Next.js RCE | Framework fingerprint detection |

## Requirements

- **JDK 17+**
- **Burp Suite Professional/Community Edition** with Montoya API support
- **Maven 3.6+** (for building)

## Installation

### Option 1: Download Pre-built JAR

Download the latest release from the [Releases](https://github.com/your-repo/burp-scanner-plugin/releases) page.

### Option 2: Build from Source

```bash
git clone https://github.com/your-repo/burp-scanner-plugin.git
cd burp-scanner-plugin
mvn clean package
```

The built JAR will be located at `target/burp-scanner-plugin-1.0.0.jar`.

### Load into Burp Suite

1. Open Burp Suite
2. Go to **Extensions** → **Installed** → **Add new extension**
3. Select **Java** as the extension type
4. Choose the JAR file
5. Click **Next** to load

## Usage

### Dashboard

After loading, a new tab **"Vuln Scanner"** appears in Burp Suite:

- **Scanner Controls**: Enable/disable Passive Scan, Active Scan, and individual vulnerability detectors
- **Vulnerability Logs**: Table showing detected vulnerabilities with domain, name, and URL
- **Scan Log**: Real-time scan activity log
- **Traffic Detail**: Click a vulnerability entry to view the HTTP request/response

### Context Menu

Right-click on any request in Proxy, Target, Repeater, or Intruder:

- **Vuln Scanner** → **Scan Log4j RCE**
- **Vuln Scanner** → **Scan Apache Shiro**
- **Vuln Scanner** → **Scan Fastjson RCE**
- **Vuln Scanner** → **Scan Next.js RCE**
- **Vuln Scanner** → **Scan All Enabled**

### Fastjson Detection

Fastjson detection uses multiple payload strategies:

1. **Syntax Error Payloads**: Detect fastjson by causing parse errors
2. **AutoCloseable Version Detection**: Identify fastjson version via AutoCloseable type
3. **Version Bypass Payloads**: Bypass type restrictions in different versions
4. **DNS Exfiltration**: Use DNS for out-of-band detection via Collaborator
5. **JNDI Exploitation**: Test JdbcRowSetImpl and ShiroAutoType payloads

## Project Structure

```
src/main/java/com/scanner/
├── BurpScannerExtension.java      # Main extension entry point
├── ApiLogger.java                 # Unified logging
├── checks/
│   ├── PassiveScanChecks.java     # Passive scan implementation
│   └── ActiveScanChecks.java      # Active scan implementation
├── ui/
│   ├── ScannerDashboard.java      # Main dashboard UI
│   ├── TrafficDetailPanel.java   # Request/Response viewer
│   ├── ScanContextMenu.java      # Context menu items
│   └── ScanLogger.java           # Scan logging utility
├── vuln/
│   ├── VulnerabilityDetector.java # Base detector interface
│   ├── Log4jDetector.java         # Log4j detection
│   ├── ShiroDetector.java        # Shiro detection
│   ├── FastjsonDetector.java      # Fastjson detection
│   ├── FastjsonPayloads.java      # Fastjson payloads
│   └── NextJsDetector.java        # Next.js detection
└── util/
    └── CollaboratorHelper.java    # Burp Collaborator integration
```

## Configuration

The scanner can be fine-tuned via the dashboard checkboxes:

| Option | Description |
|--------|-------------|
| Passive Scan | Enable/disable passive scanning of proxy traffic |
| Active Scan | Enable/disable active probing |
| Log4j RCE | Toggle Log4j detector |
| Apache Shiro | Toggle Shiro detector |
| Fastjson RCE | Toggle Fastjson detector |
| Next.js RCE | Toggle Next.js detector |

## Disclaimer

This tool is for authorized security testing and educational purposes only. Ensure you have explicit permission before scanning any target. The authors are not responsible for misuse of this tool.

## License

Apache License 2.0 - See LICENSE file for details.