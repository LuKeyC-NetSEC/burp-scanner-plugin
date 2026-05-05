package com.scanner.checks;

import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import com.scanner.ApiLogger;
import com.scanner.ui.ScannerDashboard;
import com.scanner.vuln.FastjsonDetector;
import com.scanner.vuln.Log4jDetector;
import com.scanner.vuln.NextJsDetector;
import com.scanner.vuln.ShiroDetector;
import com.scanner.util.CollaboratorHelper;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_BOTH;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_EXISTING;
import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;
import static java.util.Collections.emptyList;

public class PassiveScanChecks implements PassiveScanCheck {

    private static final Pattern JSON_PATTERN = Pattern.compile("^\\s*[{{]", Pattern.MULTILINE);

    private final ApiLogger logger;
    private final ScannerDashboard dashboard;
    private final CollaboratorHelper collaboratorHelper;

    public PassiveScanChecks(ApiLogger logger, ScannerDashboard dashboard, CollaboratorHelper collaboratorHelper) {
        this.logger = logger;
        this.dashboard = dashboard;
        this.collaboratorHelper = collaboratorHelper;
        this.logger.setScanName("PassiveScan");
    }

    @Override
    public String checkName() {
        return "Vulnerability Passive Scan";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse requestResponse) {
        if (!dashboard.isPassiveScanEnabled()) {
            return auditResult(emptyList());
        }

        List<AuditIssue> issues = new ArrayList<>();
        String url = requestResponse.request().url();
        String domain = extractDomain(url);

        if (dashboard.isLog4jEnabled()) {
            issues.addAll(testLog4j(requestResponse, domain));
        }

        if (dashboard.isShiroEnabled()) {
            issues.addAll(testShiro(requestResponse, domain));
        }

        if (dashboard.isFastjsonEnabled()) {
            issues.addAll(testFastjson(requestResponse, domain));
        }

        if (dashboard.isNextJsEnabled()) {
            issues.addAll(testNextJs(requestResponse, domain));
        }

        return auditResult(issues.isEmpty() ? emptyList() : issues);
    }

    private List<AuditIssue> testLog4j(HttpRequestResponse requestResponse, String domain) {
        List<AuditIssue> issues = new ArrayList<>();
        Log4jDetector detector = new Log4jDetector(collaboratorHelper);

        logger.logSectionStart(domain, "Log4j");

        if (detector.isVulnerable(requestResponse)) {
            logger.log(ApiLogger.Level.VULN, domain, "JNDI pattern found in request");
            dashboard.log("Passive", "Log4j RCE", domain, requestResponse.request().url(), requestResponse);
            issues.add(createIssue("Log4j RCE", "JNDI injection pattern detected", requestResponse));
        } else {
            logger.logInfo(domain, "No JNDI pattern found");
        }

        logger.logSectionEnd(domain, "Log4j");
        return issues;
    }

    private List<AuditIssue> testShiro(HttpRequestResponse requestResponse, String domain) {
        List<AuditIssue> issues = new ArrayList<>();
        ShiroDetector detector = new ShiroDetector();

        logger.logSectionStart(domain, "Shiro");

        if (detector.isVulnerable(requestResponse)) {
            logger.log(ApiLogger.Level.VULN, domain, "rememberMe cookie found");
            dashboard.log("Passive", "Apache Shiro", domain, requestResponse.request().url(), requestResponse);
            issues.add(createIssue("Apache Shiro", "Shiro rememberMe cookie detected", requestResponse));
        }

        if (ShiroDetector.hasShiroFingerprint(requestResponse)) {
            logger.log(ApiLogger.Level.VULN, domain, "Shiro fingerprint detected in response");
            dashboard.log("Passive", "Apache Shiro", domain, requestResponse.request().url(), requestResponse);
            issues.add(createIssue("Apache Shiro Fingerprint", "Application uses Shiro framework", requestResponse));
        }

        if (issues.isEmpty()) {
            logger.logInfo(domain, "No Shiro indicators found");
        }

        logger.logSectionEnd(domain, "Shiro");
        return issues;
    }

    private List<AuditIssue> testFastjson(HttpRequestResponse requestResponse, String domain) {
        List<AuditIssue> issues = new ArrayList<>();
        FastjsonDetector detector = new FastjsonDetector(collaboratorHelper);

        logger.logSectionStart(domain, "Fastjson");

        boolean isJson = requestResponse.request().contentType() == ContentType.JSON;
        String body = requestResponse.request().bodyToString();
        boolean bodyMatchesJson = body != null && !body.isEmpty() && JSON_PATTERN.matcher(body).find();

        if (isJson || bodyMatchesJson) {
            logger.logInfo(domain, "JSON content detected");

            if (detector.isVulnerable(requestResponse)) {
                logger.log(ApiLogger.Level.VULN, domain, "Fastjson potential vulnerability");
                dashboard.log("Passive", "Fastjson RCE", domain, requestResponse.request().url(), requestResponse);
                issues.add(createIssue("Fastjson RCE", "JSON payload detected", requestResponse));
            }

            if (detector.hasVulnerabilityIndicator(requestResponse)) {
                logger.log(ApiLogger.Level.VULN, domain, "Fastjson fingerprint in response");
                dashboard.log("Passive", "Fastjson RCE", domain, requestResponse.request().url(), requestResponse);
                issues.add(createIssue("Fastjson Fingerprint", "Fastjson error fingerprint in response", requestResponse));
            }
        } else {
            logger.logInfo(domain, "No JSON content found");
        }

        logger.logSectionEnd(domain, "Fastjson");
        return issues;
    }

    private List<AuditIssue> testNextJs(HttpRequestResponse requestResponse, String domain) {
        List<AuditIssue> issues = new ArrayList<>();
        NextJsDetector detector = new NextJsDetector();

        logger.logSectionStart(domain, "Next.js");

        if (detector.isVulnerable(requestResponse)) {
            logger.log(ApiLogger.Level.VULN, domain, "Next.js framework detected");
            dashboard.log("Passive", "Next.js RCE", domain, requestResponse.request().url(), requestResponse);
            issues.add(createIssue("Next.js RCE", "Next.js framework detected", requestResponse));
        } else {
            logger.logInfo(domain, "No Next.js indicators found");
        }

        logger.logSectionEnd(domain, "Next.js");
        return issues;
    }

    private AuditIssue createIssue(String name, String detail, HttpRequestResponse requestResponse) {
        return auditIssue(
                name, detail, null, requestResponse.request().url(),
                AuditIssueSeverity.HIGH, AuditIssueConfidence.TENTATIVE,
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