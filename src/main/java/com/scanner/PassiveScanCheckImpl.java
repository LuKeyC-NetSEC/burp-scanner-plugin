package com.scanner;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;

import java.util.List;

import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_BOTH;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_EXISTING;
import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;

public class PassiveScanCheckImpl implements PassiveScanCheck {

    private static final String GREP_STRING = "X-Powered-By:";
    private final ApiLogger logger;

    public PassiveScanCheckImpl(ApiLogger logger) {
        this.logger = logger;
    }

    @Override
    public String checkName() {
        return "Technology Information Leakage";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse httpRequestResponse) {
        if (httpRequestResponse.response() == null) {
            return auditResult(emptyList());
        }

        String responseBody = httpRequestResponse.response().bodyToString();

        if (responseBody.contains(GREP_STRING)) {
            List<AuditIssue> issues = singletonList(
                    auditIssue(
                            "Technology Information Leakage",
                            "The response contains technology information header: " + GREP_STRING,
                            null,
                            httpRequestResponse.request().url(),
                            AuditIssueSeverity.INFORMATION,
                            AuditIssueConfidence.CERTAIN,
                            null,
                            null,
                            AuditIssueSeverity.INFORMATION,
                            httpRequestResponse
                    )
            );

            logger.log("Passive scan detected: " + httpRequestResponse.request().url());
            return auditResult(issues);
        }

        return auditResult(emptyList());
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        return existingIssue.name().equals(newIssue.name()) ? KEEP_EXISTING : KEEP_BOTH;
    }
}
