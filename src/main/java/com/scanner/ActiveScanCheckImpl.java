package com.scanner;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;

import java.util.List;

import static burp.api.montoya.core.ByteArray.byteArray;
import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_BOTH;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_EXISTING;
import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;

public class ActiveScanCheckImpl implements ActiveScanCheck {

    private static final String TEST_PAYLOAD = "<script>alert(1)</script>";
    private static final String XSS_INDICATOR = "<script>alert";
    private final ApiLogger logger;

    public ActiveScanCheckImpl(ApiLogger logger) {
        this.logger = logger;
    }

    @Override
    public String checkName() {
        return "Cross-Site Scripting (XSS)";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse httpRequestResponse, AuditInsertionPoint auditInsertionPoint, Http http) {
        HttpRequest checkRequest = auditInsertionPoint.buildHttpRequestWithPayload(byteArray(TEST_PAYLOAD))
                .withService(httpRequestResponse.httpService());

        HttpRequestResponse checkRequestResponse = http.sendRequest(checkRequest);

        if (checkRequestResponse == null || checkRequestResponse.response() == null) {
            return auditResult(emptyList());
        }

        String responseBody = checkRequestResponse.response().bodyToString();
        List<AuditIssue> issues = emptyList();

        if (responseBody.contains(XSS_INDICATOR)) {
            issues = singletonList(
                    auditIssue(
                            "Cross-Site Scripting (XSS)",
                            "Reflected XSS payload detected",
                            null,
                            httpRequestResponse.request().url(),
                            AuditIssueSeverity.HIGH,
                            AuditIssueConfidence.CERTAIN,
                            null,
                            null,
                            AuditIssueSeverity.HIGH,
                            checkRequestResponse
                    )
            );
            logger.log("Active scan detected XSS at: " + httpRequestResponse.request().url());
        }

        return auditResult(issues);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        return existingIssue.name().equals(newIssue.name()) ? KEEP_EXISTING : KEEP_BOTH;
    }
}
