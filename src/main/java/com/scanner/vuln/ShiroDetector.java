package com.scanner.vuln;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Optional;
import java.util.regex.Pattern;

public class ShiroDetector implements VulnerabilityDetector {

    private static final String VULN_NAME = "Apache Shiro Authentication Bypass";
    private static final String SHIRO_HEADER = "rememberMe";
    private static final Pattern SHIRO_COOKIE_PATTERN = Pattern.compile("rememberMe=([^;]+)");

    @Override
    public String vulnerabilityName() {
        return VULN_NAME;
    }

    @Override
    public boolean isVulnerable(HttpRequestResponse requestResponse) {
        HttpRequest request = requestResponse.request();
        String cookies = request.headers().stream()
                .filter(h -> h.name().equalsIgnoreCase("Cookie"))
                .map(h -> h.value())
                .reduce("", (a, b) -> a + "; " + b);

        return cookies.contains(SHIRO_HEADER);
    }

    @Override
    public Optional<HttpRequest> buildExploitRequest(HttpRequest originalRequest) {
        return Optional.empty();
    }

    public static boolean hasShiroFingerprint(HttpRequestResponse requestResponse) {
        if (requestResponse.response() == null) {
            return false;
        }
        String setCookie = requestResponse.response().headers().stream()
                .filter(h -> h.name().equalsIgnoreCase("Set-Cookie"))
                .map(h -> h.value())
                .reduce("", (a, b) -> a + "; " + b);

        return setCookie.contains("rememberMe=");
    }
}
