package com.scanner.vuln;

import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.scanner.util.CollaboratorHelper;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

public class FastjsonDetector implements VulnerabilityDetector {

    private static final String VULN_NAME = "Fastjson Remote Code Execution";
    private static final Pattern JSON_PATTERN = Pattern.compile("\\{\"@type\"", Pattern.CASE_INSENSITIVE);
    private static final Pattern FASTJSON_ERROR_PATTERN = Pattern.compile("syntax error|autoCloseable|fastjson", Pattern.CASE_INSENSITIVE);
    private static final Pattern FASTJSON_VERSION_PATTERN = Pattern.compile("1\\.2\\.([0-9]+)", Pattern.CASE_INSENSITIVE);

    private final CollaboratorHelper collaboratorHelper;

    public FastjsonDetector(CollaboratorHelper collaboratorHelper) {
        this.collaboratorHelper = collaboratorHelper;
    }

    public FastjsonDetector() {
        this.collaboratorHelper = null;
    }

    @Override
    public String vulnerabilityName() {
        return VULN_NAME;
    }

    @Override
    public boolean isVulnerable(HttpRequestResponse requestResponse) {
        if (requestResponse.request().contentType() == ContentType.JSON) {
            return true;
        }

        String body = requestResponse.request().bodyToString();
        if (body != null) {
            if (JSON_PATTERN.matcher(body).find()) {
                return true;
            }
            if (body.contains("{") || body.contains("[")) {
                return true;
            }
        }
        return false;
    }

    @Override
    public Optional<HttpRequest> buildExploitRequest(HttpRequest originalRequest) {
        if (collaboratorHelper == null) {
            return Optional.empty();
        }

        String dnsPayload = collaboratorHelper.generatePayload();

        String exploitBody = String.format(
                "{\"@type\":\"java.net.Inet4Address\",\"val\":\"%s\"}",
                dnsPayload
        );

        HttpRequest exploitRequest = originalRequest.withBody(exploitBody);
        return Optional.of(exploitRequest);
    }

    public List<String> getAllDetectionPayloads() {
        List<String> payloads = new ArrayList<>();
        payloads.addAll(getVersionDetectionPayloads());
        payloads.addAll(getSyntaxErrorPayloads());
        if (collaboratorHelper != null) {
            String dnsHost = collaboratorHelper.generatePayload();
            payloads.addAll(getDnsPayloads(dnsHost));
            payloads.addAll(getMultiVersionDnsPayloads(dnsHost));
        }
        return payloads;
    }

    public List<String> getDnsPayloads(String dnsHost) {
        if (dnsHost != null && !dnsHost.isEmpty()) {
            return FastjsonPayloads.Detection.getDnsPayloads(dnsHost);
        }
        return FastjsonPayloads.Detection.getVersionDetectionPayloads();
    }

    public List<String> getVersionDetectionPayloads() {
        return FastjsonPayloads.Detection.getVersionDetectionPayloads();
    }

    public List<String> getSyntaxErrorPayloads() {
        return FastjsonPayloads.Detection.getSyntaxErrorPayloads();
    }

    public List<String> getDynamicSyntaxErrorPayloads(String originalBody) {
        return FastjsonPayloads.Detection.getDynamicSyntaxErrorPayloads(originalBody);
    }

    public List<String> getMultiVersionDnsPayloads(String dnsHost) {
        return FastjsonPayloads.Detection.getMultiVersionDnsPayloads(dnsHost);
    }

    public List<String> getVersionBypassPayloads() {
        return FastjsonPayloads.Detection.getVersionBypassPayloads();
    }

    public List<String> getAutoCloseablePayloads() {
        return FastjsonPayloads.Detection.getAutoCloseablePayloads();
    }

    public static boolean hasFastjsonFingerprint(HttpRequestResponse requestResponse) {
        if (requestResponse.response() == null) {
            return false;
        }
        String responseBody = requestResponse.response().bodyToString();
        return FASTJSON_ERROR_PATTERN.matcher(responseBody).find();
    }

    public static String detectVersion(HttpRequestResponse requestResponse) {
        if (requestResponse.response() == null) {
            return null;
        }
        String responseBody = requestResponse.response().bodyToString();

        var matcher = FASTJSON_VERSION_PATTERN.matcher(responseBody);
        if (matcher.find()) {
            return "1.2." + matcher.group(1);
        }

        if (responseBody.contains("autoCloseable") || responseBody.contains("AutoCloseable")) {
            if (responseBody.contains("1.2.76")) {
                return "1.2.76+";
            }
            return "Unknown 1.2.x";
        }

        return null;
    }

    public boolean hasVulnerabilityIndicator(HttpRequestResponse requestResponse) {
        if (requestResponse.response() == null) {
            return false;
        }
        String responseBody = requestResponse.response().bodyToString();
        return FASTJSON_ERROR_PATTERN.matcher(responseBody).find();
    }

    public boolean isVulnerableWithDns(HttpRequestResponse requestResponse) {
        if (requestResponse.response() == null) {
            return false;
        }
        String responseBody = requestResponse.response().bodyToString();

        if (collaboratorHelper != null) {
            String payload = collaboratorHelper.generatePayload();
            return responseBody.contains(payload);
        }

        return hasFastjsonFingerprint(requestResponse);
    }

    public String buildJdbcPayload(String targetHost) {
        return String.format(FastjsonPayloads.Exploit.JdbcRowSetImpl_Basic, targetHost);
    }

    public String buildAutoCloseablePayload() {
        return FastjsonPayloads.Exploit.AutoCloseable_Basic;
    }

    public String buildClassCachePayload() {
        return FastjsonPayloads.Exploit.Class_Cache;
    }

    public String buildShiroPayload(String targetHost) {
        return String.format(FastjsonPayloads.Exploit.Shiro_AutoType, targetHost);
    }

    public String buildReadFilePayload(String filePath) {
        return String.format(FastjsonPayloads.Exploit.CommonsIO_ReadFile, filePath);
    }

    public String buildWriteFilePayload(String targetPath, String tempPath) {
        return String.format(FastjsonPayloads.Exploit.CommonsIO_WriteFile_JDK8, targetPath, tempPath);
    }

    public String buildC3P0Payload(String evilHex) {
        return String.format(FastjsonPayloads.RCE_Payloads.C3P0_Serial, evilHex);
    }

    public List<String> getJdbcPayloadsForVersion(String targetHost) {
        List<String> payloads = new ArrayList<>();
        payloads.add(String.format(FastjsonPayloads.Exploit.JdbcRowSetImpl_Basic, targetHost));
        payloads.add(String.format(FastjsonPayloads.Exploit.JdbcRowSetImpl_1247, targetHost));
        return payloads;
    }
}