package com.scanner.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.scanner.vuln.FastjsonPayloads;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ScanContextMenu implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final ScannerDashboard dashboard;
    private final Logging logging;
    private final ExecutorService executor;

    public ScanContextMenu(MontoyaApi api, ScannerDashboard dashboard) {
        this.api = api;
        this.dashboard = dashboard;
        this.logging = api.logging();
        this.executor = Executors.newSingleThreadExecutor();
    }

    @Override
    public java.util.List<Component> provideMenuItems(ContextMenuEvent event) {
        java.util.List<Component> menuItems = new java.util.ArrayList<>();

        HttpRequestResponse[] requestResponses = getRequestResponses(event);
        if (requestResponses == null || requestResponses.length == 0) {
            return null;
        }

        HttpRequestResponse requestResponse = requestResponses[0];

        JMenu scanMenu = new JMenu("Vuln Scanner");

        if (dashboard.isLog4jEnabled()) {
            scanMenu.add(createLog4jMenuItem(requestResponse));
        }
        if (dashboard.isShiroEnabled()) {
            scanMenu.add(createShiroMenuItem(requestResponse));
        }
        if (dashboard.isFastjsonEnabled()) {
            scanMenu.add(createFastjsonMenuItem(requestResponse));
        }
        if (dashboard.isNextJsEnabled()) {
            scanMenu.add(createNextJsMenuItem(requestResponse));
        }

        scanMenu.addSeparator();

        JMenuItem scanAllItem = new JMenuItem("Scan All Enabled");
        scanAllItem.addActionListener(e -> scanAllEnabled(requestResponse));
        scanMenu.add(scanAllItem);

        menuItems.add(scanMenu);

        return menuItems;
    }

    private HttpRequestResponse[] getRequestResponses(ContextMenuEvent event) {
        if (event.messageEditorRequestResponse().isPresent()) {
            return new HttpRequestResponse[]{event.messageEditorRequestResponse().get().requestResponse()};
        }
        if (!event.selectedRequestResponses().isEmpty()) {
            return event.selectedRequestResponses().toArray(new HttpRequestResponse[0]);
        }
        return null;
    }

    private JMenuItem createLog4jMenuItem(HttpRequestResponse requestResponse) {
        JMenuItem item = new JMenuItem("Scan Log4j RCE");
        item.addActionListener(e -> scanLog4j(requestResponse));
        return item;
    }

    private JMenuItem createShiroMenuItem(HttpRequestResponse requestResponse) {
        JMenuItem item = new JMenuItem("Scan Apache Shiro");
        item.addActionListener(e -> scanShiro(requestResponse));
        return item;
    }

    private JMenuItem createFastjsonMenuItem(HttpRequestResponse requestResponse) {
        JMenuItem item = new JMenuItem("Scan Fastjson RCE");
        item.addActionListener(e -> scanFastjson(requestResponse));
        return item;
    }

    private JMenuItem createNextJsMenuItem(HttpRequestResponse requestResponse) {
        JMenuItem item = new JMenuItem("Scan Next.js RCE");
        item.addActionListener(e -> scanNextJs(requestResponse));
        return item;
    }

    private void scanLog4j(HttpRequestResponse requestResponse) {
        String url = requestResponse.request().url();
        String domain = extractDomain(url);
        ScanLogger logger = new ScanLogger(api, dashboard, "Log4j");

        logger.logSectionStart(domain);
        String body = requestResponse.request().bodyToString();
        boolean hasJndi = body != null && body.contains("${jndi:");

        if (hasJndi) {
            logger.log(ScanLogger.Level.VULN, domain, "JNDI pattern detected in request body");
            dashboard.log("ContextMenu", "Log4j RCE", domain, url, requestResponse);
        } else {
            logger.log(ScanLogger.Level.INFO, domain, "No JNDI pattern found");
        }
        logger.logSectionEnd(domain);
    }

    private void scanShiro(HttpRequestResponse requestResponse) {
        String url = requestResponse.request().url();
        String domain = extractDomain(url);
        ScanLogger logger = new ScanLogger(api, dashboard, "Shiro");

        logger.logSectionStart(domain);

        boolean hasCookie = requestResponse.request().headers().stream()
                .anyMatch(h -> h.name().equalsIgnoreCase("Cookie") && h.value().contains("rememberMe"));

        boolean hasFingerprint = requestResponse.response() != null &&
                requestResponse.response().headers().stream()
                        .anyMatch(h -> h.name().equalsIgnoreCase("Set-Cookie") && h.value().contains("rememberMe"));

        if (hasCookie) {
            logger.log(ScanLogger.Level.VULN, domain, "rememberMe cookie found");
            dashboard.log("ContextMenu", "Apache Shiro", domain, url, requestResponse);
        } else if (hasFingerprint) {
            logger.log(ScanLogger.Level.VULN, domain, "rememberMe fingerprint found in response");
            dashboard.log("ContextMenu", "Apache Shiro", domain, url, requestResponse);
        } else {
            logger.log(ScanLogger.Level.INFO, domain, "No Shiro indicators found");
        }
        logger.logSectionEnd(domain);
    }

    private void scanFastjson(HttpRequestResponse requestResponse) {
        String url = requestResponse.request().url();
        String domain = extractDomain(url);
        ScanLogger logger = new ScanLogger(api, dashboard, "Fastjson");
        String body = requestResponse.request().bodyToString();

        logger.logSectionStart(domain);
        logger.log(ScanLogger.Level.INFO, domain, "Request body: " + body);

        boolean hasJson = body != null && (body.contains("{") || body.contains("["));

        if (!hasJson) {
            logger.log(ScanLogger.Level.INFO, domain, "No JSON content, skipping");
            return;
        }

        List<String> payloads = buildFastjsonPayloads(body, domain);
        logger.log(ScanLogger.Level.INFO, domain, "Testing " + payloads.size() + " payloads");

        executor.submit(() -> {
            int count = 0;
            for (String payload : payloads) {
                count++;
                logger.log(ScanLogger.Level.INFO, domain, "Testing payload [" + count + "/" + payloads.size() + "]: " + payload);

                try {
                    HttpRequest exploitRequest = requestResponse.request().withBody(payload);
                    HttpRequestResponse response = api.http().sendRequest(exploitRequest);

                    if (response != null && response.response() != null) {
                        String responseBody = response.response().bodyToString();
                        int statusCode = response.response().statusCode();

                        logger.log(ScanLogger.Level.INFO, domain, "Response status: " + statusCode);

                        if (statusCode >= 500 || responseBody.contains("syntax error") ||
                            responseBody.contains("fastjson") || responseBody.contains("autoCloseable")) {

                            String responsePreview = responseBody.substring(0, Math.min(100, responseBody.length()));
                            logger.logVuln(domain, "Fastjson RCE", payload, "Response: " + responsePreview);
                            dashboard.log("ContextMenu", "Fastjson RCE", domain, url, response);
                            return;
                        }
                    }
                } catch (Exception e) {
                    logger.logError(domain, "Error: " + e.getMessage());
                }
            }

            logger.log(ScanLogger.Level.INFO, domain, "No vulnerability found");
            logger.logSectionEnd(domain);
        });
    }

    private void scanNextJs(HttpRequestResponse requestResponse) {
        String url = requestResponse.request().url();
        String domain = extractDomain(url);
        ScanLogger logger = new ScanLogger(api, dashboard, "Next.js");

        logger.logSectionStart(domain);

        if (requestResponse.response() == null) {
            logger.log(ScanLogger.Level.INFO, domain, "No response");
            return;
        }

        String headers = requestResponse.response().headers().stream()
                .map(h -> h.name() + ": " + h.value())
                .reduce("", (a, b) -> a + "\n" + b);
        String body = requestResponse.response().bodyToString();

        boolean hasNextJs = headers.contains("Next.js") || headers.contains("__NEXT") ||
                body.contains("Next.js") || body.contains("__NEXT");

        if (hasNextJs) {
            logger.log(ScanLogger.Level.VULN, domain, "Next.js framework detected");
            dashboard.log("ContextMenu", "Next.js RCE", domain, url, requestResponse);
        } else {
            logger.log(ScanLogger.Level.INFO, domain, "No Next.js indicators found");
        }
        logger.logSectionEnd(domain);
    }

    private void scanAllEnabled(HttpRequestResponse requestResponse) {
        String url = requestResponse.request().url();
        String domain = extractDomain(url);
        ScanLogger logger = new ScanLogger(api, dashboard, "Scanner");

        logger.logSectionStart(domain);

        if (dashboard.isLog4jEnabled()) scanLog4j(requestResponse);
        if (dashboard.isShiroEnabled()) scanShiro(requestResponse);
        if (dashboard.isFastjsonEnabled()) scanFastjson(requestResponse);
        if (dashboard.isNextJsEnabled()) scanNextJs(requestResponse);

        logger.logSectionEnd(domain);
    }

    private List<String> buildFastjsonPayloads(String originalBody, String targetHost) {
        List<String> payloads = new ArrayList<>();

        payloads.addAll(FastjsonPayloads.Detection.getSyntaxErrorPayloads());
        payloads.addAll(FastjsonPayloads.Detection.getDynamicSyntaxErrorPayloads(originalBody));
        payloads.add(FastjsonPayloads.Detection.AUTO_CLOSEABLE_VERSION);
        payloads.addAll(FastjsonPayloads.Detection.getVersionBypassPayloads());
        payloads.add(String.format(FastjsonPayloads.Exploit.JdbcRowSetImpl_Basic, targetHost));
        payloads.add(String.format(FastjsonPayloads.Exploit.Shiro_AutoType, targetHost));

        return payloads;
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