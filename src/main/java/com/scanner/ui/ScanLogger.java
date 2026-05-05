package com.scanner.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

import javax.swing.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class ScanLogger {

    public enum Level {
        INFO, DEBUG, ERROR, VULN
    }

    private final MontoyaApi api;
    private final Logging logging;
    private final ScannerDashboard dashboard;
    private final String scanName;

    public ScanLogger(MontoyaApi api, ScannerDashboard dashboard, String scanName) {
        this.api = api;
        this.logging = api.logging();
        this.dashboard = dashboard;
        this.scanName = scanName;
    }

    public void log(Level level, String domain, String payload) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        String levelStr = level.name();
        String logLine = String.format("[%s] [%s] [%s] [%s] [%s]", timestamp, levelStr, scanName, domain, payload);

        logging.logToOutput(logLine);
        dashboard.logScanProcess(logLine);
    }

    public void logVuln(String domain, String vulnType, String payload, String response) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        String levelStr = "VULN";
        String logLine = String.format("[%s] [%s] [%s] [%s] [%s] [%s] [%s]",
                timestamp, levelStr, scanName, domain, "Found " + vulnType + " vulnerability", payload, response);

        logging.raiseErrorEvent(logLine);
        dashboard.logScanProcess(logLine);
    }

    public void logInfo(String domain, String message) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        String logLine = String.format("[%s] [INFO] [%s] [%s] [%s]", timestamp, scanName, domain, message);

        logging.logToOutput(logLine);
        dashboard.logScanProcess(logLine);
    }

    public void logError(String domain, String message) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        String logLine = String.format("[%s] [ERROR] [%s] [%s] [%s]", timestamp, scanName, domain, message);

        logging.logToOutput(logLine);
        logging.raiseErrorEvent(logLine);
        dashboard.logScanProcess(logLine);
    }

    public void logSectionStart(String domain) {
        logInfo(domain, "=== START " + scanName + " scan ===");
    }

    public void logSectionEnd(String domain) {
        logInfo(domain, "=== END " + scanName + " scan ===");
    }
}