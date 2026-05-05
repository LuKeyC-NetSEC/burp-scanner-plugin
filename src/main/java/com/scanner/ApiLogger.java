package com.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.scanner.ui.ScannerDashboard;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class ApiLogger {

    public enum Level {
        INFO, DEBUG, ERROR, VULN
    }

    private final Logging logging;
    private final ScannerDashboard dashboard;
    private String scanName = "Scanner";

    public ApiLogger(MontoyaApi api, ScannerDashboard dashboard) {
        this.logging = api.logging();
        this.dashboard = dashboard;
    }

    public void setScanName(String name) {
        this.scanName = name;
    }

    private String formatLog(Level level, String domain, String message) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        return String.format("[%s] [%s] [%s] [%s] [%s]", timestamp, level.name(), scanName, domain, message);
    }

    private String formatLogVuln(String domain, String vulnType, String payload, String response) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        return String.format("[%s] [VULN] [%s] [%s] [%s] [%s] [%s]", timestamp, scanName, domain, "Found " + vulnType, payload, response);
    }

    public void log(String message) {
        String formatted = formatLog(Level.INFO, "-", message);
        logging.logToOutput(formatted);
        dashboard.logScanProcess(formatted);
    }

    public void log(Level level, String domain, String message) {
        String formatted = formatLog(level, domain, message);
        logging.logToOutput(formatted);
        dashboard.logScanProcess(formatted);
    }

    public void logInfo(String message) {
        logInfo("-", message);
    }

    public void logInfo(String domain, String message) {
        String formatted = formatLog(Level.INFO, domain, message);
        logging.logToOutput(formatted);
        logging.raiseInfoEvent(message);
        dashboard.logScanProcess(formatted);
    }

    public void logError(String message) {
        logError("-", message);
    }

    public void logError(String domain, String message) {
        String formatted = formatLog(Level.ERROR, domain, message);
        logging.logToOutput(formatted);
        logging.raiseErrorEvent(message);
        dashboard.logScanProcess(formatted);
    }

    public void logError(String domain, String message, Throwable throwable) {
        String formatted = formatLog(Level.ERROR, domain, message + " - " + throwable.getMessage());
        logging.logToOutput(formatted);
        logging.logToError(message, throwable);
        dashboard.logScanProcess(formatted);
    }

    public void logDebug(String domain, String message) {
        String formatted = formatLog(Level.DEBUG, domain, message);
        logging.logToOutput(formatted);
        dashboard.logScanProcess(formatted);
    }

    public void logVuln(String domain, String vulnType, String payload, String response) {
        String formatted = formatLogVuln(domain, vulnType, payload, response);
        logging.raiseErrorEvent(formatted);
        dashboard.logScanProcess(formatted);
    }

    public void logSectionStart(String domain, String sectionName) {
        logInfo(domain, "=== START " + sectionName + " ===");
    }

    public void logSectionEnd(String domain, String sectionName) {
        logInfo(domain, "=== END " + sectionName + " ===");
    }
}