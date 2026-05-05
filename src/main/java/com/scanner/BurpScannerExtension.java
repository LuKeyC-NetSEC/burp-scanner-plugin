package com.scanner;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.scanner.checks.ActiveScanChecks;
import com.scanner.checks.PassiveScanChecks;
import com.scanner.ui.ScanContextMenu;
import com.scanner.ui.ScannerDashboard;
import com.scanner.util.CollaboratorHelper;

public class BurpScannerExtension implements BurpExtension {

    private MontoyaApi api;
    private ScannerDashboard dashboard;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;

        api.extension().setName("Vulnerability Scanner");

        CollaboratorHelper collaboratorHelper = new CollaboratorHelper(api);
        this.dashboard = new ScannerDashboard(api);

        api.userInterface().registerSuiteTab("Vuln Scanner", dashboard.uiComponent());

        api.userInterface().registerContextMenuItemsProvider(new ScanContextMenu(api, dashboard));

        ApiLogger logger = new ApiLogger(api, dashboard);

        Scanner scanner = api.scanner();
        scanner.registerPassiveScanCheck(
                new PassiveScanChecks(logger, dashboard, collaboratorHelper),
                ScanCheckType.PER_REQUEST);
        scanner.registerActiveScanCheck(
                new ActiveScanChecks(logger, dashboard, collaboratorHelper),
                ScanCheckType.PER_INSERTION_POINT);

        logger.logInfo("Vulnerability Scanner loaded successfully");
        logger.log("Log4j RCE: enabled, Apache Shiro: enabled, Fastjson RCE: enabled, Next.js RCE: enabled");
        logger.log("Right-click on requests in Proxy/Target/Repeater/Intruder to scan");
        logger.log("Scan logs will appear in the panel below");
    }
}