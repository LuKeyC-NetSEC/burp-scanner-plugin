package com.scanner.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.concurrent.CopyOnWriteArrayList;

public class ScannerDashboard {

    private final MontoyaApi api;
    private final Logging logging;
    private final JPanel panel;
    private final JCheckBox log4jCheckBox;
    private final JCheckBox shiroCheckBox;
    private final JCheckBox fastjsonCheckBox;
    private final JCheckBox nextJsCheckBox;
    private final JCheckBox passiveScanCheckBox;
    private final JCheckBox activeScanCheckBox;
    private JTable logTable;
    private LogTableModel tableModel;
    private final CopyOnWriteArrayList<LogEntry> logEntries;
    private JTextArea scanLogTextArea;
    private JSplitPane mainSplitPane;
    private TrafficDetailPanel trafficDetailPanel;
    private JPanel bottomContainer;
    private CardLayout bottomCardLayout;
    private JPanel scanLogPanel;
    private JPanel logViewPanel;

    public ScannerDashboard(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        this.logEntries = new CopyOnWriteArrayList<>();

        this.panel = new JPanel(new BorderLayout());
        this.tableModel = new LogTableModel();

        this.log4jCheckBox = new JCheckBox("Log4j RCE", true);
        this.shiroCheckBox = new JCheckBox("Apache Shiro", true);
        this.fastjsonCheckBox = new JCheckBox("Fastjson RCE", true);
        this.nextJsCheckBox = new JCheckBox("Next.js RCE", true);
        this.passiveScanCheckBox = new JCheckBox("Passive Scan", true);
        this.activeScanCheckBox = new JCheckBox("Active Scan", true);

        this.scanLogPanel = new JPanel(new BorderLayout());

        initUI();
    }

    private void initUI() {
        panel.add(createControlPanel(), BorderLayout.NORTH);
        panel.add(createLogViewPanel(), BorderLayout.CENTER);
    }

    private JPanel createControlPanel() {
        JPanel controlPanel = new JPanel();
        controlPanel.setLayout(new BoxLayout(controlPanel, BoxLayout.Y_AXIS));
        controlPanel.setBorder(BorderFactory.createTitledBorder("Scanner Controls"));

        JPanel checkboxPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        checkboxPanel.add(passiveScanCheckBox);
        checkboxPanel.add(activeScanCheckBox);
        checkboxPanel.add(new JSeparator(SwingConstants.VERTICAL));
        checkboxPanel.add(log4jCheckBox);
        checkboxPanel.add(shiroCheckBox);
        checkboxPanel.add(fastjsonCheckBox);
        checkboxPanel.add(nextJsCheckBox);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton clearLogButton = new JButton("Clear Logs");
        JButton clearScanLogButton = new JButton("Clear Scan Log");
        JButton exportLogButton = new JButton("Export Logs");

        clearLogButton.addActionListener(e -> {
            logEntries.clear();
            tableModel.fireTableDataChanged();
        });

        clearScanLogButton.addActionListener(e -> {
            scanLogTextArea.setText("");
        });

        exportLogButton.addActionListener(e -> exportLogs());

        buttonPanel.add(clearLogButton);
        buttonPanel.add(clearScanLogButton);
        buttonPanel.add(exportLogButton);

        controlPanel.add(checkboxPanel);
        controlPanel.add(buttonPanel);

        return controlPanel;
    }

    private JPanel createLogViewPanel() {
        logViewPanel = new JPanel(new BorderLayout());

        mainSplitPane = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                createLogPanel(),
                createBottomContainer()
        );
        mainSplitPane.setResizeWeight(0.7);
        mainSplitPane.setContinuousLayout(true);
        mainSplitPane.setDividerLocation(0.7);

        logViewPanel.add(mainSplitPane, BorderLayout.CENTER);
        return logViewPanel;
    }

    private JPanel createBottomContainer() {
        bottomCardLayout = new CardLayout();
        bottomContainer = new JPanel(bottomCardLayout);

        scanLogPanel = createScanLogPanel();

        trafficDetailPanel = new TrafficDetailPanel(api);
        trafficDetailPanel.addBackListener(e -> showScanLogView());

        bottomContainer.add(scanLogPanel, "SCAN_LOG");
        bottomContainer.add((JPanel) trafficDetailPanel.getComponent(), "TRAFFIC_DETAIL");

        return bottomContainer;
    }

    private JPanel createLogPanel() {
        JPanel logPanel = new JPanel(new BorderLayout());
        logPanel.setBorder(BorderFactory.createTitledBorder("Vulnerability Logs"));

        logTable = new JTable(tableModel);
        logTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        logTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        logTable.getColumnModel().getColumn(0).setPreferredWidth(70);
        logTable.getColumnModel().getColumn(1).setPreferredWidth(150);
        logTable.getColumnModel().getColumn(2).setPreferredWidth(150);
        logTable.getColumnModel().getColumn(3).setPreferredWidth(400);

        logTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int selectedRow = logTable.getSelectedRow();
                if (selectedRow >= 0 && selectedRow < logEntries.size()) {
                    LogEntry entry = logEntries.get(selectedRow);
                    if (entry.requestResponse != null) {
                        showTrafficDetail(entry.requestResponse);
                    }
                }
            }
        });

        JScrollPane scrollPane = new JScrollPane(logTable);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        logPanel.add(scrollPane, BorderLayout.CENTER);

        return logPanel;
    }

    private JPanel createScanLogPanel() {
        JPanel scanLogPanelLocal = new JPanel(new BorderLayout());
        scanLogPanelLocal.setBorder(BorderFactory.createTitledBorder("Scan Log"));

        scanLogTextArea = new JTextArea();
        scanLogTextArea.setEditable(false);
        scanLogTextArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        scanLogTextArea.setLineWrap(true);
        scanLogTextArea.setWrapStyleWord(false);

        JScrollPane scrollPane = new JScrollPane(scanLogTextArea,
                ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        scanLogPanelLocal.add(scrollPane, BorderLayout.CENTER);

        return scanLogPanelLocal;
    }

    private void showTrafficDetail(HttpRequestResponse requestResponse) {
        trafficDetailPanel.setRequestResponse(requestResponse);
        bottomCardLayout.show(bottomContainer, "TRAFFIC_DETAIL");
    }

    private void showScanLogView() {
        bottomCardLayout.show(bottomContainer, "SCAN_LOG");
    }

    public void log(String source, String vulnerability, String domain, String url) {
        log(source, vulnerability, domain, url, null);
    }

    public void log(String source, String vulnerability, String domain, String url, HttpRequestResponse requestResponse) {
        LogEntry entry = new LogEntry(logEntries.size() + 1, source, vulnerability, domain, url, requestResponse);
        logEntries.add(0, entry);
        if (logEntries.size() > 1000) {
            logEntries.remove(logEntries.size() - 1);
        }
        tableModel.fireTableDataChanged();
    }

    public void logScanProcess(String message) {
        final String logLine = message;

        SwingUtilities.invokeLater(() -> {
            try {
                Document doc = scanLogTextArea.getDocument();
                doc.insertString(doc.getLength(), logLine, null);
                doc.insertString(doc.getLength(), "\n", null);
                scanLogTextArea.setCaretPosition(doc.getLength());
            } catch (BadLocationException e) {
            }
        });
    }

    public void clearScanLog() {
        scanLogTextArea.setText("");
    }

    private void exportLogs() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export Vulnerability Logs");
        int result = fileChooser.showSaveDialog(panel);

        if (result == JFileChooser.APPROVE_OPTION) {
            StringBuilder sb = new StringBuilder();
            sb.append("#(序号),域名,漏洞名称,漏洞URL\n");
            for (LogEntry entry : logEntries) {
                sb.append(String.format("\"%d\",\"%s\",\"%s\",\"%s\"\n",
                        entry.index, entry.domain, entry.vulnerability, entry.url));
            }
            logging.logToOutput("[Vuln Scanner] Logs exported to " + fileChooser.getSelectedFile().getAbsolutePath());
        }
    }

    public boolean isLog4jEnabled() {
        return log4jCheckBox.isSelected();
    }

    public boolean isShiroEnabled() {
        return shiroCheckBox.isSelected();
    }

    public boolean isFastjsonEnabled() {
        return fastjsonCheckBox.isSelected();
    }

    public boolean isNextJsEnabled() {
        return nextJsCheckBox.isSelected();
    }

    public boolean isPassiveScanEnabled() {
        return passiveScanCheckBox.isSelected();
    }

    public boolean isActiveScanEnabled() {
        return activeScanCheckBox.isSelected();
    }

    public Component uiComponent() {
        return panel;
    }

    private class LogEntry {
        final int index;
        final String source;
        final String vulnerability;
        final String domain;
        final String url;
        final HttpRequestResponse requestResponse;

        LogEntry(int index, String source, String vulnerability, String domain, String url, HttpRequestResponse requestResponse) {
            this.index = index;
            this.source = source;
            this.vulnerability = vulnerability;
            this.domain = domain;
            this.url = url;
            this.requestResponse = requestResponse;
        }
    }

    private class LogTableModel extends AbstractTableModel {
        private final String[] columnNames = {"#(序号)", "域名", "漏洞名称", "漏洞URL"};

        @Override
        public int getRowCount() {
            return logEntries.size();
        }

        @Override
        public int getColumnCount() {
            return columnNames.length;
        }

        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }

        @Override
        public Object getValueAt(int row, int column) {
            if (row >= logEntries.size()) return null;
            LogEntry entry = logEntries.get(row);
            return switch (column) {
                case 0 -> entry.index;
                case 1 -> entry.domain;
                case 2 -> entry.vulnerability;
                case 3 -> entry.url;
                default -> null;
            };
        }
    }
}