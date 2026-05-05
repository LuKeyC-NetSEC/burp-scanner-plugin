package com.scanner.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;

public class TrafficDetailPanel {

    private final MontoyaApi api;
    private final JPanel panel;
    private final JButton backButton;
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;

    public TrafficDetailPanel(MontoyaApi api) {
        this.api = api;
        panel = new JPanel(new BorderLayout());

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        backButton = new JButton("\u2190 Back to Logs");
        backButton.setPreferredSize(new Dimension(150, 30));
        topPanel.add(backButton);
        panel.add(topPanel, BorderLayout.NORTH);

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setResizeWeight(0.5);
        splitPane.setContinuousLayout(true);

        requestEditor = api.userInterface().createHttpRequestEditor();
        responseEditor = api.userInterface().createHttpResponseEditor();

        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(BorderFactory.createTitledBorder("Request"));
        requestPanel.add(requestEditor.uiComponent(), BorderLayout.CENTER);

        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBorder(BorderFactory.createTitledBorder("Response"));
        responsePanel.add(responseEditor.uiComponent(), BorderLayout.CENTER);

        splitPane.setLeftComponent(requestPanel);
        splitPane.setRightComponent(responsePanel);

        panel.add(splitPane, BorderLayout.CENTER);
    }

    public void setRequestResponse(HttpRequestResponse requestResponse) {
        if (requestResponse == null) {
            requestEditor.setRequest(null);
            responseEditor.setResponse(null);
            return;
        }

        requestEditor.setRequest(requestResponse.request());
        responseEditor.setResponse(requestResponse.response());
    }

    public void addBackListener(ActionListener listener) {
        backButton.addActionListener(listener);
    }

    public Component getComponent() {
        return panel;
    }
}