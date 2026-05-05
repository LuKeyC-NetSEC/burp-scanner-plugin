package com.scanner.util;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.logging.Logging;

import java.util.List;
import java.util.UUID;

public class CollaboratorHelper {

    private final MontoyaApi api;
    private final Logging logging;
    private CollaboratorClient collaboratorClient;
    private String collaboratorPayload;

    public CollaboratorHelper(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        initCollaborator();
    }

    private void initCollaborator() {
        try {
            collaboratorClient = api.collaborator().createClient();
            collaboratorPayload = collaboratorClient.getSecretKey().toString();
            logging.logToOutput("[Collaborator] Initialized with payload base: " + collaboratorPayload);
        } catch (Exception e) {
            logging.logToError("[Collaborator] Failed to initialize", e);
        }
    }

    public String generatePayload() {
        return UUID.randomUUID().toString().substring(0, 8) + "." + collaboratorPayload;
    }

    public String generateDnsPayload() {
        return "dns-" + UUID.randomUUID().toString().substring(0, 12) + "." + collaboratorPayload;
    }

    public CollaboratorClient getCollaboratorClient() {
        return collaboratorClient;
    }

    public boolean hasInteraction(String payload) {
        if (collaboratorClient == null || payload == null) {
            return false;
        }
        try {
            List<Interaction> interactions = collaboratorClient.getAllInteractions();
            for (Interaction interaction : interactions) {
                if (interaction.toString().contains(payload)) {
                    return true;
                }
            }
        } catch (Exception e) {
            logging.logToError("[Collaborator] Error checking interactions", e);
        }
        return false;
    }

    public boolean pollForInteraction(String payload, int maxAttempts, int delayMs) {
        if (collaboratorClient == null || payload == null) {
            return false;
        }
        for (int i = 0; i < maxAttempts; i++) {
            try {
                Thread.sleep(delayMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            if (hasInteraction(payload)) {
                return true;
            }
        }
        return false;
    }
}