package org.haox.kerb.server;

import org.haox.kerb.identity.IdentityService;
import org.haox.kerb.server.preauth.PreauthHandler;
import org.haox.kerb.server.replay.ReplayCheckService;

import java.util.List;

public class KdcContext {
    private KdcConfig config;
    private List<String> supportedKdcRealms;
    private String kdcRealm;
    private IdentityService identityService;
    private ReplayCheckService replayCache;
    private PreauthHandler preauthHandler;

    public void init(KdcConfig config) {
        this.config = config;
    }

    public KdcConfig getConfig() {
        return config;
    }

    public void setPreauthHandler(PreauthHandler preauthHandler) {
        this.preauthHandler = preauthHandler;
    }

    public PreauthHandler getPreauthHandler() {
        return this.preauthHandler;
    }

    public List<String> getSupportedKdcRealms() {
        return supportedKdcRealms;
    }

    public void setSupportedKdcRealms(List<String> supportedKdcRealms) {
        this.supportedKdcRealms = supportedKdcRealms;
    }

    public void setKdcRealm(String realm) {
        this.kdcRealm = realm;
    }

    public String getServerRealm() {
        return config.getKdcRealm();
    }

    public String getKdcRealm() {
        if (kdcRealm != null) {
            return kdcRealm;
        }
        return config.getKdcRealm();
    }

    public void setReplayCache(ReplayCheckService replayCache) {
        this.replayCache = replayCache;
    }

    public ReplayCheckService getReplayCache() {
        return replayCache;
    }

    public void setIdentityService(IdentityService identityService) {
        this.identityService = identityService;
    }


    public IdentityService getIdentityService() {
        return identityService;
    }
}
