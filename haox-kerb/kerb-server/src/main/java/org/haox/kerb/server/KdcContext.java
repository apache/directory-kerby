package org.haox.kerb.server;

import org.haox.kerb.identity.IdentityService;
import org.haox.kerb.server.replay.ReplayCheckService;

public class KdcContext {
    private KdcConfig config;
    private String kdcRealm;
    protected IdentityService identityService;
    protected ReplayCheckService replayCache;

    public KdcConfig getConfig() {
        return config;
    }

    public void setConfig(KdcConfig config) {
        this.config = config;
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
