package org.haox.kerb.client;

import org.haox.kerb.client.preauth.PreauthHandler;
import org.haox.kerb.crypto.Nonce;

public class KrbContext {

    private String kdcRealm;
    private KrbConfig config;
    private PreauthHandler preauthHandler;

    public void init(KrbConfig config) {
        this.config = config;
        preauthHandler = new PreauthHandler();
        preauthHandler.init(this);
    }

    public KrbConfig getConfig() {
        return config;
    }

    public void setKdcRealm(String realm) {
        this.kdcRealm = realm;
    }

    public String getKdcRealm() {
        if (kdcRealm != null) {
            return kdcRealm;
        }

        return config.getKdcRealm();
    }

    public int generateNonce() {
        return Nonce.value();
    }

    public long getTicketValidTime() {
        return 8 * 60 * 60 * 1000;
    }
}
