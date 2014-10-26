package org.haox.kerb.client;

import org.haox.kerb.crypto.Nonce;
import org.haox.kerb.spec.type.common.PrincipalName;

public class KrbContext {

    private String kdcRealm;

    private KrbConfig config;

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

    public KrbConfig getConfig() {
        return config;
    }

    public void setConfig(KrbConfig config) {
        this.config = config;
    }
}
