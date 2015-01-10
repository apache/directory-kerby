package org.apache.kerberos.kerb.client;

import org.apache.kerberos.kerb.client.preauth.PreauthHandler;
import org.apache.kerberos.kerb.crypto.Nonce;

public class KrbContext {

    private String kdcRealm;
    private KrbConfig config;
    private String kdcHost;
    private short kdcPort;
    private long timeout = 10L;
    private PreauthHandler preauthHandler;

    public void init(KrbConfig config) {
        this.config = config;
        preauthHandler = new PreauthHandler();
        preauthHandler.init(this);
    }

    public String getKdcHost() {
        if (kdcHost != null) {
            return kdcHost;
        }
        return config.getKdcHost();
    }

    public void setKdcHost(String kdcHost) {
        this.kdcHost = kdcHost;
    }

    public short getKdcPort() {
        if (kdcPort > 0) {
            return kdcPort;
        }
        return config.getKdcPort();
    }

    public void setKdcPort(short kdcPort) {
        this.kdcPort = kdcPort;
    }

    public void setTimeout(long timeout) {
        this.timeout = timeout;
    }

    public long getTimeout() {
        return this.timeout;
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

    public PreauthHandler getPreauthHandler() {
        return preauthHandler;
    }
}
