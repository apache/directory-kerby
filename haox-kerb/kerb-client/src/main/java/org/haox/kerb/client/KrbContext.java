package org.haox.kerb.client;

import org.haox.kerb.common.KrbUtil;
import org.haox.kerb.spec.type.common.EncryptionType;

import java.security.SecureRandom;
import java.util.List;

public class KrbContext {
    private String kdcHost;
    private int kdcPort;
    private String clientPrincipal;
    private String password;
    private String realm;
    private String serverPrincipal;
    private List<EncryptionType> defaultEtypes;

    private SecureRandom nonceGenerator;
    private KrbConfig config;

    public KrbContext() {
        nonceGenerator = new SecureRandom(String.valueOf(System.currentTimeMillis()).getBytes());
    }

    public int generateNonce() {
        return nonceGenerator.nextInt();
    }

    public long getTicketValidTime() {
        return 8 * 60 * 60 * 1000;
    }

    public String getClientPrincipal() {
        return clientPrincipal;
    }

    public void setClientPrincipal(String clientPrincipal) {
        this.clientPrincipal = clientPrincipal;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public String getServerPrincipal() {
        return serverPrincipal;
    }

    public void setServerPrincipal(String serverPrincipal) {
        this.serverPrincipal = serverPrincipal;
    }

    public KrbConfig getConfig() {
        return config;
    }

    public void setConfig(KrbConfig config) {
        this.config = config;
    }

    public String getKdcHost() {
        return kdcHost;
    }

    public void setKdcHost(String kdcHost) {
        this.kdcHost = kdcHost;
    }

    public int getKdcPort() {
        return kdcPort;
    }

    public void setKdcPort(int kdcPort) {
        this.kdcPort = kdcPort;
    }

    public List<EncryptionType> getDefaultEtypes() {
        if (defaultEtypes == null || defaultEtypes.isEmpty()) {
            defaultEtypes = KrbUtil.getEncryptionTypes(config.getEncryptionTypes());
        }
        return defaultEtypes;
    }
}
