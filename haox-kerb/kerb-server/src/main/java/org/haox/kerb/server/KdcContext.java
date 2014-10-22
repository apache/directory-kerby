package org.haox.kerb.server;

import org.haox.kerb.identity.KrbIdentity;
import org.haox.kerb.server.replay.ReplayCheckService;
import org.haox.kerb.spec.KrbConstant;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.spec.type.common.PrincipalName;
import org.haox.kerb.spec.type.kdc.KdcRep;
import org.haox.kerb.spec.type.kdc.KdcReq;
import org.haox.kerb.spec.type.ticket.Ticket;

import java.net.InetAddress;

public abstract class KdcContext {
    private KdcConfig config;
    private String kdcRealm;
    private Ticket ticket;
    private boolean isPreAuthenticated;
    private KdcReq request;
    private KdcRep reply;
    private InetAddress clientAddress;
    private boolean isTcp;
    private EncryptionType encryptionType;
    private ReplayCheckService replayCache;
    private EncryptionKey clientKey;
    private KrbIdentity clientEntry;
    private KrbIdentity serverEntry;
    private EncryptionKey serverKey;
    private KrbIdentity tgsEntry;

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

    public KdcReq getRequest() {
        return request;
    }

    public void setRequest(KdcReq request) {
        this.request = request;
    }

    public boolean isTcp() {
        return isTcp;
    }

    public void isTcp(boolean isTcp) {
        this.isTcp = isTcp;
    }

    public KrbMessage getReply() {
        return reply;
    }

    public void setReply(KdcRep reply) {
        this.reply = reply;
    }

    public InetAddress getClientAddress() {
        return clientAddress;
    }

    public void setClientAddress(InetAddress clientAddress) {
        this.clientAddress = clientAddress;
    }

    public EncryptionType getEncryptionType() {
        return encryptionType;
    }

    public void setEncryptionType(EncryptionType encryptionType) {
        this.encryptionType = encryptionType;
    }

    public void setReplayCache(ReplayCheckService replayCache) {
        this.replayCache = replayCache;
    }

    public ReplayCheckService getReplayCache() {
        return replayCache;
    }

    public Ticket getTicket() {
        return ticket;
    }

    public void setTicket(Ticket ticket) {
        this.ticket = ticket;
    }

    public boolean isPreAuthenticated() {
        return isPreAuthenticated;
    }

    public void setPreAuthenticated(boolean isPreAuthenticated) {
        this.isPreAuthenticated = isPreAuthenticated;
    }

    public KrbIdentity getServerEntry() {
        return serverEntry;
    }

    public void setServerEntry(KrbIdentity serverEntry) {
        this.serverEntry = serverEntry;
    }

    public KrbIdentity getClientEntry() {
        return clientEntry;
    }

    public void setClientEntry(KrbIdentity clientEntry) {
        this.clientEntry = clientEntry;
    }

    public EncryptionKey getClientKey() {
        return clientKey;
    }

    public void setClientKey(EncryptionKey clientKey) {
        this.clientKey = clientKey;
    }

    public EncryptionKey getServerKey() {
        return serverKey;
    }

    public void setServerKey(EncryptionKey serverKey) {
        this.serverKey = serverKey;
    }

    public KrbIdentity getTgsEntry() {
        return tgsEntry;
    }

    public void setTgsEntry(KrbIdentity tgsEntry) {
        this.tgsEntry = tgsEntry;
    }

    public PrincipalName getTgsPrincipal() {
        PrincipalName result = new PrincipalName(config.getTgsPrincipal());
        result.setRealm(getKdcRealm());
        return result;
    }
}
