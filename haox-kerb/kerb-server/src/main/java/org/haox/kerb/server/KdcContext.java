package org.haox.kerb.server;

import org.haox.kerb.common.KrbUtil;
import org.haox.kerb.server.identity.IdentityService;
import org.haox.kerb.server.identity.KrbIdentity;
import org.haox.kerb.server.replay.ReplayCheckService;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.spec.type.kdc.KdcRep;
import org.haox.kerb.spec.type.kdc.KdcReq;
import org.haox.kerb.spec.type.ticket.Ticket;

import java.net.InetAddress;
import java.util.List;

public abstract class KdcContext {
    private KdcConfig config;
    private IdentityService identityService;
    private List<EncryptionType> defaultEtypes;
    private Ticket ticket;
    private boolean isPreAuthenticated;
    private KdcReq request;
    private KdcRep reply;
    private InetAddress clientAddress;
    private EncryptionType encryptionType;
    private ReplayCheckService replayCache;
    private EncryptionKey clientKey;
    private KrbIdentity clientEntry;
    private KrbIdentity serverEntry;

    public KdcConfig getConfig() {
        return config;
    }

    public void setConfig(KdcConfig config) {
        this.config = config;
    }

    public List<EncryptionType> getDefaultEtypes() {
        if (defaultEtypes == null || defaultEtypes.isEmpty()) {
            defaultEtypes = KrbUtil.getEncryptionTypes(config.getEncryptionTypes());
        }
        return defaultEtypes;
    }

    public IdentityService getIdentityService() {
        return identityService;
    }

    public void setIdentityService(IdentityService identityService) {
        this.identityService = identityService;
    }

    public KdcReq getRequest() {
        return request;
    }

    public void setRequest(KdcReq request) {
        this.request = request;
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
}
