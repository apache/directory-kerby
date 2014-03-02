package org.haox.kerb.spec.type.ticket;

import org.haox.kerb.spec.type.common.*;

public class EncTicketPart {
    /** the ticket's flags */
    private TicketFlags flags;
    /** the encryption key */
    private EncryptionKey key;
    /** the client's realm */
    private String crealm;
    /** client's principal */
    private PrincipalName cname;
    /** field containing list of transited realm names */
    private TransitedEncoding transited;
    /** time of initial authentication */
    private KrbTime authTime;
    /** time after which ticket is valid */
    private KrbTime startTime;
    /** ticket's expiry time */
    private KrbTime endTime;
    /** the maximum endtime that may be included in a renewal */
    private KrbTime renewtill;
    /** the addresses from which this ticket can be used */
    private HostAddresses clientAddresses;
    /** the authorization data */
    private AuthorizationData authorizationData;

    public TicketFlags getFlags() {
        return flags;
    }

    public void setFlags(TicketFlags flags) {
        this.flags = flags;
    }

    public EncryptionKey getKey() {
        return key;
    }

    public void setKey(EncryptionKey key) {
        this.key = key;
    }

    public String getCrealm() {
        return crealm;
    }

    public void setCrealm(String crealm) {
        this.crealm = crealm;
    }

    public PrincipalName getCname() {
        return cname;
    }

    public void setCname(PrincipalName cname) {
        this.cname = cname;
    }

    public TransitedEncoding getTransited() {
        return transited;
    }

    public void setTransited(TransitedEncoding transited) {
        this.transited = transited;
    }

    public KrbTime getAuthTime() {
        return authTime;
    }

    public void setAuthTime(KrbTime authTime) {
        this.authTime = authTime;
    }

    public KrbTime getStartTime() {
        return startTime;
    }

    public void setStartTime(KrbTime startTime) {
        this.startTime = startTime;
    }

    public KrbTime getEndTime() {
        return endTime;
    }

    public void setEndTime(KrbTime endTime) {
        this.endTime = endTime;
    }

    public KrbTime getRenewtill() {
        return renewtill;
    }

    public void setRenewtill(KrbTime renewtill) {
        this.renewtill = renewtill;
    }

    public HostAddresses getClientAddresses() {
        return clientAddresses;
    }

    public void setClientAddresses(HostAddresses clientAddresses) {
        this.clientAddresses = clientAddresses;
    }

    public AuthorizationData getAuthorizationData() {
        return authorizationData;
    }

    public void setAuthorizationData(AuthorizationData authorizationData) {
        this.authorizationData = authorizationData;
    }
}
