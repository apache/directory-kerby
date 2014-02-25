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
    private KerberosTime authTime;
    /** time after which ticket is valid */
    private KerberosTime startTime;
    /** ticket's expiry time */
    private KerberosTime endTime;
    /** the maximum endtime that may be included in a renewal */
    private KerberosTime renewtill;
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

    public KerberosTime getAuthTime() {
        return authTime;
    }

    public void setAuthTime(KerberosTime authTime) {
        this.authTime = authTime;
    }

    public KerberosTime getStartTime() {
        return startTime;
    }

    public void setStartTime(KerberosTime startTime) {
        this.startTime = startTime;
    }

    public KerberosTime getEndTime() {
        return endTime;
    }

    public void setEndTime(KerberosTime endTime) {
        this.endTime = endTime;
    }

    public KerberosTime getRenewtill() {
        return renewtill;
    }

    public void setRenewtill(KerberosTime renewtill) {
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
