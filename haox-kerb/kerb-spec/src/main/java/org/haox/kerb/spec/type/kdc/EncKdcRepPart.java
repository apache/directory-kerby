package org.haox.kerb.spec.type.kdc;

import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.type.ticket.TicketFlags;

/**
 EncKDCRepPart   ::= SEQUENCE {
 key             [0] EncryptionKey,
 last-req        [1] LastReq,
 nonce           [2] UInt32,
 key-expiration  [3] KerberosTime OPTIONAL,
 flags           [4] TicketFlags,
 authtime        [5] KerberosTime,
 starttime       [6] KerberosTime OPTIONAL,
 endtime         [7] KerberosTime,
 renew-till      [8] KerberosTime OPTIONAL,
 srealm          [9] Realm,
 sname           [10] PrincipalName,
 caddr           [11] HostAddresses OPTIONAL
 }
 */
public class EncKdcRepPart {
    private EncryptionKey key;
    private LastReq lastReq;
    private int nonce;
    private KerberosTime keyExpiration;
    private TicketFlags flags;
    private KerberosTime authTime;
    private KerberosTime startTime;
    private KerberosTime endTime;
    private KerberosTime renewTill;
    private String srealm;
    private PrincipalName sname;
    private HostAddresses caddr;

    public EncryptionKey getKey() {
        return key;
    }

    public void setKey(EncryptionKey key) {
        this.key = key;
    }

    public LastReq getLastReq() {
        return lastReq;
    }

    public void setLastReq(LastReq lastReq) {
        this.lastReq = lastReq;
    }

    public int getNonce() {
        return nonce;
    }

    public void setNonce(int nonce) {
        this.nonce = nonce;
    }

    public KerberosTime getKeyExpiration() {
        return keyExpiration;
    }

    public void setKeyExpiration(KerberosTime keyExpiration) {
        this.keyExpiration = keyExpiration;
    }

    public TicketFlags getFlags() {
        return flags;
    }

    public void setFlags(TicketFlags flags) {
        this.flags = flags;
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

    public KerberosTime getRenewTill() {
        return renewTill;
    }

    public void setRenewTill(KerberosTime renewTill) {
        this.renewTill = renewTill;
    }

    public String getSrealm() {
        return srealm;
    }

    public void setSrealm(String srealm) {
        this.srealm = srealm;
    }

    public PrincipalName getSname() {
        return sname;
    }

    public void setSname(PrincipalName sname) {
        this.sname = sname;
    }

    public HostAddresses getCaddr() {
        return caddr;
    }

    public void setCaddr(HostAddresses caddr) {
        this.caddr = caddr;
    }
}
