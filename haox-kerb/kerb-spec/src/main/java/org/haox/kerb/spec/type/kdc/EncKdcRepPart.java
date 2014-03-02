package org.haox.kerb.spec.type.kdc;

import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.type.ticket.TicketFlags;

/**
 EncKDCRepPart   ::= SEQUENCE {
 key             [0] EncryptionKey,
 last-req        [1] LastReq,
 nonce           [2] UInt32,
 key-expiration  [3] KrbTime OPTIONAL,
 flags           [4] TicketFlags,
 authtime        [5] KrbTime,
 starttime       [6] KrbTime OPTIONAL,
 endtime         [7] KrbTime,
 renew-till      [8] KrbTime OPTIONAL,
 srealm          [9] Realm,
 sname           [10] PrincipalName,
 caddr           [11] HostAddresses OPTIONAL
 }
 */
public class EncKdcRepPart {
    private EncryptionKey key;
    private LastReq lastReq;
    private int nonce;
    private KrbTime keyExpiration;
    private TicketFlags flags;
    private KrbTime authTime;
    private KrbTime startTime;
    private KrbTime endTime;
    private KrbTime renewTill;
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

    public KrbTime getKeyExpiration() {
        return keyExpiration;
    }

    public void setKeyExpiration(KrbTime keyExpiration) {
        this.keyExpiration = keyExpiration;
    }

    public TicketFlags getFlags() {
        return flags;
    }

    public void setFlags(TicketFlags flags) {
        this.flags = flags;
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

    public KrbTime getRenewTill() {
        return renewTill;
    }

    public void setRenewTill(KrbTime renewTill) {
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
