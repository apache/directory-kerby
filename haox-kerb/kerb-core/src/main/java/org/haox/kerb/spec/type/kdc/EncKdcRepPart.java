package org.haox.kerb.spec.type.kdc;

import org.haox.asn1.type.Asn1Integer;
import org.haox.asn1.Asn1Tag;
import org.haox.kerb.spec.type.KerberosString;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.KrbAppSequenceType;
import org.haox.kerb.spec.type.KrbSequenceType;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.HostAddresses;
import org.haox.kerb.spec.type.common.LastReq;
import org.haox.kerb.spec.type.common.PrincipalName;
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
public class EncKdcRepPart extends KrbAppSequenceType {
    private static int KEY = 0;
    private static int LAST_REQ = 1;
    private static int NONCE = 2;
    private static int KEY_EXPIRATION = 3;
    private static int FLAGS = 4;
    private static int AUTHTIME = 5;
    private static int STARTTIME = 6;
    private static int ENDTIME = 7;
    private static int RENEW_TILL = 8;
    private static int SREALM = 9;
    private static int SNAME = 10;
    private static int CADDR = 11;

    static Asn1Tag[] tags = new Asn1Tag[] {
            new Asn1Tag(KEY, 0, EncryptionKey.class),
            new Asn1Tag(LAST_REQ, 1, LastReq.class),
            new Asn1Tag(NONCE, 2, Asn1Integer.class),
            new Asn1Tag(KEY_EXPIRATION, 3, KerberosTime.class),
            new Asn1Tag(FLAGS, 4, TicketFlags.class),
            new Asn1Tag(AUTHTIME, 5, KerberosTime.class),
            new Asn1Tag(STARTTIME, 6, KerberosTime.class),
            new Asn1Tag(ENDTIME, 7, KerberosTime.class),
            new Asn1Tag(RENEW_TILL, 8, KerberosTime.class),
            new Asn1Tag(SREALM, 9, KerberosString.class),
            new Asn1Tag(SNAME, 10, PrincipalName.class),
            new Asn1Tag(CADDR, 11, HostAddresses.class)
    };

    public EncKdcRepPart(int tagNo) {
        super(tagNo);
    }

    @Override
    protected Asn1Tag[] getTags() {
        return tags;
    }

    public EncryptionKey getKey() {
        return getFieldAs(KEY, EncryptionKey.class);
    }

    public void setKey(EncryptionKey key) {
        setFieldAs(KEY, key);
    }

    public LastReq getLastReq() {
        return getFieldAs(LAST_REQ, LastReq.class);
    }

    public void setLastReq(LastReq lastReq) {
        setFieldAs(LAST_REQ, lastReq);
    }

    public int getNonce() {
        return getFieldAsInt(NONCE);
    }

    public void setNonce(int nonce) {
        setFieldAsInt(NONCE, nonce);
    }

    public KerberosTime getKeyExpiration() {
        return getFieldAsTime(KEY_EXPIRATION);
    }

    public void setKeyExpiration(KerberosTime keyExpiration) {
        setFieldAs(KEY_EXPIRATION, keyExpiration);
    }

    public TicketFlags getFlags() {
        return getFieldAs(FLAGS, TicketFlags.class);
    }

    public void setFlags(TicketFlags flags) {
        setFieldAs(FLAGS, flags);
    }

    public KerberosTime getAuthTime() {
        return getFieldAsTime(AUTHTIME);
    }

    public void setAuthTime(KerberosTime authTime) {
        setFieldAs(AUTHTIME, authTime);
    }

    public KerberosTime getStartTime() {
        return getFieldAsTime(STARTTIME);
    }

    public void setStartTime(KerberosTime startTime) {
        setFieldAs(STARTTIME, startTime);
    }

    public KerberosTime getEndTime() {
        return getFieldAsTime(ENDTIME);
    }

    public void setEndTime(KerberosTime endTime) {
        setFieldAs(ENDTIME, endTime);
    }

    public KerberosTime getRenewTill() {
        return getFieldAsTime(RENEW_TILL);
    }

    public void setRenewTill(KerberosTime renewTill) {
        setFieldAs(RENEW_TILL, renewTill);
    }

    public String getSrealm() {
        return getFieldAsString(SREALM);
    }

    public void setSrealm(String srealm) {
        setFieldAsString(SREALM, srealm);
    }

    public PrincipalName getSname() {
        return getFieldAs(SNAME, PrincipalName.class);
    }

    public void setSname(PrincipalName sname) {
        setFieldAs(SNAME, sname);
    }

    public HostAddresses getCaddr() {
        return getFieldAs(CADDR, HostAddresses.class);
    }

    public void setCaddr(HostAddresses caddr) {
        setFieldAs(CADDR, caddr);
    }
}
