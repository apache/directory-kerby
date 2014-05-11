package org.haox.kerb.spec.type.ticket;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.kerb.spec.type.KerberosString;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.KrbAppSequenceType;
import org.haox.kerb.spec.type.common.*;

/**
 -- Encrypted part of ticket
 EncTicketPart   ::= [APPLICATION 3] SEQUENCE {
 flags                   [0] TicketFlags,
 key                     [1] EncryptionKey,
 crealm                  [2] Realm,
 cname                   [3] PrincipalName,
 transited               [4] TransitedEncoding,
 authtime                [5] KerberosTime,
 starttime               [6] KerberosTime OPTIONAL,
 endtime                 [7] KerberosTime,
 renew-till              [8] KerberosTime OPTIONAL,
 caddr                   [9] HostAddresses OPTIONAL,
 authorization-data      [10] AuthorizationData OPTIONAL
 }
 */
public class EncTicketPart extends KrbAppSequenceType {
    public static final int TAG = 3;

    private static int FLAGS = 0;
    private static int KEY = 1;
    private static int CREALM = 2;
    private static int CNAME = 3;
    private static int TRANSITED = 4;
    private static int AUTHTIME = 5;
    private static int STARTTIME = 6;
    private static int ENDTIME = 7;
    private static int RENEW_TILL = 8;
    private static int CADDR = 9;
    private static int AUTHORIZATION_DATA = 10;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(FLAGS, 0, TicketFlags.class),
            new Asn1FieldInfo(KEY, 1, EncryptionKey.class),
            new Asn1FieldInfo(CREALM, 2, KerberosString.class),
            new Asn1FieldInfo(CNAME, 3, PrincipalName.class),
            new Asn1FieldInfo(TRANSITED, 4, TransitedEncoding.class),
            new Asn1FieldInfo(AUTHTIME, 5, KerberosTime.class),
            new Asn1FieldInfo(STARTTIME, 6, KerberosTime.class),
            new Asn1FieldInfo(ENDTIME, 7, KerberosTime.class),
            new Asn1FieldInfo(ENDTIME, 8, KerberosTime.class),
            new Asn1FieldInfo(CADDR, 9, HostAddresses.class),
            new Asn1FieldInfo(AUTHORIZATION_DATA, 10, AuthorizationData.class)
    };

    public EncTicketPart() {
        super(TAG, fieldInfos);
    }

    public TicketFlags getFlags() {
        return getFieldAs(FLAGS, TicketFlags.class);
    }


    public void setFlags(TicketFlags flags) {
        setFieldAs(FLAGS, flags);
    }


    public EncryptionKey getKey() {
        return getFieldAs(KEY, EncryptionKey.class);
    }


    public void setKey(EncryptionKey key) {
        setFieldAs(KEY, key);
    }


    public String getCrealm() {
        return getFieldAsString(CREALM);
    }


    public void setCrealm(String crealm) {
        setFieldAsString(CREALM, crealm);
    }


    public PrincipalName getCname() {
        return getFieldAs(CNAME, PrincipalName.class);
    }


    public void setCname(PrincipalName cname) {
        setFieldAs(CNAME, cname);
    }


    public TransitedEncoding getTransited() {
        return getFieldAs(TRANSITED, TransitedEncoding.class);
    }


    public void setTransited(TransitedEncoding transited) {
        setFieldAs(TRANSITED, transited);
    }


    public KerberosTime getAuthTime() {
        return getFieldAs(AUTHTIME, KerberosTime.class);
    }


    public void setAuthTime(KerberosTime authTime) {
        setFieldAs(AUTHTIME, authTime);
    }


    public KerberosTime getStartTime() {
        return getFieldAs(STARTTIME, KerberosTime.class);
    }


    public void setStartTime(KerberosTime startTime) {
        setFieldAs(STARTTIME, startTime);
    }


    public KerberosTime getEndTime() {
        return getFieldAs(ENDTIME, KerberosTime.class);
    }


    public void setEndTime(KerberosTime endTime) {
        setFieldAs(ENDTIME, endTime);
    }


    public KerberosTime getRenewtill() {
        return getFieldAs(RENEW_TILL, KerberosTime.class);
    }


    public void setRenewtill(KerberosTime renewtill) {
        setFieldAs(RENEW_TILL, renewtill);
    }


    public HostAddresses getClientAddresses() {
        return getFieldAs(CADDR, HostAddresses.class);
    }


    public void setClientAddresses(HostAddresses clientAddresses) {
        setFieldAs(CADDR, clientAddresses);
    }


    public AuthorizationData getAuthorizationData() {
        return getFieldAs(AUTHORIZATION_DATA, AuthorizationData.class);
    }


    public void setAuthorizationData(AuthorizationData authorizationData) {
        setFieldAs(AUTHORIZATION_DATA, authorizationData);
    }
}
