package org.haox.kerb.spec.type.ticket;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.kerb.spec.KrbException;
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

    public TicketFlags getFlags() throws KrbException {
        return getFieldAs(FLAGS, TicketFlags.class);
    }


    public void setFlags(TicketFlags flags) throws KrbException {
        setFieldAs(FLAGS, flags);
    }


    public EncryptionKey getKey() throws KrbException {
        return getFieldAs(KEY, EncryptionKey.class);
    }


    public void setKey(EncryptionKey key) throws KrbException {
        setFieldAs(KEY, key);
    }


    public String getCrealm() throws KrbException {
        return getFieldAsString(CREALM);
    }


    public void setCrealm(String crealm) throws KrbException {
        setFieldAsString(CREALM, crealm);
    }


    public PrincipalName getCname() throws KrbException {
        return getFieldAs(CNAME, PrincipalName.class);
    }


    public void setCname(PrincipalName cname) throws KrbException {
        setFieldAs(CNAME, cname);
    }


    public TransitedEncoding getTransited() throws KrbException {
        return getFieldAs(TRANSITED, TransitedEncoding.class);
    }


    public void setTransited(TransitedEncoding transited) throws KrbException {
        setFieldAs(TRANSITED, transited);
    }


    public KerberosTime getAuthTime() throws KrbException {
        return getFieldAs(AUTHTIME, KerberosTime.class);
    }


    public void setAuthTime(KerberosTime authTime) throws KrbException {
        setFieldAs(AUTHTIME, authTime);
    }


    public KerberosTime getStartTime() throws KrbException {
        return getFieldAs(STARTTIME, KerberosTime.class);
    }


    public void setStartTime(KerberosTime startTime) throws KrbException {
        setFieldAs(STARTTIME, startTime);
    }


    public KerberosTime getEndTime() throws KrbException {
        return getFieldAs(ENDTIME, KerberosTime.class);
    }


    public void setEndTime(KerberosTime endTime) throws KrbException {
        setFieldAs(ENDTIME, endTime);
    }


    public KerberosTime getRenewtill() throws KrbException {
        return getFieldAs(RENEW_TILL, KerberosTime.class);
    }


    public void setRenewtill(KerberosTime renewtill) throws KrbException {
        setFieldAs(RENEW_TILL, renewtill);
    }


    public HostAddresses getClientAddresses() throws KrbException {
        return getFieldAs(CADDR, HostAddresses.class);
    }


    public void setClientAddresses(HostAddresses clientAddresses) throws KrbException {
        setFieldAs(CADDR, clientAddresses);
    }


    public AuthorizationData getAuthorizationData() throws KrbException {
        return getFieldAs(AUTHORIZATION_DATA, AuthorizationData.class);
    }


    public void setAuthorizationData(AuthorizationData authorizationData) throws KrbException {
        setFieldAs(AUTHORIZATION_DATA, authorizationData);
    }
}
