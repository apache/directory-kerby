package org.haox.kerb.spec.type.kdc;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.asn1.type.Asn1Integer;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KerberosString;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.KrbIntegers;
import org.haox.kerb.spec.type.KrbSequenceType;
import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.type.ticket.Tickets;

import java.util.Set;

/**
 KDC-REQ-BODY    ::= SEQUENCE {
 kdc-options             [0] KDCOptions,
 cname                   [1] PrincipalName OPTIONAL
 -- Used only in AS-REQ --,
 realm                   [2] Realm
 -- Server's realm
 -- Also client's in AS-REQ --,
 sname                   [3] PrincipalName OPTIONAL,
 from                    [4] KerberosTime OPTIONAL,
 till                    [5] KerberosTime,
 rtime                   [6] KerberosTime OPTIONAL,
 nonce                   [7] UInt32,
 etype                   [8] SEQUENCE OF Int32 -- EncryptionType
 -- in preference order --,
 addresses               [9] HostAddresses OPTIONAL,
 enc-authorization-data  [10] EncryptedData OPTIONAL
 -- AuthorizationData --,
 additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
 -- NOTE: not empty
 }
 */
public class KdcReqBody extends KrbSequenceType {
    private static int KDC_OPTIONS = 0;
    private static int CNAME = 1;
    private static int REALM = 2;
    private static int SNAME = 3;
    private static int FROM = 4;
    private static int TILL = 5;
    private static int RTIME = 6;
    private static int NONCE = 7;
    private static int ETYPE = 8;
    private static int ADDRESSES = 9;
    private static int ENC_AUTHORIZATION_DATA = 10;
    private static int ADDITIONAL_TICKETS = 11;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(KDC_OPTIONS, 0, KdcOptions.class),
            new Asn1FieldInfo(CNAME, 1, PrincipalName.class),
            new Asn1FieldInfo(REALM, 2, KerberosString.class),
            new Asn1FieldInfo(SNAME, 3, PrincipalName.class),
            new Asn1FieldInfo(FROM, 4, KerberosTime.class),
            new Asn1FieldInfo(TILL, 5, KerberosTime.class),
            new Asn1FieldInfo(RTIME, 6, KerberosTime.class),
            new Asn1FieldInfo(NONCE, 7, Asn1Integer.class),
            new Asn1FieldInfo(ETYPE, 8, KrbIntegers.class),
            new Asn1FieldInfo(ADDRESSES, 9, HostAddresses.class),
            new Asn1FieldInfo(ENC_AUTHORIZATION_DATA, 10, AuthorizationData.class),
            new Asn1FieldInfo(ADDITIONAL_TICKETS, 11, Tickets.class)
    };

    public KdcReqBody() {
        super(fieldInfos);
    }

    private AuthorizationData authorizationData;

    public KerberosTime getFrom() throws KrbException {
        return getFieldAs(FROM, KerberosTime.class);
    }

    public void setFrom(KerberosTime from) throws KrbException {
        setFieldAs(FROM, from);
    }

    public KerberosTime getTill() throws KrbException {
        return getFieldAs(TILL, KerberosTime.class);
    }

    public void setTill(KerberosTime till) throws KrbException {
        setFieldAs(TILL, till);
    }


    public KerberosTime getRtime() throws KrbException {
        return getFieldAs(RTIME, KerberosTime.class);
    }


    public void setRtime(KerberosTime rtime) throws KrbException {
        setFieldAs(RTIME, rtime);
    }

    public int getNonce() {
        return 0;
    }

    public void setNonce(int nonce) {

    }

    public Set<EncryptionType> getEtype() {
        return null;
    }

    public void setEtype(Set<EncryptionType> etype) {

    }

    public HostAddresses getAddresses() {
        return null;
    }

    public void setAddresses(HostAddresses addresses) {

    }


    public EncryptedData getEncryptedAuthorizationData() throws KrbException {
        return getFieldAs(ENC_AUTHORIZATION_DATA, EncryptedData.class);
    }


    public void setEncryptedAuthorizationData(EncryptedData encAuthorizationData) throws KrbException {
        setFieldAs(ENC_AUTHORIZATION_DATA, encAuthorizationData);
    }


    public AuthorizationData getAuthorizationData() {
        return authorizationData;
    }


    public void setAuthorizationData(AuthorizationData authorizationData) {
        this.authorizationData = authorizationData;
    }


    public Tickets getAdditionalTickets() throws KrbException {
        return getFieldAs(ADDITIONAL_TICKETS, Tickets.class);
    }


    public void setAdditionalTickets(Tickets additionalTickets) throws KrbException {
        setFieldAs(ADDITIONAL_TICKETS, additionalTickets);
    }


    public KdcOptions getKdcOptions() throws KrbException {
        return getFieldAs(KDC_OPTIONS, KdcOptions.class);
    }


    public void setKdcOptions(KdcOptions kdcOptions) throws KrbException {
        setFieldAs(KDC_OPTIONS, kdcOptions);
    }

    public PrincipalName getSname() throws KrbException {
        return getFieldAs(SNAME, PrincipalName.class);
    }

    public void setSname(PrincipalName sname) throws KrbException {
        setFieldAs(SNAME, sname);
    }

    public PrincipalName getCname() throws KrbException {
        return getFieldAs(CNAME, PrincipalName.class);
    }

    public void setCname(PrincipalName cname) throws KrbException {
        setFieldAs(CNAME, cname);
    }

    public String getRealm() throws KrbException {
        return getFieldAsString(REALM);
    }

    public void setRealm(String realm) throws KrbException {
        setFieldAs(REALM, new KerberosString(realm));
    }
}
