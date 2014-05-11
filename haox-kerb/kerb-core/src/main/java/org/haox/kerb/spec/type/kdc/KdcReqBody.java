package org.haox.kerb.spec.type.kdc;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.asn1.type.Asn1Integer;
import org.haox.kerb.spec.type.KerberosString;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.KrbIntegers;
import org.haox.kerb.spec.type.KrbSequenceType;
import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.type.ticket.Tickets;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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
            new Asn1FieldInfo(KDC_OPTIONS, KdcOptions.class),
            new Asn1FieldInfo(CNAME, PrincipalName.class),
            new Asn1FieldInfo(REALM, KerberosString.class),
            new Asn1FieldInfo(SNAME, PrincipalName.class),
            new Asn1FieldInfo(FROM, KerberosTime.class),
            new Asn1FieldInfo(TILL, KerberosTime.class),
            new Asn1FieldInfo(RTIME, KerberosTime.class),
            new Asn1FieldInfo(NONCE, Asn1Integer.class),
            new Asn1FieldInfo(ETYPE, KrbIntegers.class),
            new Asn1FieldInfo(ADDRESSES, HostAddresses.class),
            new Asn1FieldInfo(ENC_AUTHORIZATION_DATA, AuthorizationData.class),
            new Asn1FieldInfo(ADDITIONAL_TICKETS, Tickets.class)
    };

    public KdcReqBody() {
        super(fieldInfos);
    }

    private AuthorizationData authorizationData;

    public KerberosTime getFrom() {
        return getFieldAs(FROM, KerberosTime.class);
    }

    public void setFrom(KerberosTime from) {
        setFieldAs(FROM, from);
    }

    public KerberosTime getTill() {
        return getFieldAs(TILL, KerberosTime.class);
    }

    public void setTill(KerberosTime till) {
        setFieldAs(TILL, till);
    }

    public KerberosTime getRtime() {
        return getFieldAs(RTIME, KerberosTime.class);
    }

    public void setRtime(KerberosTime rtime) {
        setFieldAs(RTIME, rtime);
    }

    public int getNonce() {
        return getFieldAsInt(NONCE);
    }

    public void setNonce(int nonce) {
        setFieldAsInt(NONCE, nonce);
    }

    public List<EncryptionType> getEtypes() {
        KrbIntegers values = getFieldAs(ETYPE, KrbIntegers.class);
        if (values == null) {
            return Collections.emptyList();
        }

        List<EncryptionType> results = new ArrayList<EncryptionType>();
        for (Integer value : values.getValues()) {
            results.add(EncryptionType.fromValue(value));
        }
        return results;
    }

    public void setEtypes(List<EncryptionType> etypes) {
        List<Integer> values = new ArrayList<Integer>();
        for (EncryptionType etype: etypes) {
            values.add(etype.getValue());
        }
        KrbIntegers value = new KrbIntegers(values);
        setFieldAs(ETYPE, value);
    }

    public HostAddresses getAddresses() {
        return getFieldAs(ADDRESSES, HostAddresses.class);
    }

    public void setAddresses(HostAddresses addresses) {
        setFieldAs(ADDRESSES, addresses);
    }

    public EncryptedData getEncryptedAuthorizationData() {
        return getFieldAs(ENC_AUTHORIZATION_DATA, EncryptedData.class);
    }

    public void setEncryptedAuthorizationData(EncryptedData encAuthorizationData) {
        setFieldAs(ENC_AUTHORIZATION_DATA, encAuthorizationData);
    }

    public AuthorizationData getAuthorizationData() {
        return authorizationData;
    }

    public void setAuthorizationData(AuthorizationData authorizationData) {
        this.authorizationData = authorizationData;
    }

    public Tickets getAdditionalTickets() {
        return getFieldAs(ADDITIONAL_TICKETS, Tickets.class);
    }

    public void setAdditionalTickets(Tickets additionalTickets) {
        setFieldAs(ADDITIONAL_TICKETS, additionalTickets);
    }

    public KdcOptions getKdcOptions() {
        return getFieldAs(KDC_OPTIONS, KdcOptions.class);
    }

    public void setKdcOptions(KdcOptions kdcOptions) {
        setFieldAs(KDC_OPTIONS, kdcOptions);
    }

    public PrincipalName getSname() {
        return getFieldAs(SNAME, PrincipalName.class);
    }

    public void setSname(PrincipalName sname) {
        setFieldAs(SNAME, sname);
    }

    public PrincipalName getCname() {
        return getFieldAs(CNAME, PrincipalName.class);
    }

    public void setCname(PrincipalName cname) {
        setFieldAs(CNAME, cname);
    }

    public String getRealm() {
        return getFieldAsString(REALM);
    }

    public void setRealm(String realm) {
        setFieldAs(REALM, new KerberosString(realm));
    }
}
