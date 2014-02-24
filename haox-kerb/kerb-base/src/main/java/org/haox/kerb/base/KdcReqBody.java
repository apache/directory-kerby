package org.haox.kerb.base;

import java.util.List;
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
public class KdcReqBody {
    private KdcOptions kdcOptions;
    private PrincipalName cname;
    private String realm;
    private PrincipalName sname;
    private KerberosTime from;
    private KerberosTime till;
    private KerberosTime rtime;
    private int nonce;
    private Set<EncryptionType> etype;
    private HostAddresses addresses;
    private EncryptedData encAuthorizationData;
    private List<Ticket> additionalTickets;

    public KdcOptions getKdcOptions() {
        return kdcOptions;
    }

    public void setKdcOptions(KdcOptions kdcOptions) {
        this.kdcOptions = kdcOptions;
    }

    public PrincipalName getCname() {
        return cname;
    }

    public void setCname(PrincipalName cname) {
        this.cname = cname;
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public PrincipalName getSname() {
        return sname;
    }

    public void setSname(PrincipalName sname) {
        this.sname = sname;
    }

    public KerberosTime getFrom() {
        return from;
    }

    public void setFrom(KerberosTime from) {
        this.from = from;
    }

    public KerberosTime getTill() {
        return till;
    }

    public void setTill(KerberosTime till) {
        this.till = till;
    }

    public KerberosTime getRtime() {
        return rtime;
    }

    public void setRtime(KerberosTime rtime) {
        this.rtime = rtime;
    }

    public int getNonce() {
        return nonce;
    }

    public void setNonce(int nonce) {
        this.nonce = nonce;
    }

    public Set<EncryptionType> getEtype() {
        return etype;
    }

    public void setEtype(Set<EncryptionType> etype) {
        this.etype = etype;
    }

    public HostAddresses getAddresses() {
        return addresses;
    }

    public void setAddresses(HostAddresses addresses) {
        this.addresses = addresses;
    }

    public EncryptedData getEncAuthorizationData() {
        return encAuthorizationData;
    }

    public void setEncAuthorizationData(EncryptedData encAuthorizationData) {
        this.encAuthorizationData = encAuthorizationData;
    }

    public List<Ticket> getAdditionalTickets() {
        return additionalTickets;
    }

    public void setAdditionalTickets(List<Ticket> additionalTickets) {
        this.additionalTickets = additionalTickets;
    }
}
