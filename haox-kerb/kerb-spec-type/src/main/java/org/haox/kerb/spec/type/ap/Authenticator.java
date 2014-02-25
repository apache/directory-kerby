package org.haox.kerb.spec.type.ap;

import org.haox.kerb.spec.type.common.*;

/**
 Authenticator   ::= [APPLICATION 2] SEQUENCE  {
 authenticator-vno       [0] INTEGER (5),
 crealm                  [1] Realm,
 cname                   [2] PrincipalName,
 cksum                   [3] Checksum OPTIONAL,
 cusec                   [4] Microseconds,
 ctime                   [5] KerberosTime,
 subkey                  [6] EncryptionKey OPTIONAL,
 seq-number              [7] UInt32 OPTIONAL,
 authorization-data      [8] AuthorizationData OPTIONAL
 }
 */
public class Authenticator {
    private int authenticatorVno;
    private String crealm;
    private PrincipalName cname;
    private Checksum cksum;
    private int cusec;
    private KerberosTime ctime;
    private EncryptionKey subKey;
    private Integer seqNumber;
    private AuthorizationData authorizationData;

    public int getAuthenticatorVno() {
        return authenticatorVno;
    }

    public void setAuthenticatorVno(int authenticatorVno) {
        this.authenticatorVno = authenticatorVno;
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

    public Checksum getCksum() {
        return cksum;
    }

    public void setCksum(Checksum cksum) {
        this.cksum = cksum;
    }

    public int getCusec() {
        return cusec;
    }

    public void setCusec(int cusec) {
        this.cusec = cusec;
    }

    public KerberosTime getCtime() {
        return ctime;
    }

    public void setCtime(KerberosTime ctime) {
        this.ctime = ctime;
    }

    public EncryptionKey getSubKey() {
        return subKey;
    }

    public void setSubKey(EncryptionKey subKey) {
        this.subKey = subKey;
    }

    public Integer getSeqNumber() {
        return seqNumber;
    }

    public void setSeqNumber(Integer seqNumber) {
        this.seqNumber = seqNumber;
    }

    public AuthorizationData getAuthorizationData() {
        return authorizationData;
    }

    public void setAuthorizationData(AuthorizationData authorizationData) {
        this.authorizationData = authorizationData;
    }
}
