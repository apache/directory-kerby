package org.haox.kerb.spec.type.ap;

import org.haox.asn1.type.Asn1Integer;
import org.haox.asn1.Asn1Tag;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KerberosString;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.KrbSequenceType;
import org.haox.kerb.spec.type.common.AuthorizationData;
import org.haox.kerb.spec.type.common.Checksum;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.PrincipalName;

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
public class Authenticator extends KrbSequenceType {
    private static int AUTHENTICATOR_VNO = 0;
    private static int CREALM = 1;
    private static int CNAME = 2;
    private static int CKSUM = 3;
    private static int CUSEC = 4;
    private static int CTIME = 5;
    private static int SUBKEY = 6;
    private static int SEQ_NUMBER = 7;
    private static int AUTHORIZATION_DATA = 8;

    static Asn1Tag[] tags = new Asn1Tag[] {
            new Asn1Tag(AUTHENTICATOR_VNO, 0, Asn1Integer.class),
            new Asn1Tag(CREALM, 1, KerberosString.class),
            new Asn1Tag(CNAME, 2, PrincipalName.class),
            new Asn1Tag(CKSUM, 3, Checksum.class),
            new Asn1Tag(CUSEC, 4, Asn1Integer.class),
            new Asn1Tag(CTIME, 5, KerberosTime.class),
            new Asn1Tag(SUBKEY, 6, EncryptionKey.class),
            new Asn1Tag(SEQ_NUMBER, 7, Asn1Integer.class),
            new Asn1Tag(AUTHORIZATION_DATA, 8, AuthorizationData.class)
    };

    public Authenticator() {
        super();
    }

    @Override
    protected Asn1Tag[] getTags() {
        return tags;
    }

    public int getAuthenticatorVno() throws KrbException {
        return getFieldAsInt(AUTHENTICATOR_VNO);
    }

    public void setAuthenticatorVno(int authenticatorVno) throws KrbException {
        setFieldAsInt(AUTHENTICATOR_VNO, authenticatorVno);
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

    public Checksum getCksum() throws KrbException {
        return getFieldAs(CKSUM, Checksum.class);
    }

    public void setCksum(Checksum cksum) throws KrbException {
        setFieldAs(CKSUM, cksum);
    }

    public int getCusec() throws KrbException {
        return getFieldAsInt(CUSEC);
    }

    public void setCusec(int cusec) throws KrbException {
        setFieldAsInt(CUSEC, cusec);
    }

    public KerberosTime getCtime() throws KrbException {
        return getFieldAsTime(CTIME);
    }

    public void setCtime(KerberosTime ctime) throws KrbException {
        setFieldAs(CTIME, ctime);
    }

    public EncryptionKey getSubKey() throws KrbException {
        return getFieldAs(SUBKEY, EncryptionKey.class);
    }

    public void setSubKey(EncryptionKey subKey) throws KrbException {
        setFieldAs(SUBKEY, subKey);
    }

    public int getSeqNumber() throws KrbException {
        return getFieldAsInt(SEQ_NUMBER);
    }

    public void setSeqNumber(Integer seqNumber) throws KrbException {
        setFieldAsInt(SEQ_NUMBER, seqNumber);
    }

    public AuthorizationData getAuthorizationData() throws KrbException {
        return getFieldAs(AUTHORIZATION_DATA, AuthorizationData.class);
    }

    public void setAuthorizationData(AuthorizationData authorizationData) throws KrbException {
        setFieldAs(AUTHORIZATION_DATA, authorizationData);
    }
}
