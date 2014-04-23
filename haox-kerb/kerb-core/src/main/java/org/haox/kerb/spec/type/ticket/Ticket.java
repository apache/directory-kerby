package org.haox.kerb.spec.type.ticket;

import org.haox.asn1.type.Asn1Integer;
import org.haox.asn1.Asn1Tag;
import org.haox.kerb.spec.KrbConstant;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KerberosString;
import org.haox.kerb.spec.type.KrbSequenceType;
import org.haox.kerb.spec.type.common.EncryptedData;
import org.haox.kerb.spec.type.common.PrincipalName;

/**
 Ticket          ::= [APPLICATION 1] SEQUENCE {
 tkt-vno         [0] INTEGER (5),
 realm           [1] Realm,
 sname           [2] PrincipalName,
 enc-part        [3] EncryptedData -- EncTicketPart
 }
 */
public class Ticket extends KrbSequenceType {
    public static final int TKT_KVNO = KrbConstant.KERBEROS_V5;
    public static final int TAG = 1;

    private static int TKT_VNO = 0;
    private static int REALM = 1;
    private static int SNAME = 2;
    private static int ENC_PART = 3;

    static Asn1Tag[] tags = new Asn1Tag[] {
            new Asn1Tag(TKT_VNO, 0, Asn1Integer.class),
            new Asn1Tag(REALM, 1, KerberosString.class),
            new Asn1Tag(SNAME, 2, PrincipalName.class),
            new Asn1Tag(ENC_PART, 3, EncryptedData.class)
    };

    public Ticket() {
        super(TAG);
    }

    @Override
    protected Asn1Tag[] getTags() {
        return tags;
    }

    private EncTicketPart encPart;

    public int getTktvno() throws KrbException {
        return getFieldAsInt(TKT_VNO);
    }

    public PrincipalName getSname() throws KrbException {
        return getFieldAs(SNAME, PrincipalName.class);
    }

    public void setSname(PrincipalName sname) throws KrbException {
        setFieldAs(SNAME, sname);
    }

    public String getRealm() throws KrbException {
        return getFieldAsString(REALM);
    }

    public void setRealm(String realm) throws KrbException {
        setFieldAs(REALM, new KerberosString(realm));
    }

    public EncryptedData getEncryptedEncPart() throws KrbException {
        return getFieldAs(ENC_PART, EncryptedData.class);
    }

    public void setEncryptedEncPart(EncryptedData encryptedEncPart) throws KrbException {
        setFieldAs(ENC_PART, encryptedEncPart);
    }

    public EncTicketPart getEncPart() {
        return encPart;
    }

    public void setEncPart(EncTicketPart encPart) {
        this.encPart = encPart;
    }
}
