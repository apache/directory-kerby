package org.haox.kerb.spec.ticket;

import org.apache.haox.asn1.type.Asn1FieldInfo;
import org.apache.haox.asn1.type.Asn1Integer;
import org.haox.kerb.KrbConstant;
import org.haox.kerb.spec.KerberosString;
import org.haox.kerb.spec.KrbAppSequenceType;
import org.haox.kerb.spec.common.EncryptedData;
import org.haox.kerb.spec.common.PrincipalName;

/**
 Ticket          ::= [APPLICATION 1] SEQUENCE {
 tkt-vno         [0] INTEGER (5),
 realm           [1] Realm,
 sname           [2] PrincipalName,
 enc-part        [3] EncryptedData -- EncTicketPart
 }
 */
public class Ticket extends KrbAppSequenceType {
    public static final int TKT_KVNO = KrbConstant.KRB_V5;
    public static final int TAG = 1;

    private static int TKT_VNO = 0;
    private static int REALM = 1;
    private static int SNAME = 2;
    private static int ENC_PART = 3;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(TKT_VNO, 0, Asn1Integer.class),
            new Asn1FieldInfo(REALM, 1, KerberosString.class),
            new Asn1FieldInfo(SNAME, 2, PrincipalName.class),
            new Asn1FieldInfo(ENC_PART, 3, EncryptedData.class)
    };

    public Ticket() {
        super(TAG, fieldInfos);
        setTktKvno(TKT_KVNO);
    }

    private EncTicketPart encPart;

    public int getTktvno() {
        return getFieldAsInt(TKT_VNO);
    }

    public void setTktKvno(int kvno) {
        setFieldAsInt(TKT_VNO, kvno);
    }
    public PrincipalName getSname() {
        return getFieldAs(SNAME, PrincipalName.class);
    }

    public void setSname(PrincipalName sname) {
        setFieldAs(SNAME, sname);
    }

    public String getRealm() {
        return getFieldAsString(REALM);
    }

    public void setRealm(String realm) {
        setFieldAs(REALM, new KerberosString(realm));
    }

    public EncryptedData getEncryptedEncPart() {
        return getFieldAs(ENC_PART, EncryptedData.class);
    }

    public void setEncryptedEncPart(EncryptedData encryptedEncPart) {
        setFieldAs(ENC_PART, encryptedEncPart);
    }

    public EncTicketPart getEncPart() {
        return encPart;
    }

    public void setEncPart(EncTicketPart encPart) {
        this.encPart = encPart;
    }
}
