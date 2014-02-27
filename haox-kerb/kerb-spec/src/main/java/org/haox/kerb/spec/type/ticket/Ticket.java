package org.haox.kerb.spec.type.ticket;

import org.haox.kerb.spec.KrbConstant;
import org.haox.kerb.spec.type.common.EncryptedData;

/**
 Ticket          ::= [APPLICATION 1] SEQUENCE {
 tkt-vno         [0] INTEGER (5),
 realm           [1] Realm,
 sname           [2] PrincipalName,
 enc-part        [3] EncryptedData -- EncTicketPart
 }
 */
public class Ticket {
    public static final int TKT_KVNO = KrbConstant.KERBEROS_V5;

    private final int tktvno = TKT_KVNO;
    private String sname;
    private String realm;
    private EncTicketPart encPart;
    private EncryptedData encryptedEncPart;
    //
    public int getTktvno() {
        return tktvno;
    }

    public String getSname() {
        return sname;
    }

    public void setSname(String sname) {
        this.sname = sname;
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public EncryptedData getEncryptedEncPart() {
        return encryptedEncPart;
    }

    public void setEncryptedEncPart(EncryptedData encryptedEncPart) {
        this.encryptedEncPart = encryptedEncPart;
    }

    public EncTicketPart getEncPart() {
        return encPart;
    }

    public void setEncPart(EncTicketPart encPart) {
        this.encPart = encPart;
    }
}
