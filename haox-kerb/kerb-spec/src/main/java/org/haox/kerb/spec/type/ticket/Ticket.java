package org.haox.kerb.spec.type.ticket;

import org.haox.kerb.spec.KrbConstant;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.*;
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
public interface Ticket extends SequenceType {
    public static final int TKT_KVNO = KrbConstant.KERBEROS_V5;

    public static enum Tag implements KrbTag {
        TKT_VNO(0, KrbInteger.class),
        REALM(1, KrbString.class),
        SNAME(2, PrincipalName.class),
        ENC_PART(3, EncryptedData.class);

        private int value;
        private Class<? extends KrbType> type;

        private Tag(int value, Class<? extends KrbType> type) {
            this.value = value;
            this.type = type;
        }

        @Override
        public int getValue() {
            return value;
        }

        @Override
        public int getIndex() {
            return ordinal();
        }

        @Override
        public Class<? extends KrbType> getType() {
            return type;
        }
    };

    public int getTktvno() throws KrbException;

    public String getSname() throws KrbException;

    public void setSname(String sname) throws KrbException;

    public String getRealm() throws KrbException;

    public void setRealm(String realm) throws KrbException;

    public EncryptedData getEncryptedEncPart() throws KrbException;

    public void setEncryptedEncPart(EncryptedData encryptedEncPart) throws KrbException;

    public EncTicketPart getEncPart();

    public void setEncPart(EncTicketPart encPart);
}
