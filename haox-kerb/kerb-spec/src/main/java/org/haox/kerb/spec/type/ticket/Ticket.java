package org.haox.kerb.spec.type.ticket;

import org.haox.kerb.spec.KrbConstant;
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

    public int getTktvno();

    public String getSname();

    public void setSname(String sname);

    public String getRealm();

    public void setRealm(String realm);

    public EncryptedData getEncryptedEncPart();

    public void setEncryptedEncPart(EncryptedData encryptedEncPart);

    public EncTicketPart getEncPart();

    public void setEncPart(EncTicketPart encPart);
}
