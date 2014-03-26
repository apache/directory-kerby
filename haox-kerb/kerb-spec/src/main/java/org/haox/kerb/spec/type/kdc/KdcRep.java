package org.haox.kerb.spec.type.kdc;

import org.haox.kerb.spec.type.KrbInteger;
import org.haox.kerb.spec.type.KrbString;
import org.haox.kerb.spec.type.KrbTag;
import org.haox.kerb.spec.type.KrbType;
import org.haox.kerb.spec.type.common.EncryptedData;
import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.spec.type.common.PaData;
import org.haox.kerb.spec.type.common.PrincipalName;
import org.haox.kerb.spec.type.ticket.Ticket;

/**
 KDC-REP         ::= SEQUENCE {
 pvno            [0] INTEGER (5),
 msg-type        [1] INTEGER (11 -- AS -- | 13 -- TGS --),
 padata          [2] SEQUENCE OF PA-DATA OPTIONAL
 -- NOTE: not empty --,
 crealm          [3] Realm,
 cname           [4] PrincipalName,
 ticket          [5] Ticket,
 enc-part        [6] EncryptedData
 -- EncASRepPart or EncTGSRepPart,
 -- as appropriate
 }
 */
public interface KdcRep extends KrbMessage {
    public static enum Tag implements KrbTag {
        PVNO(0, KrbInteger.class),
        MSG_TYPE(1, KrbInteger.class),
        PADATA(2, PaData.class),
        CREALM(3, KrbString.class),
        CNAME(4, PrincipalName.class),
        TICKET(5, Ticket.class),
        ENC_PART(6, EncryptedData.class);

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

    public PaData getPaData();

    public void setPaData(PaData paData);

    public String getCrealm();

    public void setCrealm(String crealm);

    public PrincipalName getCname();

    public void setCname(PrincipalName cname);

    public Ticket getTicket();

    public void setTicket(Ticket ticket);

    public EncryptedData getEncryptedEncPart();

    public void setEncryptedEncPart(EncryptedData encryptedEncPart);

    public EncKdcRepPart getEncPart();

    public void setEncPart(EncKdcRepPart encPart);
}
