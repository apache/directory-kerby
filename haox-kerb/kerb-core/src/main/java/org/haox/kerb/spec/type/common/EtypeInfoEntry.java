package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.type.*;

/**
 ETYPE-INFO-ENTRY        ::= SEQUENCE {
 etype           [0] Int32,
 salt            [1] OCTET STRING OPTIONAL
 }
 */
public interface EtypeInfoEntry extends SequenceType {
    public static enum Tag implements KrbTag {
        ETYPE(0, KrbInteger.class),
        SALT(1, KrbOctetString.class);

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

    public byte[] getSalt();

    public void setSalt(byte[] salt);

    public int getEtype();

    public void setEtype(int etype);
}
