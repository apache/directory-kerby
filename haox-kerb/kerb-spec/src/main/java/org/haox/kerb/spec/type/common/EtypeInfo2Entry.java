package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.type.*;

/**
 ETYPE-INFO2-ENTRY       ::= SEQUENCE {
 etype           [0] Int32,
 salt            [1] KerberosString OPTIONAL,
 s2kparams       [2] OCTET STRING OPTIONAL
 }
 */
public interface EtypeInfo2Entry extends SequenceType {
    public static enum Tag implements KrbTag {
        ETYPE(0, KrbInteger.class),
        SALT(1, KrbOctetString.class),
        S2KPARAMS(2, KrbOctetString.class);

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

    public byte[] getS2kParams();

    public void setS2kParams(byte[] s2kParams);

}
