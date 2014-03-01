package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KrbInteger;
import org.haox.kerb.spec.type.KrbOctetString;
import org.haox.kerb.spec.type.KrbTag;
import org.haox.kerb.spec.type.KrbType;

/**
 Checksum        ::= SEQUENCE {
 cksumtype       [0] Int32,
 checksum        [1] OCTET STRING
 }
 */
public interface MyChecksum extends KrbType {
    public static enum Tag implements KrbTag {
        CKSUM_TYPE(0, KrbInteger.class),
        CHECK_SUM(1, KrbOctetString.class);

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

    public ChecksumType getCksumtype();
    public void setCksumtype(ChecksumType cksumtype) throws KrbException;
    public byte[] getChecksum();
    public void setChecksum(byte[] checksum) throws KrbException;
}
