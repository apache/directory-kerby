package org.haox.kerb.spec.type.common;

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
        CK_SUM_TYPE(0xA0),
        CHECK_SUM(0xA1);

        private int value;

        private Tag(int value) {
            this.value = value;
        }

        @Override
        public int getTag() {
            return value;
        }
    };

    public ChecksumType getCksumtype();
    public void setCksumtype(ChecksumType cksumtype);
    public byte[] getChecksum();
    public void setChecksum(byte[] checksum);
}
