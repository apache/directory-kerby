package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KrbInteger;
import org.haox.kerb.spec.type.KrbOctetString;
import org.haox.kerb.spec.type.KrbTag;
import org.haox.kerb.spec.type.KrbType;

/**
 EncryptionKey   ::= SEQUENCE {
 keytype         [0] Int32 -- actually encryption type --,
 keyvalue        [1] OCTET STRING
 }
 */
public interface EncryptionKey extends KrbType {
    public static enum Tag implements KrbTag {
        KEY_TYPE(0, KrbInteger.class),
        KEY_VALUE(1, KrbOctetString.class);

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

    public EncryptionType getKeyType() throws KrbException;

    public void setKeyType(EncryptionType keyType) throws KrbException;

    public byte[] getKeyData() throws KrbException;

    public void setKeyData(byte[] keyData) throws KrbException;
}
