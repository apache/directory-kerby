package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.*;

/**
 TransitedEncoding       ::= SEQUENCE {
 tr-type         [0] Int32 -- must be registered --,
 contents        [1] OCTET STRING
 }
 */
public interface TransitedEncoding extends SequenceType {
    public static enum Tag implements KrbTag {
        TR_TYPE(0, KrbInteger.class),
        CONTENTS(1, KrbOctetString.class);

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

    public TransitedEncodingType getTrType() throws KrbException;

    public void setTrType(TransitedEncodingType trType) throws KrbException;

    public byte[] getContents() throws KrbException;

    public void setContents(byte[] contents) throws KrbException;
}
