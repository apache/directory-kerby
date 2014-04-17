package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.*;

/**
 PA-DATA         ::= SEQUENCE {
 -- NOTE: first tag is [1], not [0]
 padata-type     [1] Int32,
 padata-value    [2] OCTET STRING -- might be encoded AP-REQ
 }
 */
public interface PaDataEntry extends SequenceType {
    public static enum Tag implements KrbTag {
        PADATA_TYPE(1, KrbInteger.class),
        PADATA_VALUE(2, KrbOctetString.class);

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
            return ordinal() - 1;
        }

        @Override
        public Class<? extends KrbType> getType() {
            return type;
        }
    };

    public PaDataType getPaDataType() throws KrbException;

    public void setPaDataType(PaDataType paDataType) throws KrbException;

    public byte[] getPaDataValue() throws KrbException;

    public void setPaDataValue(byte[] paDataValue) throws KrbException;
}
