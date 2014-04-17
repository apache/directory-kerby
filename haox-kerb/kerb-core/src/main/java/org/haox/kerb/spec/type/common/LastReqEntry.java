package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.type.KrbInteger;
import org.haox.kerb.spec.type.KrbTag;
import org.haox.kerb.spec.type.KrbType;
import org.haox.kerb.spec.type.SequenceType;

/**
 LastReq         ::=     SEQUENCE OF SEQUENCE {
 lr-type         [0] Int32,
 lr-value        [1] KrbTime
 }
 */
public interface LastReqEntry extends SequenceType {
    public static enum Tag implements KrbTag {
        LR_TYPE(0, KrbInteger.class),
        LR_VALUE(1, KrbTime.class);

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

    public LastReqType getLrType();

    public void setLrType(LastReqType lrType);

    public KrbTime getLrValue();

    public void setLrValue(KrbTime lrValue);
}
