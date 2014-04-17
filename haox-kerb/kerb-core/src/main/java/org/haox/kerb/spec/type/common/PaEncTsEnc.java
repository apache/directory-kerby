package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KrbInteger;
import org.haox.kerb.spec.type.KrbTag;
import org.haox.kerb.spec.type.KrbType;

/**
 PA-ENC-TS-ENC           ::= SEQUENCE {
 patimestamp     [0] KerberosTime -- client's time --,
 pausec          [1] Microseconds OPTIONAL
 }
 */
public interface PaEncTsEnc extends KrbType {
    public static enum Tag implements KrbTag {
        PATIMESTAMP(0, KrbTime.class),
        PAUSEC(1, KrbInteger.class);

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

    public KrbTime getPaTimestamp() throws KrbException;

    public void setPaTimestamp(KrbTime paTimestamp) throws KrbException;

    public long getPaUsec() throws KrbException;

    public void setPaUsec(long paUsec) throws KrbException;
}
