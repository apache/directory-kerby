package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.*;

/**
 AuthorizationData       ::= SEQUENCE OF SEQUENCE {
 ad-type         [0] Int32,
 ad-data         [1] OCTET STRING
 }
 */
public interface AuthorizationDataEntry extends SequenceType {
    public static enum Tag implements KrbTag {
        AD_TYPE(0, KrbInteger.class),
        AD_DATA(1, KrbOctetString.class);

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

    public AuthorizationType getAuthzType() throws KrbException;

    public void setAuthzType(AuthorizationType authzType) throws KrbException;

    public byte[] getAuthzData() throws KrbException;

    public void setAuthzData(byte[] authzData) throws KrbException;
}
