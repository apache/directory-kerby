package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.*;

/*
HostAddress     ::= SEQUENCE  {
        addr-type       [0] Int32,
        address         [1] OCTET STRING
}
 */
public interface HostAddress extends SequenceType {
    public static enum Tag implements KrbTag {
        ADDR_TYPE(0, KrbInteger.class),
        ADDRESS(1, KrbOctetString.class);

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

    public HostAddrType getAddrType() throws KrbException;

    public void setAddrType(HostAddrType addrType) throws KrbException;

    public byte[] getAddress() throws KrbException;

    public void setAddress(byte[] address) throws KrbException;
}
