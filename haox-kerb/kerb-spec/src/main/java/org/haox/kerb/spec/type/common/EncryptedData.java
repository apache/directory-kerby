package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.*;

/**
 EncryptedData   ::= SEQUENCE {
 etype   [0] Int32 -- EncryptionType --,
 kvno    [1] UInt32 OPTIONAL,
 cipher  [2] OCTET STRING -- ciphertext
 }
 */
public interface EncryptedData extends SequenceType {
    public static enum Tag implements KrbTag {
        ETYPE(0, KrbInteger.class),
        KVNO(1, KrbInteger.class),
        CIPHER(2, KrbOctetString.class);

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
    public EncryptionType geteType() throws KrbException;

    public void seteType(EncryptionType eType) throws KrbException;

    public int getKvno() throws KrbException;

    public void setKvno(int kvno) throws KrbException;

    public byte[] getCipher() throws KrbException;

    public void setCipher(byte[] cipher) throws KrbException;
}
