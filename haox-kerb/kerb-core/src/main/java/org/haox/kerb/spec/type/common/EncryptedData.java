package org.haox.kerb.spec.type.common;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.asn1.type.Asn1Integer;
import org.haox.asn1.type.Asn1OctetString;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KrbSequenceType;

/**
 EncryptedData   ::= SEQUENCE {
 etype   [0] Int32 -- EncryptionType --,
 kvno    [1] UInt32 OPTIONAL,
 cipher  [2] OCTET STRING -- ciphertext
 }
 */
public class EncryptedData extends KrbSequenceType {
    private static int ETYPE = 0;
    private static int KVNO = 1;
    private static int CIPHER = 2;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(ETYPE, 0, Asn1Integer.class),
            new Asn1FieldInfo(KVNO, 1, Asn1Integer.class),
            new Asn1FieldInfo(CIPHER, 2, Asn1OctetString.class)
    };

    public EncryptedData() {
        super(fieldInfos);
    }

    public EncryptionType getEType() throws KrbException {
        Integer value = getFieldAsInteger(ETYPE);
        return EncryptionType.fromValue(value);
    }

    public void setEType(EncryptionType eType) throws KrbException {
        setFieldAsInt(ETYPE, eType.getValue());
    }

    public int getKvno() throws KrbException {
        Integer value = getFieldAsInteger(KVNO);
        if (value != null) {
            return value.intValue();
        }
        return -1;
    }

    public void setKvno(int kvno) throws KrbException {
        setFieldAsInt(KVNO, kvno);
    }

    public byte[] getCipher() throws KrbException {
        return getFieldAsOctetBytes(CIPHER);
    }

    public void setCipher(byte[] cipher) throws KrbException {
        setFieldAsOctetBytes(CIPHER, cipher);
    }
}
