package org.apache.kerberos.kerb.spec.common;

import org.apache.haox.asn1.type.Asn1FieldInfo;
import org.apache.haox.asn1.type.Asn1Integer;
import org.apache.haox.asn1.type.Asn1OctetString;
import org.apache.kerberos.kerb.spec.KrbSequenceType;

import java.util.Arrays;

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

    public EncryptionType getEType() {
        Integer value = getFieldAsInteger(ETYPE);
        return EncryptionType.fromValue(value);
    }

    public void setEType(EncryptionType eType) {
        setFieldAsInt(ETYPE, eType.getValue());
    }

    public int getKvno() {
        Integer value = getFieldAsInteger(KVNO);
        if (value != null) {
            return value.intValue();
        }
        return -1;
    }

    public void setKvno(int kvno) {
        setFieldAsInt(KVNO, kvno);
    }

    public byte[] getCipher() {
        return getFieldAsOctets(CIPHER);
    }

    public void setCipher(byte[] cipher) {
        setFieldAsOctets(CIPHER, cipher);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        EncryptedData that = (EncryptedData) o;

        /*
        if (getKvno() != -1 && that.getKvno() != -1 &&
                getKvno() != that.getKvno()) return false;
        */

        if (getEType() != that.getEType()) return false;

        return Arrays.equals(getCipher(), that.getCipher());
    }
}
