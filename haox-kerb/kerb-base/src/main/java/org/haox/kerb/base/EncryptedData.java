package org.haox.kerb.base;

/**
 EncryptedData   ::= SEQUENCE {
 etype   [0] Int32 -- EncryptionType --,
 kvno    [1] UInt32 OPTIONAL,
 cipher  [2] OCTET STRING -- ciphertext
 }
 */
public class EncryptedData {
    private EncryptionType eType;
    private int kvno;
    private byte[] cipher;

    public EncryptionType geteType() {
        return eType;
    }

    public void seteType(EncryptionType eType) {
        this.eType = eType;
    }

    public int getKvno() {
        return kvno;
    }

    public void setKvno(int kvno) {
        this.kvno = kvno;
    }

    public byte[] getCipher() {
        return cipher;
    }

    public void setCipher(byte[] cipher) {
        this.cipher = cipher;
    }
}
