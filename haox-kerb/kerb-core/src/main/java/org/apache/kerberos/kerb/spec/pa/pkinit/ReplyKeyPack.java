package org.apache.kerberos.kerb.spec.pa.pkinit;

import org.apache.haox.asn1.type.Asn1FieldInfo;
import org.apache.kerberos.kerb.spec.KrbSequenceType;
import org.apache.kerberos.kerb.spec.common.CheckSum;
import org.apache.kerberos.kerb.spec.common.EncryptionKey;

/**
 ReplyKeyPack ::= SEQUENCE {
    replyKey                [0] EncryptionKey,
    asChecksum              [1] Checksum,
 }
 */
public class ReplyKeyPack extends KrbSequenceType {
    private static int REPLY_KEY = 0;
    private static int AS_CHECKSUM = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(REPLY_KEY, EncryptionKey.class),
            new Asn1FieldInfo(AS_CHECKSUM, CheckSum.class)
    };

    public ReplyKeyPack() {
        super(fieldInfos);
    }

    public EncryptionKey getReplyKey() {
        return getFieldAs(REPLY_KEY, EncryptionKey.class);
    }

    public void setReplyKey(EncryptionKey replyKey) {
        setFieldAs(REPLY_KEY, replyKey);
    }

    public CheckSum getAsChecksum() {
        return getFieldAs(AS_CHECKSUM, CheckSum.class);
    }

    public void setAsChecksum(CheckSum checkSum) {
        setFieldAs(AS_CHECKSUM, checkSum);
    }
}
