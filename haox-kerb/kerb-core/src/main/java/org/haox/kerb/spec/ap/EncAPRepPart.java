package org.haox.kerb.spec.ap;

import org.apache.haox.asn1.type.Asn1FieldInfo;
import org.apache.haox.asn1.type.Asn1Integer;
import org.haox.kerb.spec.KerberosTime;
import org.haox.kerb.spec.KrbAppSequenceType;
import org.haox.kerb.spec.common.EncryptionKey;

/**
 EncAPRepPart    ::= [APPLICATION 27] SEQUENCE {
 ctime           [0] KerberosTime,
 cusec           [1] Microseconds,
 subkey          [2] EncryptionKey OPTIONAL,
 seq-number      [3] UInt32 OPTIONAL
 }
 */
public class EncAPRepPart extends KrbAppSequenceType {
    public static int TAG = 27;
    private static int CTIME = 0;
    private static int CUSEC = 1;
    private static int SUBKEY = 2;
    private static int SEQ_NUMBER = 3;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(CTIME, 0, KerberosTime.class),
            new Asn1FieldInfo(CUSEC, 1, Asn1Integer.class),
            new Asn1FieldInfo(SUBKEY, 2, EncryptionKey.class),
            new Asn1FieldInfo(SEQ_NUMBER, 3, Asn1Integer.class)
    };

    public EncAPRepPart() {
        super(TAG, fieldInfos);
    }

    public KerberosTime getCtime() {
        return getFieldAsTime(CTIME);
    }

    public void setCtime(KerberosTime ctime) {
        setFieldAs(CTIME, ctime);
    }

    public int getCusec() {
        return getFieldAsInt(CUSEC);
    }

    public void setCusec(int cusec) {
        setFieldAsInt(CUSEC, cusec);
    }

    public EncryptionKey getSubkey() {
        return getFieldAs(SUBKEY, EncryptionKey.class);
    }

    public void setSubkey(EncryptionKey subkey) {
        setFieldAs(SUBKEY, subkey);
    }

    public int getSeqNumber() {
        return getFieldAsInt(SEQ_NUMBER);
    }

    public void setSeqNumber(Integer seqNumber) {
        setFieldAsInt(SEQ_NUMBER, seqNumber);
    }
}
