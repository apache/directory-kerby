package org.haox.kerb.spec.type.ap;

import org.haox.asn1.Asn1Tag;
import org.haox.asn1.type.Asn1Integer;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.KrbAppSequenceType;
import org.haox.kerb.spec.type.common.EncryptionKey;

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

    static Asn1Tag[] tags = new Asn1Tag[] {
            new Asn1Tag(CTIME, 0, KerberosTime.class),
            new Asn1Tag(CUSEC, 1, Asn1Integer.class),
            new Asn1Tag(SUBKEY, 2, EncryptionKey.class),
            new Asn1Tag(SEQ_NUMBER, 3, Asn1Integer.class)
    };

    @Override
    protected Asn1Tag[] getTags() {
        return tags;
    }

    public EncAPRepPart() {
        super(TAG);
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
