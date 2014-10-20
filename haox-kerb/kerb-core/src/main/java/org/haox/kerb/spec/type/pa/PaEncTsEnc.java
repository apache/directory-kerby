package org.haox.kerb.spec.type.pa;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.asn1.type.Asn1Integer;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.KrbSequenceType;

/**
 PA-ENC-TS-ENC           ::= SEQUENCE {
    patimestamp     [0] KerberosTime -- client's time --,
    pausec          [1] Microseconds OPTIONAL
 }
 */
public class PaEncTsEnc extends KrbSequenceType {
    private static int PATIMESTAMP = 0;
    private static int PAUSEC = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(PATIMESTAMP, 1, KerberosTime.class),
            new Asn1FieldInfo(PAUSEC, 2, Asn1Integer.class)
    };

    public PaEncTsEnc() {
        super(fieldInfos);
    }

    public KerberosTime getPaTimestamp() {
        return getFieldAsTime(PATIMESTAMP);
    }

    public void setPaTimestamp(KerberosTime paTimestamp) {
        setFieldAs(PATIMESTAMP, paTimestamp);
    }

    public int getPaUsec() {
        return getFieldAsInt(PAUSEC);
    }

    public void setPaUsec(int paUsec) {
        setFieldAsInt(PAUSEC, paUsec);
    }

    public KerberosTime getAllTime() {
        KerberosTime paTimestamp = getPaTimestamp();
        return paTimestamp.extend(getPaUsec() / 1000);
    }
}
