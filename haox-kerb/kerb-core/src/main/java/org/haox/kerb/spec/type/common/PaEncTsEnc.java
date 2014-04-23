package org.haox.kerb.spec.type.common;

import org.haox.asn1.type.Asn1Integer;
import org.haox.asn1.Asn1Tag;
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

    static Asn1Tag[] tags = new Asn1Tag[] {
            new Asn1Tag(PATIMESTAMP, 1, KerberosTime.class),
            new Asn1Tag(PAUSEC, 2, Asn1Integer.class)
    };

    @Override
    protected Asn1Tag[] getTags() {
        return tags;
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
}
