package org.haox.kerb.spec.type.fast;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.kerb.spec.type.KrbSequenceType;
import org.haox.kerb.spec.type.common.Checksum;
import org.haox.kerb.spec.type.common.EncryptedData;
import org.haox.kerb.spec.type.pa.PaData;

/**
 KrbFastFinished ::= SEQUENCE {
     timestamp       [0] KerberosTime,
     usec            [1] Microseconds,
     -- timestamp and usec represent the time on the KDC when
     -- the reply was generated.
     crealm          [2] Realm,
     cname           [3] PrincipalName,
     -- Contains the client realm and the client name.
     ticket-checksum [4] Checksum,
     -- checksum of the ticket in the KDC-REP using the armor
     -- and the key usage is KEY_USAGE_FAST_FINISH.
     -- The checksum type is the required checksum type
     -- of the armor key.
 }
 */
public class KrbFastFinished extends KrbSequenceType {
    private static int FAST_OPTIONS = 0;
    private static int PADATA = 1;
    private static int REQ_BODY = 2;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(FAST_OPTIONS, KrbFastArmor.class),
            new Asn1FieldInfo(PADATA, PaData.class),
            new Asn1FieldInfo(REQ_BODY, EncryptedData.class),
    };

    public KrbFastFinished() {
        super(fieldInfos);
    }

    public KrbFastArmor getArmor() {
        return getFieldAs(FAST_OPTIONS, KrbFastArmor.class);
    }

    public void setArmor(KrbFastArmor armor) {
        setFieldAs(FAST_OPTIONS, armor);
    }

    public Checksum getReqChecksum() {
        return getFieldAs(PADATA, Checksum.class);
    }

    public void setReqChecksum(Checksum checksum) {
        setFieldAs(PADATA, checksum);
    }

    public EncryptedData getEncFastReq() {
        return getFieldAs(REQ_BODY, EncryptedData.class);
    }

    public void setEncFastReq(EncryptedData encFastReq) {
        setFieldAs(REQ_BODY, encFastReq);
    }
}
