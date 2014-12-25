package org.apache.kerberos.kerb.spec.fast;

import org.apache.haox.asn1.type.Asn1FieldInfo;
import org.apache.kerberos.kerb.spec.KrbSequenceType;
import org.apache.kerberos.kerb.spec.common.CheckSum;
import org.apache.kerberos.kerb.spec.common.EncryptedData;

/**
 KrbFastArmoredReq ::= SEQUENCE {
     armor        [0] KrbFastArmor OPTIONAL,
     -- Contains the armor that identifies the armor key.
     -- MUST be present in AS-REQ.
     req-checksum [1] Checksum,
     -- For AS, contains the checksum performed over the type
     -- KDC-REQ-BODY for the req-body field of the KDC-REQ
     -- structure;
     -- For TGS, contains the checksum performed over the type
     -- AP-REQ in the PA-TGS-REQ padata.
     -- The checksum key is the armor key, the checksum
     -- type is the required checksum type for the enctype of
     -- the armor key, and the key usage number is
     -- KEY_USAGE_FAST_REQ_CHKSUM.
     enc-fast-req [2] EncryptedData, -- KrbFastReq --
     -- The encryption key is the armor key, and the key usage
     -- number is KEY_USAGE_FAST_ENC.
 }
 */
public class KrbFastArmoredReq extends KrbSequenceType {
    private static int ARMOR = 0;
    private static int REQ_CHECKSUM = 1;
    private static int ENC_FAST_REQ = 2;

    private KrbFastReq fastReq;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(ARMOR, KrbFastArmor.class),
            new Asn1FieldInfo(REQ_CHECKSUM, CheckSum.class),
            new Asn1FieldInfo(ENC_FAST_REQ, EncryptedData.class),
    };

    public KrbFastArmoredReq() {
        super(fieldInfos);
    }

    public KrbFastArmor getArmor() {
        return getFieldAs(ARMOR, KrbFastArmor.class);
    }

    public void setArmor(KrbFastArmor armor) {
        setFieldAs(ARMOR, armor);
    }

    public CheckSum getReqChecksum() {
        return getFieldAs(REQ_CHECKSUM, CheckSum.class);
    }

    public void setReqChecksum(CheckSum checkSum) {
        setFieldAs(REQ_CHECKSUM, checkSum);
    }

    public KrbFastReq getFastReq() {
        return fastReq;
    }

    public void setFastReq(KrbFastReq fastReq) {
        this.fastReq = fastReq;
    }

    public EncryptedData getEncryptedFastReq() {
        return getFieldAs(ENC_FAST_REQ, EncryptedData.class);
    }

    public void setEncryptedFastReq(EncryptedData encFastReq) {
        setFieldAs(ENC_FAST_REQ, encFastReq);
    }
}
