package org.haox.kerb.spec.type.pa.pkinit;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.asn1.type.Asn1Integer;
import org.haox.asn1.type.Asn1OctetString;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.KrbSequenceType;

/**
 PKAuthenticator ::= SEQUENCE {
     cusec                   [0] INTEGER (0..999999),
     ctime                   [1] KerberosTime,
     -- cusec and ctime are used as in [RFC4120], for
     -- replay prevention.
     nonce                   [2] INTEGER (0..4294967295),
     -- Chosen randomly; this nonce does not need to
     -- match with the nonce in the KDC-REQ-BODY.
     paChecksum              [3] OCTET STRING OPTIONAL,
     -- MUST be present.
     -- Contains the SHA1 checksum, performed over
     -- KDC-REQ-BODY.
 }
 */
public class PkAuthenticator extends KrbSequenceType {
    private static int CUSEC = 0;
    private static int CTIME = 1;
    private static int NONCE = 2;
    private static int PA_CHECKSUM = 3;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(CUSEC, Asn1Integer.class),
            new Asn1FieldInfo(CTIME, KerberosTime.class),
            new Asn1FieldInfo(NONCE, Asn1Integer.class),
            new Asn1FieldInfo(PA_CHECKSUM, Asn1OctetString.class)
    };

    public PkAuthenticator() {
        super(fieldInfos);
    }

    public int getCusec() {
        return getFieldAsInt(CUSEC);
    }

    public void setCusec(int cusec) {
        setFieldAsInt(CUSEC, cusec);
    }

    public KerberosTime getCtime() {
        return getFieldAsTime(CTIME);
    }

    public void setCtime(KerberosTime ctime) {
        setFieldAs(CTIME, ctime);
    }

    public int getNonce() {
        return getFieldAsInt(NONCE);
    }

    public void setNonce(int nonce) {
        setFieldAsInt(NONCE, nonce);
    }

    public byte[] getPaChecksum() {
        return getFieldAsOctets(PA_CHECKSUM);
    }

    public void setPaChecksum(byte[] paChecksum) {
        setFieldAsOctets(PA_CHECKSUM, paChecksum);
    }
}
