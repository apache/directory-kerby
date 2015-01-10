package org.apache.kerberos.kerb.crypto.enc;

import org.apache.kerberos.kerb.crypto.cksum.provider.Sha1Provider;
import org.apache.kerberos.kerb.crypto.enc.provider.Des3Provider;
import org.apache.kerberos.kerb.crypto.key.Des3KeyMaker;
import org.apache.kerberos.kerb.spec.common.CheckSumType;
import org.apache.kerberos.kerb.spec.common.EncryptionType;

public class Des3CbcSha1Enc extends KeKiHmacSha1Enc {

    public Des3CbcSha1Enc() {
        super(new Des3Provider(), new Sha1Provider());
        keyMaker(new Des3KeyMaker(this.encProvider()));
    }

    public EncryptionType eType() {
        return EncryptionType.DES3_CBC_SHA1;
    }

    public CheckSumType checksumType() {
        return CheckSumType.HMAC_SHA1_DES3;
    }
}
