package org.haox.kerb.crypto.enc;

import org.haox.kerb.crypto.Confounder;
import org.haox.kerb.crypto.Des3;
import org.haox.kerb.crypto.cksum.provider.Sha1Provider;
import org.haox.kerb.crypto.enc.provider.Des3Provider;
import org.haox.kerb.crypto.key.Des3KeyMaker;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSumType;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.common.KrbErrorCode;

import java.security.GeneralSecurityException;

public class Des3CbcSha1Enc extends KeKiKcHmacSha1Enc {

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
