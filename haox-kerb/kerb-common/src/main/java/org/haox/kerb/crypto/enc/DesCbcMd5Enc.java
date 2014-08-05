package org.haox.kerb.crypto.enc;

import org.haox.kerb.crypto.cksum.provider.Md5Provider;
import org.haox.kerb.spec.type.common.CheckSumType;
import org.haox.kerb.spec.type.common.EncryptionType;

public class DesCbcMd5Enc extends DesCbcEnc {

    public DesCbcMd5Enc() {
        super(new Md5Provider());
    }

    public EncryptionType eType() {
        return EncryptionType.DES_CBC_MD5;
    }

    public CheckSumType checksumType() {
        return CheckSumType.RSA_MD5;
    }
}
