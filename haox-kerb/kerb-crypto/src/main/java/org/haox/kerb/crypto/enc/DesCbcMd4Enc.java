package org.haox.kerb.crypto.enc;

import org.haox.kerb.crypto.cksum.provider.Md4Provider;
import org.haox.kerb.spec.type.common.CheckSumType;
import org.haox.kerb.spec.type.common.EncryptionType;

public class DesCbcMd4Enc extends DesCbcEnc {

    public DesCbcMd4Enc() {
        super(new Md4Provider());
    }

    public EncryptionType eType() {
        return EncryptionType.DES_CBC_MD4;
    }

    public CheckSumType checksumType() {
        return CheckSumType.RSA_MD4_DES;
    }
}
