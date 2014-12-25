package org.apache.kerberos.kerb.crypto.enc;

import org.apache.kerberos.kerb.crypto.cksum.provider.Md4Provider;
import org.apache.kerberos.kerb.spec.common.CheckSumType;
import org.apache.kerberos.kerb.spec.common.EncryptionType;

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
