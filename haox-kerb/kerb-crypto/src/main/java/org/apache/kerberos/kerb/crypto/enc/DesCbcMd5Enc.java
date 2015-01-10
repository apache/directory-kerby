package org.apache.kerberos.kerb.crypto.enc;

import org.apache.kerberos.kerb.crypto.cksum.provider.Md5Provider;
import org.apache.kerberos.kerb.spec.common.CheckSumType;
import org.apache.kerberos.kerb.spec.common.EncryptionType;

public class DesCbcMd5Enc extends DesCbcEnc {

    public DesCbcMd5Enc() {
        super(new Md5Provider());
    }

    public EncryptionType eType() {
        return EncryptionType.DES_CBC_MD5;
    }

    public CheckSumType checksumType() {
        return CheckSumType.RSA_MD5_DES;
    }
}
