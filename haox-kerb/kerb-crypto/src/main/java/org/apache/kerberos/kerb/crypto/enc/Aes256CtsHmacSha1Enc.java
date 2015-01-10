package org.apache.kerberos.kerb.crypto.enc;

import org.apache.kerberos.kerb.crypto.cksum.provider.Sha1Provider;
import org.apache.kerberos.kerb.crypto.enc.provider.Aes256Provider;
import org.apache.kerberos.kerb.crypto.enc.provider.AesProvider;
import org.apache.kerberos.kerb.crypto.key.AesKeyMaker;
import org.apache.kerberos.kerb.spec.common.CheckSumType;
import org.apache.kerberos.kerb.spec.common.EncryptionType;

public class Aes256CtsHmacSha1Enc extends KeKiHmacSha1Enc {

    public Aes256CtsHmacSha1Enc() {
        super(new Aes256Provider(), new Sha1Provider());
        keyMaker(new AesKeyMaker((AesProvider) encProvider()));
    }

    public EncryptionType eType() {
        return EncryptionType.AES256_CTS_HMAC_SHA1_96;
    }

    public CheckSumType checksumType() {
        return CheckSumType.HMAC_SHA1_96_AES256;
    }

    @Override
    public int checksumSize() {
        return 96 / 8;
    }
}
