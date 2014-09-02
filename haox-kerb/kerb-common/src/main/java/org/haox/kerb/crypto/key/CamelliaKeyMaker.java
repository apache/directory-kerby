package org.haox.kerb.crypto.key;

import org.haox.kerb.crypto.Cmac;
import org.haox.kerb.crypto.Util;
import org.haox.kerb.crypto.enc.provider.CamelliaProvider;
import org.haox.kerb.spec.KrbException;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

public class CamelliaKeyMaker extends DkKeyMaker {

    public CamelliaKeyMaker(CamelliaProvider encProvider) {
        super(encProvider);
    }

    @Override
    public byte[] random2Key(byte[] randomBits) throws KrbException {
        return randomBits;
    }

    @Override
    public byte[] str2key(String string, String salt, byte[] param) throws KrbException {
        int iterCount = getIterCount(param, 32768);

        byte[] saltBytes = null;
        try {
            saltBytes = getSaltBytes(salt, getPepper());
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        int keySize = encProvider().keySize();
        byte[] random = new byte[0];
        try {
            random = PBKDF2(string.toCharArray(), saltBytes, iterCount, keySize);
        } catch (GeneralSecurityException e) {
            throw new KrbException("PBKDF2 failed", e);
        }

        byte[] tmpKey = random2Key(random);
        byte[] result = dk(tmpKey, KERBEROS_CONSTANT);

        return result;
    }

    private String getPepper() {
        int keySize = encProvider().keySize();
        String pepper = keySize == 16 ? "camellia128-cts-cmac" : "camellia256-cts-cmac";
        return pepper;
    }

    /*
     * NIST SP800-108 KDF in feedback mode (section 5.2).
     */
    @Override
    protected byte[] dr(byte[] key, byte[] constant) throws KrbException {

        int blocksize = encProvider().blockSize();
        int keyInuptSize = encProvider().keyInputSize();
        byte[] keyBytes = new byte[keyInuptSize];
        byte[] Ki;

        int len = 0;
        // K(i-1): the previous block of PRF output, initially all-zeros.
        len += blocksize;
        // four-byte big-endian binary string giving the block counter
        len += 4;
        // the fixed derived-key input
        len += constant.length;
        // 0x00: separator byte
        len += 1;
        // four-byte big-endian binary string giving the output length
        len += 4;

        Ki = new byte[len];
        System.arraycopy(constant, 0, Ki, blocksize + 4, constant.length);
        Util.int2bytesBe(keyInuptSize * 8, Ki, len - 4);

        int i, n = 0;
        byte[] tmp;
        for (i = 1, n = 0; n < keyInuptSize; i++) {
            // Update the block counter
            Util.int2bytesBe(i, Ki, blocksize);

            // Compute a CMAC checksum, update Ki with the result
            tmp = Cmac.cmac(encProvider(), key, Ki);
            System.arraycopy(tmp, 0, Ki, 0, blocksize);

            if (n + blocksize >= keyInuptSize) {
                System.arraycopy(Ki, 0, keyBytes, n, keyInuptSize - n);
                break;
            }

            System.arraycopy(Ki, 0, keyBytes, n, blocksize);
            n += blocksize;
        }

        return keyBytes;
    }
}
