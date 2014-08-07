package org.haox.kerb.crypto.enc;

import org.haox.kerb.crypto.Confounder;
import org.haox.kerb.crypto.cksum.HashProvider;
import org.haox.kerb.crypto.dk.AesDkCrypto;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.KrbErrorCode;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

public abstract class AesCtsHmacSha1Enc extends AbstractEncTypeHandler {

    public AesCtsHmacSha1Enc(EncryptProvider encProvider,
                             HashProvider hashProvider) {
        super(encProvider, hashProvider);
    }

    @Override
    public int paddingSize() {
        return 0;
    }

    @Override
    protected void encryptWith(byte[] workBuffer, int[] workLens,
                               byte[] key, byte[] iv, int usage) throws KrbException {
        int confounderLen = workLens[0];
        int checksumLen = workLens[1];
        int inputLen = workLens[2];
        int paddingLen = workLens[3];

        byte[] Ke, Ki, Kc;
        byte[] constant = new byte[5];
        constant[0] = (byte) ((usage>>24)&0xff);
        constant[1] = (byte) ((usage>>16)&0xff);
        constant[2] = (byte) ((usage>>8)&0xff);
        constant[3] = (byte) (usage&0xff);
        constant[4] = (byte) 0xaa;
        Ke = keyMaker().dk(key, constant);
        constant[4] = (byte) 0x55;
        Ki = keyMaker().dk(key, constant);
        constant[4] = (byte) 0x99;
        Kc = keyMaker().dk(key, constant);

        /**
         * Instead of E(Confounder | Checksum | Plaintext | Padding),
         * E(Confounder | Plaintext | Padding) | Checksum,
         * so need to adjust the workBuffer arrangement
         */

        byte[] tmpEnc = new byte[confounderLen + inputLen + paddingLen];
        // confounder
        byte[] confounder = Confounder.bytes(confounderLen);
        System.arraycopy(confounder, 0, tmpEnc, 0, confounderLen);

        // data
        System.arraycopy(workBuffer, confounderLen + checksumLen,
                tmpEnc, confounderLen, inputLen);

        // padding
        for (int i = confounderLen + inputLen; i < paddingLen; ++i) {
            tmpEnc[i] = 0;
        }

        // checksum & encrypt
        byte[] checksum;
        try {
            checksum = getHmac(Ki, tmpEnc, checksumLen);
            encProvider().encrypt(Ke, iv, tmpEnc);
        } catch (GeneralSecurityException e) {
            KrbException ke = new KrbException(e.getMessage());
            ke.initCause(e);
            throw ke;
        }

        System.arraycopy(tmpEnc, 0, workBuffer, 0, tmpEnc.length);
        System.arraycopy(checksum, 0, workBuffer, tmpEnc.length, checksum.length);
    }

    @Override
    protected byte[] decryptWith(byte[] workBuffer, int[] workLens,
                                 byte[] key, byte[] iv, int usage) throws KrbException {
        int confounderLen = workLens[0];
        int checksumLen = workLens[1];
        int dataLen = workLens[2];

        byte[] Ke, Ki, Kc;
        byte[] constant = new byte[5];
        constant[0] = (byte) ((usage>>24)&0xff);
        constant[1] = (byte) ((usage>>16)&0xff);
        constant[2] = (byte) ((usage>>8)&0xff);
        constant[3] = (byte) (usage&0xff);
        constant[4] = (byte) 0xaa;
        Ke = keyMaker().dk(key, constant);
        constant[4] = (byte) 0x55;
        Ki = keyMaker().dk(key, constant);
        constant[4] = (byte) 0x99;
        Kc = keyMaker().dk(key, constant);

        // decrypt and verify checksum

        byte[] tmpEnc = new byte[confounderLen + dataLen];
        System.arraycopy(workBuffer, 0,
                tmpEnc, 0, confounderLen + dataLen);
        byte[] checksum = new byte[checksumLen];
        System.arraycopy(workBuffer, confounderLen + dataLen,
                checksum, 0, checksumLen);

        byte[] newChecksum;
        try {
            encProvider().decrypt(Ke, iv, tmpEnc);
            newChecksum = getHmac(Ki, tmpEnc, checksumLen);
        } catch (GeneralSecurityException e) {
            KrbException ke = new KrbException(e.getMessage());
            ke.initCause(e);
            throw ke;
        }

        if (! checksumEqual(checksum, newChecksum)) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BAD_INTEGRITY);
        }

        byte[] data = new byte[dataLen];
        System.arraycopy(tmpEnc, confounderLen, data, 0, dataLen);
        return data;
    }

    protected byte[] getHmac(byte[] key, byte[] msg, int hashSize)
            throws GeneralSecurityException {

        SecretKey keyKi = new SecretKeySpec(key, "HMAC");
        Mac m = Mac.getInstance("HmacSHA1");
        m.init(keyKi);

        // generate hash
        byte[] hash = m.doFinal(msg);

        // truncate hash
        byte[] output = new byte[hashSize];
        System.arraycopy(hash, 0, output, 0, hashSize);
        return output;
    }
}
