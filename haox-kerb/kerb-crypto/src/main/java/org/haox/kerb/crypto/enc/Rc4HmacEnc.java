package org.haox.kerb.crypto.enc;

import org.haox.kerb.KrbErrorCode;
import org.haox.kerb.crypto.BytesUtil;
import org.haox.kerb.crypto.Confounder;
import org.haox.kerb.crypto.Rc4;
import org.haox.kerb.crypto.Hmac;
import org.haox.kerb.crypto.cksum.provider.Md5Provider;
import org.haox.kerb.crypto.enc.provider.Rc4Provider;
import org.haox.kerb.crypto.key.Rc4KeyMaker;
import org.haox.kerb.KrbException;
import org.haox.kerb.spec.common.CheckSumType;
import org.haox.kerb.spec.common.EncryptionType;

public class Rc4HmacEnc extends AbstractEncTypeHandler {
    private boolean exportable;

    public Rc4HmacEnc() {
        this(false);
    }

    public Rc4HmacEnc(boolean exportable) {
        super(new Rc4Provider(), new Md5Provider());
        keyMaker(new Rc4KeyMaker(this.encProvider()));
        this.exportable = exportable;
    }

    public EncryptionType eType() {
        return EncryptionType.ARCFOUR_HMAC;
    }

    @Override
    public int confounderSize() {
        return 8;
    }

    @Override
    public int paddingSize() {
        return 0;
    }

    public CheckSumType checksumType() {
        return CheckSumType.HMAC_MD5_ARCFOUR;
    }

    protected void encryptWith(byte[] workBuffer, int[] workLens,
         byte[] key, byte[] iv, int usage) throws KrbException {
        int confounderLen = workLens[0];
        int checksumLen = workLens[1];
        int dataLen = workLens[2];

        /**
         * Instead of E(Confounder | Checksum | Plaintext | Padding),
         * Checksum | E(Confounder | Plaintext)
         */

        // confounder
        byte[] confounder = Confounder.makeBytes(confounderLen);
        System.arraycopy(confounder, 0, workBuffer, checksumLen, confounderLen);

        // no padding

        /* checksum and encryption */
        byte[] usageKey = makeUsageKey(key, usage);

        byte[] checksum = Hmac.hmac(hashProvider(), usageKey, workBuffer,
                checksumLen, confounderLen + dataLen);

        byte[] encKey = makeEncKey(usageKey, checksum);

        byte[] tmpEnc = new byte[confounderLen + dataLen];
        System.arraycopy(workBuffer, checksumLen,
                tmpEnc, 0, confounderLen + dataLen);
        encProvider().encrypt(encKey, iv, tmpEnc);
        System.arraycopy(checksum, 0, workBuffer, 0, checksumLen);
        System.arraycopy(tmpEnc, 0, workBuffer, checksumLen, tmpEnc.length);
    }

    protected byte[] makeUsageKey(byte[] key, int usage) throws KrbException {
        byte[] salt = Rc4.getSalt(usage, exportable);
        byte[] usageKey = Hmac.hmac(hashProvider(), key, salt);
        return usageKey;
    }

    protected byte[] makeEncKey(byte[] usageKey, byte[] checksum) throws KrbException {
        byte[] tmpKey = usageKey;

        if (exportable) {
            tmpKey = BytesUtil.duplicate(usageKey);
            for (int i = 0; i < 9; ++i) {
                tmpKey[i + 7] = (byte) 0xab;
            }
        }

        byte[] encKey = Hmac.hmac(hashProvider(), tmpKey, checksum);
        return encKey;
    }

    @Override
    protected byte[] decryptWith(byte[] workBuffer, int[] workLens,
                                 byte[] key, byte[] iv, int usage) throws KrbException {
        int confounderLen = workLens[0];
        int checksumLen = workLens[1];
        int dataLen = workLens[2];

        /* checksum and decryption */
        byte[] usageKey = makeUsageKey(key, usage);

        byte[] checksum = new byte[checksumLen];
        System.arraycopy(workBuffer, 0, checksum, 0, checksumLen);

        byte[] encKey = makeEncKey(usageKey, checksum);

        byte[] tmpEnc = new byte[confounderLen + dataLen];
        System.arraycopy(workBuffer, checksumLen,
                tmpEnc, 0, confounderLen + dataLen);
        encProvider().decrypt(encKey, iv, tmpEnc);

        byte[] newChecksum = Hmac.hmac(hashProvider(), usageKey, tmpEnc);
        if (! checksumEqual(checksum, newChecksum)) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BAD_INTEGRITY);
        }

        byte[] data = new byte[dataLen];
        System.arraycopy(tmpEnc, confounderLen,
                data, 0, dataLen);

        return data;
    }
}
