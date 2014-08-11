package org.haox.kerb.crypto.cksum;

import org.haox.kerb.crypto.Confounder;
import org.haox.kerb.crypto.Des;
import org.haox.kerb.crypto.cksum.provider.Md4Provider;
import org.haox.kerb.crypto.enc.provider.DesProvider;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSumType;

import javax.crypto.spec.DESKeySpec;
import java.security.InvalidKeyException;

public final class RsaMd4DesCheckSum extends AbstractKeyedCheckSumTypeHandler {

    public RsaMd4DesCheckSum() {
        super(new DesProvider(), new Md4Provider(), 24, 24);
    }

    public int confounderSize() {
        return 8;
    }

    public CheckSumType cksumType() {
        return CheckSumType.RSA_MD4_DES;
    }

    public boolean isSafe() {
        return true;
    }

    public int cksumSize() {
        return 24;
    }

    public int keySize() {
        return 8;
    }

    @Override
    protected byte[] makeKeyedChecksumWith(byte[] data, int start, int len,
                                           byte[] key, int usage) throws KrbException {
        //prepend confounder
        byte[] new_data = new byte[data.length + confounderSize()];
        byte[] conf = Confounder.bytes(confounderSize());
        System.arraycopy(conf, 0, new_data, 0, confounderSize());
        System.arraycopy(data, 0, new_data, confounderSize(), data.length);

        //calculate md5 cksum
        hashProvider().hash(new_data);
        byte[] mdc_cksum = hashProvider().output();
        byte[] cksum = new byte[cksumSize()];
        System.arraycopy(conf, 0, cksum, 0, confounderSize());
        System.arraycopy(mdc_cksum, 0, cksum, confounderSize(),
                cksumSize() - confounderSize());

        //compute modified key
        byte[] new_key = new byte[keySize()];
        System.arraycopy(key, 0, new_key, 0, key.length);
        for (int i = 0; i < new_key.length; i++)
            new_key[i] = (byte)(new_key[i] ^ 0xf0);
        //check for weak keys
        try {
            if (DESKeySpec.isWeak(new_key, 0)) {
                new_key[7] = (byte)(new_key[7] ^ 0xF0);
            }
        } catch (InvalidKeyException ex) {
            // swallow, since it should never happen
        }
        byte[] ivec = new byte[new_key.length];

        //des-cbc encrypt
        byte[] enc_cksum = new byte[cksum.length];
        Des.cbc_encrypt(cksum, enc_cksum, new_key, ivec, true);
        return enc_cksum;
    }

    public byte[] makeKeyedChecksumOld(byte[] data, byte[] key, int usage) throws KrbException {
        //prepend confounder
        byte[] new_data = new byte[data.length + confounderSize()];
        byte[] conf = Confounder.bytes(confounderSize());
        System.arraycopy(conf, 0, new_data, 0, confounderSize());
        System.arraycopy(data, 0, new_data, confounderSize(), data.length);

        //calculate md5 cksum
        hashProvider().hash(new_data);
        byte[] mdc_cksum = hashProvider().output();
        byte[] cksum = new byte[cksumSize()];
        System.arraycopy(conf, 0, cksum, 0, confounderSize());
        System.arraycopy(mdc_cksum, 0, cksum, confounderSize(),
                cksumSize() - confounderSize());

        //compute modified key
        byte[] new_key = new byte[keySize()];
        System.arraycopy(key, 0, new_key, 0, key.length);
        for (int i = 0; i < new_key.length; i++)
            new_key[i] = (byte)(new_key[i] ^ 0xf0);
        //check for weak keys
        try {
            if (DESKeySpec.isWeak(new_key, 0)) {
                new_key[7] = (byte)(new_key[7] ^ 0xF0);
            }
        } catch (InvalidKeyException ex) {
            // swallow, since it should never happen
        }
        byte[] ivec = new byte[new_key.length];

        //des-cbc encrypt
        byte[] enc_cksum = new byte[cksum.length];
        Des.cbc_encrypt(cksum, enc_cksum, new_key, ivec, true);
        return enc_cksum;
    }

    @Override
    public boolean verifyWithKey(byte[] data,
                                 byte[] key, int usage, byte[] checksum) throws KrbException {
        //decrypt checksum
        byte[] cksum = decryptKeyedChecksum(checksum, key);

        //prepend confounder
        byte[] new_data = new byte[data.length + confounderSize()];
        System.arraycopy(cksum, 0, new_data, 0, confounderSize());
        System.arraycopy(data, 0, new_data, confounderSize(), data.length);

        hashProvider().hash(new_data);
        byte[] new_cksum = hashProvider().output();
        //extract original cksum value
        byte[] orig_cksum = new byte[cksumSize() - confounderSize()];
        System.arraycopy(cksum,  confounderSize(), orig_cksum, 0,
                cksumSize() - confounderSize());

        return checksumEqual(orig_cksum, new_cksum);
    }

    private byte[] decryptKeyedChecksum(byte[] enc_cksum, byte[] key) throws KrbException {
        //compute modified key
        byte[] new_key = new byte[keySize()];
        System.arraycopy(key, 0, new_key, 0, key.length);
        for (int i = 0; i < new_key.length; i++)
            new_key[i] = (byte)(new_key[i] ^ 0xf0);
        //check for weak keys
        try {
            if (DESKeySpec.isWeak(new_key, 0)) {
                new_key[7] = (byte)(new_key[7] ^ 0xF0);
            }
        } catch (InvalidKeyException ex) {
            // swallow, since it should never happen
        }
        byte[] ivec = new byte[new_key.length];

        byte[] cksum = new byte[enc_cksum.length];
        Des.cbc_encrypt(enc_cksum, cksum, new_key, ivec, false);
        return cksum;
    }
}
