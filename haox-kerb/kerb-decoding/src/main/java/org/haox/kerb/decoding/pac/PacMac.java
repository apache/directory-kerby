package org.haox.kerb.decoding.pac;

import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.spec.SecretKeySpec;

import org.haox.kerb.decoding.DecodingUtil;

public class PacMac {

    private static final String HMAC_ALGORITHM = "hmac";
    private static final String SIGNATURE_KEY = "signaturekey\0";

    private MessageDigest messageDigest;
    private MessageDigest macMessageDigest;

    private byte[] constant;
    private byte[] xorInputPad;
    private byte[] xorOutputPad;

    public void init(Key key) throws NoSuchAlgorithmException {
        messageDigest = MessageDigest.getInstance("MD5");
        macMessageDigest = MessageDigest.getInstance("MD5");

        macInit(new SecretKeySpec(key.getEncoded(), HMAC_ALGORITHM));
        try {
            constant = SIGNATURE_KEY.getBytes("UTF8");
        } catch(UnsupportedEncodingException e) {
            constant = SIGNATURE_KEY.getBytes();
        }
        macMessageDigest.update(constant);
        byte digest[] = macDigest();

        macInit(new SecretKeySpec(digest, HMAC_ALGORITHM));
        byte[] encType = DecodingUtil.asBytes(PacConstants.MD5_KRB_SALT);
        messageDigest.update(encType);
    }

    public void update(byte toUpdate[]) {
        messageDigest.update(toUpdate);
    }

    public byte[] doFinal() {
        byte[] digest = messageDigest.digest();
        macMessageDigest.update(digest);

        return macDigest();
    }

    private void macInit(Key key) {
        xorInputPad = new byte[PacConstants.MD5_BLOCK_LENGTH];
        xorOutputPad = new byte[PacConstants.MD5_BLOCK_LENGTH];

        byte[] keyData = key.getEncoded();
        if(keyData.length > PacConstants.MD5_BLOCK_LENGTH) {
            macMessageDigest.reset();
            keyData = macMessageDigest.digest(keyData);
        }

        System.arraycopy(keyData, 0, xorInputPad, 0, keyData.length);
        System.arraycopy(keyData, 0, xorOutputPad, 0, keyData.length);

        for(int i = 0; i < PacConstants.MD5_BLOCK_LENGTH; i++) {
            xorInputPad[i] ^= 0x36;
            xorOutputPad[i] ^= 0x5c;
        }

        macMessageDigest.reset();
        macMessageDigest.update(xorInputPad);
    }

    private byte[] macDigest() {
        byte[] digest = macMessageDigest.digest();
        macMessageDigest.update(xorOutputPad);

        digest = macMessageDigest.digest(digest);
        macMessageDigest.update(xorInputPad);

        return digest;
    }

}
