package org.apache.kerberos.kerb.crypto.key;

import org.apache.kerberos.kerb.crypto.enc.EncryptProvider;
import org.apache.kerberos.kerb.KrbException;
import sun.security.provider.MD4;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;

public class Rc4KeyMaker extends AbstractKeyMaker {

    public Rc4KeyMaker(EncryptProvider encProvider) {
        super(encProvider);
    }

    @Override
    public byte[] str2key(String string, String salt, byte[] param) throws KrbException {

        if (param != null && param.length > 0) {
            throw new RuntimeException("Invalid param to str2Key");
        }

        try {
            byte[] passwd = string.getBytes("UTF-16LE"); // to unicode
            MessageDigest md = MD4.getInstance();
            md.update(passwd);
            return md.digest();
        } catch (UnsupportedEncodingException e) {
            throw new KrbException("str2key failed", e);
        }
    }

}
