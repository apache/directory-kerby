package org.haox.kerb.common;

import org.haox.kerb.spec.type.common.PrincipalName;

public class KerberosKey {

    private PrincipalName principal;

    private int versionNum;

    private KeyImpl key;

    public KerberosKey(PrincipalName principal,
                       byte[] keyBytes,
                       int keyType,
                       int versionNum) {
        this.principal = principal;
        this.versionNum = versionNum;
        key = new KeyImpl(keyBytes, keyType);
    }

    public KerberosKey(PrincipalName principal,
                       char[] password,
                       String algorithm) {

        this.principal = principal;
        // Pass principal in for salt
        key = new KeyImpl(principal, password, algorithm);
    }

    public final PrincipalName getPrincipal() {
        return principal;
    }

    public final int getVersionNumber() {
        return versionNum;
    }

    public final int getKeyType() {
        return key.getKeyType();
    }

    public final byte[] getKeyBytes() {
        return key.getKeyBytes();
    }

    public final String getAlgorithm() {
        return key.getAlgorithm();
    }
}
