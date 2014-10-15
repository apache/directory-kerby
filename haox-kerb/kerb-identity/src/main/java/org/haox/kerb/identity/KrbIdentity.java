package org.haox.kerb.identity;

import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.common.PrincipalName;

import java.util.HashMap;
import java.util.Map;

public class KrbIdentity {
    private PrincipalName principal;
    private int keyVersion = 1;
    private int kdcFlags = 0;
    private boolean disabled = false;
    private boolean locked = false;
    private KerberosTime expireTime = KerberosTime.NEVER;
    private KerberosTime createdTime = KerberosTime.now();
    private Map<EncryptionType, EncryptionKey> keys =
            new HashMap<EncryptionType, EncryptionKey>();

    public void setPrincipal(PrincipalName principal) {
        this.principal = principal;
    }

    public PrincipalName getPrincipal() {
        return principal;
    }

    public void setKeyVersion(int keyVersion) {
        this.keyVersion = keyVersion;
    }

    public void setKdcFlags(int kdcFlags) {
        this.kdcFlags = kdcFlags;
    }

    public void setDisabled(boolean disabled) {
        this.disabled = disabled;
    }

    public void setLocked(boolean locked) {
        this.locked = locked;
    }

    public void setExpireTime(KerberosTime expireTime) {
        this.expireTime = expireTime;
    }

    public KerberosTime getExpireTime() {
        return expireTime;
    }

    public KerberosTime getCreatedTime() {
        return createdTime;
    }

    public void setCreatedTime(KerberosTime createdTime) {
        this.createdTime = createdTime;
    }

    public KrbIdentity(String principal) {
        this.principal = new PrincipalName(principal);
    }

    public boolean isDisabled() {
        return disabled;
    }

    public boolean isLocked() {
        return locked;
    }

    public void addKey(EncryptionKey key) {
        keys.put(key.getKeyType(), key);
    }

    public Map<EncryptionType, EncryptionKey> getKeys() {
        return keys;
    }

    public int getKdcFlags() {
        return kdcFlags;
    }

    public int getKeyVersion() {
        return keyVersion;
    }
}
