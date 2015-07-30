/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.kerby.kerberos.kerb.identity;

import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.spec.base.PrincipalName;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 * A class to represent a kerberos identity.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class KrbIdentity {
    /** the principal */
    private PrincipalName principal;

    /** the key version */
    private int keyVersion = 1;

    /** KDC flags */
    private int kdcFlags = 0;

    /** flag to indicate if this identity was disabled */
    private boolean disabled;

    /** flag to indicate if this identity was locked */
    private boolean locked;

    /** the expiration time of the identity, default set to never expire */
    private KerberosTime expireTime = KerberosTime.NEVER;

    /** the creation time of the identity */
    private KerberosTime createdTime = KerberosTime.now();

    /** the keys associated with this identity */
    private Map<EncryptionType, EncryptionKey> keys =
            new HashMap<EncryptionType, EncryptionKey>();

    public KrbIdentity(String principalName) {
        this.principal = new PrincipalName(principalName);
    }

    public String getPrincipalName() {
        return principal.getName();
    }

    public void setPrincipalName(String newPrincipalName) {
        principal = new PrincipalName(newPrincipalName);
    }

    public PrincipalName getPrincipal() {
        return principal;
    }

    public void setPrincipal(PrincipalName principal) {
        this.principal = principal;
    }

    public KerberosTime getExpireTime() {
        return expireTime;
    }

    public void setExpireTime(KerberosTime expireTime) {
        this.expireTime = expireTime;
    }

    public KerberosTime getCreatedTime() {
        return createdTime;
    }

    public void setCreatedTime(KerberosTime createdTime) {
        this.createdTime = createdTime;
    }

    public boolean isDisabled() {
        return disabled;
    }

    public void setDisabled(boolean disabled) {
        this.disabled = disabled;
    }

    public boolean isLocked() {
        return locked;
    }

    public void setLocked(boolean locked) {
        this.locked = locked;
    }

    public void addKey(EncryptionKey encKey) {
        keys.put(encKey.getKeyType(), encKey);
    }

    public void addKeys(List<EncryptionKey> encKeys) {
        for (EncryptionKey key : encKeys) {
            keys.put(key.getKeyType(), key);
        }
    }

    public Map<EncryptionType, EncryptionKey> getKeys() {
        return keys;
    }

    public EncryptionKey getKey(EncryptionType encType) {
        return keys.get(encType);
    }

    public int getKdcFlags() {
        return kdcFlags;
    }

    public void setKdcFlags(int kdcFlags) {
        this.kdcFlags = kdcFlags;
    }

    public int getKeyVersion() {
        return keyVersion;
    }

    public void setKeyVersion(int keyVersion) {
        this.keyVersion = keyVersion;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj == null) {
            return false;
        }

        if (obj instanceof KrbIdentity) {
            KrbIdentity other = (KrbIdentity) obj;
            if (principal == null) {
                if (other.principal != null) {
                    return false;
                }
            } else if (!principal.equals(other.principal)) {
                return false;
            }
            return true;
        }
        return false;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((principal == null) ? 0
                : principal.hashCode());
        return result;
    }
}
