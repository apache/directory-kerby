/**
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

public class KrbIdentity {
    private String principalName;
    private PrincipalName principal;
    private int keyVersion = 1;
    private int kdcFlags = 0;
    private boolean disabled;
    private boolean locked;
    private KerberosTime expireTime = KerberosTime.NEVER;
    private KerberosTime createdTime = KerberosTime.now();

    private Map<EncryptionType, EncryptionKey> keys =
            new HashMap<EncryptionType, EncryptionKey>();

    public KrbIdentity(String principalName) {
        this.principalName = principalName;
        this.principal = new PrincipalName(principalName);
    }

    public String getPrincipalName() {
        return principalName;
    }

    public void setPrincipalName(String newPrincipalName) { principalName = newPrincipalName; }

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
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        KrbIdentity identity = (KrbIdentity) o;

        if (disabled != identity.disabled) return false;
        if (kdcFlags != identity.kdcFlags) return false;
        if (keyVersion != identity.keyVersion) return false;
        if (locked != identity.locked) return false;
        if (createdTime != null ? !createdTime.equals(identity.createdTime) :
                identity.createdTime != null)
            return false;
        if (expireTime != null ? !expireTime.equals(identity.expireTime) :
                identity.expireTime != null)
            return false;
        if (keys != null ? !keys.equals(identity.keys) : identity.keys != null)
            return false;
        if (principalName != null ? !principalName.equals(
                identity.principalName) : identity.principalName != null)
            return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = principalName != null ? principalName.hashCode() : 0;
        result = 31 * result + keyVersion;
        result = 31 * result + kdcFlags;
        result = 31 * result + (disabled ? 1 : 0);
        result = 31 * result + (locked ? 1 : 0);
        result = 31 * result + (expireTime != null ? expireTime.hashCode() : 0);
        result = 31 * result + (createdTime != null ? createdTime.hashCode() : 0);
        result = 31 * result + (keys != null ? keys.hashCode() : 0);
        return result;
    }
}
