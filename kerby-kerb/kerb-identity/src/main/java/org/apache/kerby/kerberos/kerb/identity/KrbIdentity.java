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
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionType;
import org.apache.kerby.kerberos.kerb.spec.common.PrincipalName;

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

    public boolean isDisabled() {
        return disabled;
    }

    public boolean isLocked() {
        return locked;
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

    public int getKeyVersion() {
        return keyVersion;
    }
}
