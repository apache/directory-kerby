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
package org.apache.kerby.kerberos.kdc.identitybackend;

import org.apache.kerby.kerberos.kerb.crypto.util.BytesUtil;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionType;
import org.apache.kerby.util.UTF8;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.ZooKeeper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Iterator;
import java.util.Map;

public class IdentityZNode {
    private static final Logger LOG = LoggerFactory.getLogger(IdentityZNode.class);
    private ZooKeeper zk;
    private String identityName;

    public IdentityZNode(ZooKeeper zk, String identityName) {
        this.zk = zk;
        this.identityName = identityName;
    }

    public void setPrincipalName(String principal) throws KeeperException {
        ZKUtil.createSetData(this.zk,
                IdentityZNodeHelper.getPrincipalNameZnode(this.identityName),
                UTF8.toBytes(principal));
    }

    public void setKeyVersion(int keyVersion) throws KeeperException {
        ZKUtil.createSetData(this.zk,
                IdentityZNodeHelper.getKeyVersionZNode(this.identityName),
                BytesUtil.int2bytes(keyVersion, true));
    }

    public void setKdcFlags(int kdcFlags) throws KeeperException {
        ZKUtil.createSetData(this.zk,
                IdentityZNodeHelper.getKdcFlagsZNode(this.identityName),
                BytesUtil.int2bytes(kdcFlags, true));
    }

    public void setDisabled(boolean disabled) throws KeeperException {
        int value;
        if (disabled) {
            value = 1;
        } else {
            value = 0;
        }
        ZKUtil.createSetData(this.zk,
                IdentityZNodeHelper.getDisabledZNode(this.identityName),
                BytesUtil.int2bytes(value, true));
    }

    public void setLocked(boolean locked) throws KeeperException {
        int value;
        if (locked) {
            value = 1;
        } else {
            value = 0;
        }
        ZKUtil.createSetData(this.zk,
                IdentityZNodeHelper.getLockedZNode(this.identityName),
                BytesUtil.int2bytes(value, true));
    }

    public void setExpireTime(KerberosTime time) throws KeeperException {
        ZKUtil.createSetData(this.zk,
                IdentityZNodeHelper.getExpireTimeZNode(this.identityName),
                BytesUtil.long2bytes(time.getTime(), true));
    }

    public void setCreatedTime(KerberosTime time) throws KeeperException {
        ZKUtil.createSetData(this.zk,
                IdentityZNodeHelper.getCreatedTimeZNode(this.identityName),
                BytesUtil.long2bytes(time.getTime(), true));
    }

    public void setKeys(Map<EncryptionType, EncryptionKey> keys) throws KeeperException {
        if (ZKUtil.checkExists(this.zk, IdentityZNodeHelper.getKeysZNode(this.identityName)) == -1) {
            ZKUtil.createWithParents(this.zk, IdentityZNodeHelper.getKeysZNode(this.identityName));
        }
        Iterator it = keys.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry pair = (Map.Entry) it.next();
            EncryptionType key = (EncryptionType) pair.getKey();
            ZKUtil.createWithParents(this.zk, IdentityZNodeHelper.getKeyTypeZNode(this.identityName, key.getName()));
            EncryptionKey value = (EncryptionKey) pair.getValue();
            ZKUtil.createSetData(this.zk, IdentityZNodeHelper.getEncryptionKeyTypeZNode(this.identityName, key.getName()),
                    UTF8.toBytes(value.getKeyType().getName()));
            ZKUtil.createSetData(this.zk, IdentityZNodeHelper.getEncryptionKeyDataZNode(this.identityName, key.getName()),
                    value.getKeyData());
            ZKUtil.createSetData(this.zk, IdentityZNodeHelper.getEncryptionKeyNoZNode(this.identityName, key.getName()),
                    BytesUtil.int2bytes(value.getKvno(), true));
        }
    }
}
