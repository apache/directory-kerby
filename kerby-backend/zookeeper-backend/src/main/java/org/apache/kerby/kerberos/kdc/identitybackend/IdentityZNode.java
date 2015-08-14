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
import org.apache.kerby.kerberos.kerb.spec.base.PrincipalName;
import org.apache.kerby.util.Utf8;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.ZooKeeper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class IdentityZNode {
    private static final Logger LOG = LoggerFactory.getLogger(IdentityZNode.class);
    private ZooKeeper zk;
    private String identityName;

    public IdentityZNode(ZooKeeper zk, String identityName) {
        this.zk = zk;
        this.identityName = identityName;
    }

    public boolean exist() throws KeeperException {
        String znode = IdentityZNodeHelper.getIndentityZNode(this.identityName);
        if (ZKUtil.checkExists(this.zk, znode) == -1) {
            return false;
        } else {
            return true;
        }
    }

    public PrincipalName getPrincipalName() throws KeeperException {
        String znode = IdentityZNodeHelper.getPrincipalNameZnode(this.identityName);
        if (ZKUtil.checkExists(this.zk, znode) == -1) {
            throw new IllegalArgumentException("The znode " + znode + " is not found");
        }
        byte[] data;
        try {
            data = ZKUtil.getData(this.zk, znode);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
        if (data != null) {
            return new PrincipalName(Utf8.toString(data));
        } else {
            LOG.warn("can't get the date from znode: " + znode);
            return null;
        }
    }

    public void setPrincipalName(String principal) throws KeeperException {
        ZKUtil.createSetData(this.zk,
                IdentityZNodeHelper.getPrincipalNameZnode(this.identityName),
                Utf8.toBytes(principal));
    }

    public int getKeyVersion() throws KeeperException {
        String znode = IdentityZNodeHelper.getKeyVersionZNode(this.identityName);
        if (ZKUtil.checkExists(this.zk, znode) == -1) {
            throw new IllegalArgumentException("The znode " + znode + " is not found");
        }
        byte[] data = new byte[0];
        try {
            data = ZKUtil.getData(this.zk, znode);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if (data != null) {
            return BytesUtil.bytes2int(data, true);
        } else {
            LOG.warn("can't get the date from znode: " + znode);
            return -1;
        }
    }

    public void setKeyVersion(int keyVersion) throws KeeperException {
        ZKUtil.createSetData(this.zk,
                IdentityZNodeHelper.getKeyVersionZNode(this.identityName),
                BytesUtil.int2bytes(keyVersion, true));
    }

    public int getKdcFlags() throws KeeperException {
        String znode = IdentityZNodeHelper.getKdcFlagsZNode(this.identityName);
        if (ZKUtil.checkExists(this.zk, znode) == -1) {
            throw new IllegalArgumentException("The znode " + znode + " is not found");
        }
        byte[] data = new byte[0];
        try {
            data = ZKUtil.getData(this.zk, znode);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if (data != null) {
            return BytesUtil.bytes2int(data, true);
        } else {
            LOG.warn("can't get the date from znode: " + znode);
            return -1;
        }
    }

    public void setKdcFlags(int kdcFlags) throws KeeperException {
        ZKUtil.createSetData(this.zk,
                IdentityZNodeHelper.getKdcFlagsZNode(this.identityName),
                BytesUtil.int2bytes(kdcFlags, true));
    }

    public boolean getDisabled() throws KeeperException {
        String znode = IdentityZNodeHelper.getDisabledZNode(this.identityName);
        if (ZKUtil.checkExists(this.zk, znode) == -1) {
            throw new IllegalArgumentException("The znode " + znode + " is not found");
        }
        byte[] data = new byte[0];
        try {
            data = ZKUtil.getData(this.zk, znode);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if (data != null) {
            int disabled = BytesUtil.bytes2int(data, true);
            return disabled == 1;
        } else {
            LOG.warn("can't get the date from znode: " + znode);
            return false;
        }
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

    public boolean getLocked() throws KeeperException {
        String znode = IdentityZNodeHelper.getLockedZNode(this.identityName);
        if (ZKUtil.checkExists(this.zk, znode) == -1) {
            throw new IllegalArgumentException("The znode " + znode + " is not found");
        }
        byte[] data = new byte[0];
        try {
            data = ZKUtil.getData(this.zk, znode);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if (data != null) {
            int locked = BytesUtil.bytes2int(data, true);
            return locked == 1;
        } else {
            LOG.warn("can't get the date from znode: " + znode);
            return false;
        }
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

    public KerberosTime getExpireTime() throws KeeperException {
        String znode = IdentityZNodeHelper.getExpireTimeZNode(this.identityName);
        if (ZKUtil.checkExists(this.zk, znode) == -1) {
            throw new IllegalArgumentException("The znode " + znode + " is not found");
        }
        byte[] data = new byte[0];
        try {
            data = ZKUtil.getData(this.zk, znode);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if (data != null) {
            long time = BytesUtil.bytes2long(data, true);
            return new KerberosTime(time);
        } else {
            LOG.warn("can't get the date from znode:" + znode);
            return null;
        }
    }

    public void setExpireTime(KerberosTime time) throws KeeperException {
        ZKUtil.createSetData(this.zk,
                IdentityZNodeHelper.getExpireTimeZNode(this.identityName),
                BytesUtil.long2bytes(time.getTime(), true));
    }

    public KerberosTime getCreatedTime() throws KeeperException {
        String znode = IdentityZNodeHelper.getCreatedTimeZNode(this.identityName);
        if (ZKUtil.checkExists(this.zk, znode) == -1) {
            throw new IllegalArgumentException("The znode " + znode + " is not found");
        }
        byte[] data = new byte[0];
        try {
            data = ZKUtil.getData(this.zk, znode);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if (data != null) {
            long time = BytesUtil.bytes2long(data, true);
            return new KerberosTime(time);
        } else {
            LOG.warn("can't get the date from znode: " + znode);
            return null;
        }
    }

    public void setCreatedTime(KerberosTime time) throws KeeperException {
        ZKUtil.createSetData(this.zk,
                IdentityZNodeHelper.getCreatedTimeZNode(this.identityName),
                BytesUtil.long2bytes(time.getTime(), true));
    }

    public EncryptionType getEncryptionKeyType(String type) throws KeeperException {
        String znode = IdentityZNodeHelper.getEncryptionKeyTypeZNode(this.identityName, type);
        if (ZKUtil.checkExists(this.zk, znode) == -1) {
            throw new IllegalArgumentException("The znode " + znode + " is not found");
        }
        byte[] data = new byte[0];
        try {
            data = ZKUtil.getData(this.zk, znode);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if (data != null) {
            return EncryptionType.fromName(Utf8.toString(data));
        } else {
            LOG.warn("can't get the date from znode: " + znode);
            return null;
        }
    }

    public byte[] getEncryptionKey(String type) throws KeeperException {
        String znode = IdentityZNodeHelper.getEncryptionKeyZNode(this.identityName, type);
        if (ZKUtil.checkExists(this.zk, znode) == -1) {
            throw new IllegalArgumentException("The znode " + znode + " is not found");
        }
        byte[] data = new byte[0];
        try {
            data = ZKUtil.getData(this.zk, znode);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if (data == null) {
            LOG.warn("can't get the date from znode: " + znode);
        }
        return data;
    }

    public int getEncryptionKeyNo(String type) throws KeeperException {
        String znode = IdentityZNodeHelper.getEncryptionKeyNoZNode(this.identityName, type);
        if (ZKUtil.checkExists(this.zk, znode) == -1) {
            throw new IllegalArgumentException("The znode " + znode + " is not found");
        }
        byte[] data = new byte[0];
        try {
            data = ZKUtil.getData(this.zk, znode);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if (data != null) {
            return BytesUtil.bytes2int(data, true);
        } else {
            LOG.warn("can't get the date from znode: " + znode);
            return -1;
        }
    }

    public List<EncryptionKey> getKeys() throws KeeperException {
        String znode = IdentityZNodeHelper.getKeysZNode(this.identityName);
        if (ZKUtil.checkExists(this.zk, znode) == -1) {
            throw new IllegalArgumentException("The znode " + znode + " is not found");
        }
        List<String> typeNames = ZKUtil.listChildrenNoWatch(this.zk, znode);
        List<EncryptionKey> keys = new ArrayList<EncryptionKey>(typeNames.size());
        for (String typeName : typeNames) {
            byte[] key = getEncryptionKey(typeName);
            EncryptionKey encryptionKey = new EncryptionKey();
            try {
                encryptionKey.decode(key);
            } catch (IOException e) {
                e.printStackTrace();
            }
            encryptionKey.setKvno(getEncryptionKeyNo(typeName));
            keys.add(encryptionKey);
        }
        return keys;
    }

    public void setKeys(Map<EncryptionType, EncryptionKey> keys) throws KeeperException {
        if (ZKUtil.checkExists(this.zk, IdentityZNodeHelper.getKeysZNode(this.identityName)) == -1) {
            ZKUtil.createWithParents(this.zk, IdentityZNodeHelper.getKeysZNode(this.identityName));
        }
        Iterator<Map.Entry<EncryptionType, EncryptionKey>> it = keys.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<EncryptionType, EncryptionKey> pair = it.next();
            EncryptionType key = (EncryptionType) pair.getKey();
            ZKUtil.createWithParents(this.zk, IdentityZNodeHelper.getKeyTypeZNode(this.identityName, key.getName()));
            EncryptionKey value = (EncryptionKey) pair.getValue();
            ZKUtil.createSetData(this.zk, IdentityZNodeHelper.getEncryptionKeyZNode(this.identityName, key.getName()),
                    value.encode());
            ZKUtil.createSetData(this.zk, IdentityZNodeHelper.getEncryptionKeyNoZNode(this.identityName, key.getName()),
                    BytesUtil.int2bytes(value.getKvno(), true));
        }
    }

    public void deleteIdentity() throws KeeperException {
        ZKUtil.deleteNodeRecursively(this.zk, IdentityZNodeHelper.getIndentityZNode(this.identityName));
    }
}
