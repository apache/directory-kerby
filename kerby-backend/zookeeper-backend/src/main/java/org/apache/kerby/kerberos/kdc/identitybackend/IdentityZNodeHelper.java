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

import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.ZooKeeper;

import java.util.List;

public class IdentityZNodeHelper {

    private static final String IDENTITIES_ZNODE_NAME = "identities";
    private static final String PRINCIPAL_NAME_ZNODE_NAME = "principalName";
    private static final String KEY_VERSION_ZNODE_NAME = "keyVersion";
    private static final String KDC_FLAGS_ZNODE_NAME = "kdcFlags";
    private static final String DISABLED_ZNODE_NAME = "disabled";
    private static final String LOCKED_ZNODE_NAME = "locked";
    private static final String EXPIRE_TIME_ZNODE_NAME = "expireTime";
    private static final String CREATED_TIME_ZNODE_NAME = "createdTime";
    private static final String KEYS_ZNODE_NAME = "keys";
    private static final String KEY_TYPE_ZNODE_NAME = "keyType";
    private static final String KEY_ZNODE_NAME = "keyData";
    private static final String ENCRYPTION_KEY_NO_ZNODE_NAME = "keyNo";
    private static String baseZNode = "/kerby";

    /**
     * Get base znode.
     * @return Base
     */
    public static String getBaseZNode() {
      return baseZNode;
    }

    /**
     * Get identities znode.
     * @return Identities.
     */
    public static String getIdentitiesZNode() {
      return ZKUtil.joinZNode(getBaseZNode(), IDENTITIES_ZNODE_NAME);
    }

    /**
     * Get identity znode.
     * @param principalName Principal name
     * @return Identity
     */
    public static String getIndentityZNode(String principalName) {
        return ZKUtil.joinZNode(getIdentitiesZNode(), principalName);
    }

    /**
     * Get principal name znode.
     * @param principalName Principal name.
     * @return Principal name
     */
    public static String getPrincipalNameZnode(String principalName) {
        return ZKUtil.joinZNode(getIndentityZNode(principalName), PRINCIPAL_NAME_ZNODE_NAME);
    }

    /**
     * Get key version znode.
     * @param principalName Principal name.
     * @return Key version
     */
    public static String getKeyVersionZNode(String principalName) {
        return ZKUtil.joinZNode(getIndentityZNode(principalName), KEY_VERSION_ZNODE_NAME);
    }

    /**
     * Get kdc flags znode.
     * @param principalName Principal name.
     * @return Kdc flags
     */
    public static String getKdcFlagsZNode(String principalName) {
        return ZKUtil.joinZNode(getIndentityZNode(principalName), KDC_FLAGS_ZNODE_NAME);
    }

    /**
     * Get disabled znode.
     * @param principalName Principal name.
     * @return Whether this principal's account is disabled.
     */
    public static String getDisabledZNode(String principalName) {
        return ZKUtil.joinZNode(getIndentityZNode(principalName), DISABLED_ZNODE_NAME);
    }

    /**
     * Get locked znode.
     * @param principalName Principal name.
     * @return Whether principal's account is locked
     */
    public static String getLockedZNode(String principalName) {
        return ZKUtil.joinZNode(getIndentityZNode(principalName), LOCKED_ZNODE_NAME);
    }

    /**
     * Get expire time znode.
     * @param principalName Principal name.
     * @return Expired time.
     */
    public static String getExpireTimeZNode(String principalName) {
        return ZKUtil.joinZNode(getIndentityZNode(principalName), EXPIRE_TIME_ZNODE_NAME);
    }

    /**
     * Get created time znode.
     * @param principalName Principal name.
     * @return Created time.
     */
    public static String getCreatedTimeZNode(String principalName) {
        return ZKUtil.joinZNode(getIndentityZNode(principalName), CREATED_TIME_ZNODE_NAME);
    }

    /**
     * Get keys znode.
     * @param principalName Principal name.
     * @return Key
     */
    public static String getKeysZNode(String principalName) {
        return ZKUtil.joinZNode(getIndentityZNode(principalName), KEYS_ZNODE_NAME);
    }

    /**
     * Get key type znode.
     * @param principalName Principal name.
     * @param type Key type.
     * @return Key type.
     */
    public static String getKeyTypeZNode(String principalName, String type) {
        return ZKUtil.joinZNode(getKeysZNode(principalName), type);
    }

    /**
     * Get encryption key type znode.
     * @param principalName Principal name.
     * @param type Encryption type.
     * @return Encryption key type
     */
    public static String getEncryptionKeyTypeZNode(String principalName, String type) {
        return ZKUtil.joinZNode(getKeyTypeZNode(principalName, type), KEY_TYPE_ZNODE_NAME);
    }

    /**
     * Get encryption key znode.
     * @param principalName Principal Name.
     * @param type Encryption type.
     * @return Encryption key
     */
    public static String getEncryptionKeyZNode(String principalName, String type) {
        return ZKUtil.joinZNode(getKeyTypeZNode(principalName, type), KEY_ZNODE_NAME);
    }

    /**
     * Get encryption key kvno znode.
     * @param principalName Principal name.
     * @param type Key type.
     * @return Encryption key
     */
    public static String getEncryptionKeyNoZNode(String principalName, String type) {
        return ZKUtil.joinZNode(getKeyTypeZNode(principalName, type), ENCRYPTION_KEY_NO_ZNODE_NAME);
    }

    /**
     * Get identity names.
     *
     * @throws org.apache.zookeeper.KeeperException e
     * @param zk The zookeeper
     * @return The list of principal names.
     */
    public static List<String> getIdentityNames(ZooKeeper zk) throws KeeperException {
        List<String> identityNames = ZKUtil.listChildrenNoWatch(zk, getIdentitiesZNode());
        return identityNames;
    }
}