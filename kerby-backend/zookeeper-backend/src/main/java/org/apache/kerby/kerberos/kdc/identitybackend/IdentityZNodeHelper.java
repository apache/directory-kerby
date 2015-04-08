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

public class IdentityZNodeHelper {

    private final static String IDENTITIES_ZNODE_NAME = "identities";
    private final static String PRINCIPAL_NAME_ZNODE_NAME = "principalName";
    private final static String KEY_VERSION_ZNODE_NAME = "keyVersion";
    private final static String KDC_FLAGS_ZNODE_NAME = "kdcFlags";
    private final static String DISABLED_ZNODE_NAME = "disabled";
    private final static String LOCKED_ZNODE_NAME = "locked";
    private final static String EXPIRE_TIME_ZNODE_NAME = "expireTime";
    private final static String CREATED_TIME_ZNODE_NAME = "createdTime";
    private final static String KEYS_ZNODE_NAME = "keys";
    private final static String KEY_TYPE_ZNODE_NAME = "keyType";
    private final static String KEY_DATA_ZNODE_NAME = "keyData";
    private final static String ENCRYPTION_KEY_NO_ZNODE_NAME = "keyNo";
    private static String baseZNode = "/kerby";

    public static String getBaseZNode() {
      return baseZNode;
    }

    public static String getIdentitiesZNode() {
      return ZKUtil.joinZNode(getBaseZNode(), IDENTITIES_ZNODE_NAME);
    }

    public static String getIndentityZNode(String principalName) {
        return ZKUtil.joinZNode(getIdentitiesZNode(), principalName);
    }

    public static String getPrincipalNameZnode(String principalName) {
        return ZKUtil.joinZNode(getIndentityZNode(principalName), PRINCIPAL_NAME_ZNODE_NAME);
    }

    public static String getKeyVersionZNode(String principalName) {
        return ZKUtil.joinZNode(getIndentityZNode(principalName), KEY_VERSION_ZNODE_NAME);
    }

    public static String getKdcFlagsZNode(String principalName) {
        return ZKUtil.joinZNode(getIndentityZNode(principalName), KDC_FLAGS_ZNODE_NAME);
    }

    public static String getDisabledZNode(String principalName) {
        return ZKUtil.joinZNode(getIndentityZNode(principalName), DISABLED_ZNODE_NAME);
    }

    public static String getLockedZNode(String principalName) {
        return ZKUtil.joinZNode(getIndentityZNode(principalName), LOCKED_ZNODE_NAME);
    }

    public static String getExpireTimeZNode(String principalName) {
        return ZKUtil.joinZNode(getIndentityZNode(principalName), EXPIRE_TIME_ZNODE_NAME);
    }

    public static String getCreatedTimeZNode(String principalName) {
        return ZKUtil.joinZNode(getIndentityZNode(principalName), CREATED_TIME_ZNODE_NAME);
    }

    public static String getKeysZNode(String principalName) {
        return ZKUtil.joinZNode(getIndentityZNode(principalName), KEYS_ZNODE_NAME);
    }

    public static String getKeyTypeZNode(String principalName, String type) {
        return ZKUtil.joinZNode(getKeysZNode(principalName), type);
    }

    public static String getEncryptionKeyTypeZNode(String principalName, String type) {
        return ZKUtil.joinZNode(getKeyTypeZNode(principalName, type), KEY_TYPE_ZNODE_NAME);
    }

    public static String getEncryptionKeyDataZNode(String principalName, String type) {
        return ZKUtil.joinZNode(getKeyTypeZNode(principalName, type), KEY_DATA_ZNODE_NAME);
    }

    public static String getEncryptionKeyNoZNode(String principalName, String type) {
        return ZKUtil.joinZNode(getKeyTypeZNode(principalName, type), ENCRYPTION_KEY_NO_ZNODE_NAME);
    }
}