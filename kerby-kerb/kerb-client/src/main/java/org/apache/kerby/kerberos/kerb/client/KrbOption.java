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
package org.apache.kerby.kerberos.kerb.client;

public enum KrbOption implements KOption {
    NONE("NONE"),
    LIFE_TIME("life time", KOptionType.INT),
    START_TIME("start time", KOptionType.INT),
    RENEWABLE_TIME("renewable lifetime", KOptionType.INT),
    FORWARDABLE("forwardable"),
    NOT_FORWARDABLE("not forwardable"),
    PROXIABLE("proxiable"),
    NOT_PROXIABLE("not proxiable"),
    ANONYMOUS("anonymous"),
    INCLUDE_ADDRESSES("include addresses"),
    NOT_INCLUDE_ADDRESSES("do not include addresses"),
    VALIDATE("validate"),
    RENEW("renew"),
    CANONICALIZE("canonicalize"),
    AS_ENTERPRISE_PN("as-enterprise-pn", "client is enterprise principal name"),
    USE_KEYTAB("use-keytab", "use keytab"),
    USE_DFT_KEYTAB("user-default-keytab", "use default client keytab"),
    USER_KEYTAB_FILE("user-keytab-file", "filename of keytab to use", KOptionType.FILE),
    KRB5_CACHE("krb5-cache", "K5 cache name", KOptionType.FILE),
    SERVICE("service", KOptionType.STR),
    ARMOR_CACHE("armor-cache", "armor credential cache", KOptionType.STR),

    CONF_DIR("conf dir", KOptionType.DIR),
    USER_PASSWD("user-passwd", "User plain password"),

    PKINIT_X509_IDENTITY("x509-identities", "X509 user private key and cert", KOptionType.STR),
    PKINIT_X509_PRIVATE_KEY("x509-privatekey", "X509 user private key", KOptionType.STR),
    PKINIT_X509_CERTIFICATE("x509-cert", "X509 user certificate", KOptionType.STR),
    PKINIT_X509_ANCHORS("x509-anchors", "X509 anchors", KOptionType.STR),
    PKINIT_X509_ANONYMOUS("x509-anonymous", "X509 anonymous"),
    PKINIT_USING_RSA("using-rsa-or-dh", "Using RSA or DH"),

    TOKEN_USING_IDTOKEN("using-id-token", "Using identity token"),
    TOKEN_USER_ID_TOKEN("user-id-token", "User identity token", KOptionType.STR),
    TOKEN_USER_AC_TOKEN("user-ac-token", "User access token", KOptionType.STR),

    ;

    private String name;
    private KOptionType type;
    private String description;
    private Object value;

    KrbOption(String description) {
        this(description, KOptionType.NOV); // As a flag by default
    }

    KrbOption(String description, KOptionType type) {
        this.description = description;
        this.type = type;
    }

    KrbOption(String name, String description) {
        this(name, description, KOptionType.NOV); // As a flag by default
    }

    KrbOption(String name, String description, KOptionType type) {
        this.name = name;
        this.description = description;
        this.type = type;
    }

    @Override
    public String getOptionName() {
        return name();
    }

    public void setType(KOptionType type) {
        this.type = type;
    }

    public KOptionType getType() {
        return this.type;
    }

    @Override
    public void setName(String name) {
        this.name = name;
    }

    @Override
    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public String getName() {
        if (name != null) {
            return name;
        }
        return name();
    }

    @Override
    public String getDescription() {
        return this.description;
    }

    @Override
    public void setValue(Object value) {
        this.value = value;
    }

    @Override
    public Object getValue() {
        return value;
    }

    public static KrbOption fromName(String name) {
        if (name != null) {
            for (KrbOption ko : values()) {
                if (ko.getName().equals(name)) {
                    return (KrbOption) ko;
                }
            }
        }
        return NONE;
    }

    public static KrbOption fromOptionName(String optionName) {
        if (optionName != null) {
            for (KrbOption ko : values()) {
                if (ko.getOptionName().equals(optionName)) {
                    return (KrbOption) ko;
                }
            }
        }
        return NONE;
    }
}
