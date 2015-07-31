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

import org.apache.kerby.KOption;
import org.apache.kerby.KOptionType;

public enum KrbOption implements KOption {
    NONE("NONE"),
    CLIENT_PRINCIPAL("client-principal", "Client principal", KOptionType.STR),
    KDC_REALM("kdc realm", KOptionType.STR),
    KDC_HOST("kdc host", KOptionType.STR),
    KDC_TCP_PORT("kdc tcp port", KOptionType.INT),
    ALLOW_UDP("allow udp", KOptionType.BOOL),
    ALLOW_TCP("allow tcp", KOptionType.BOOL),
    KDC_UDP_PORT("kdc udp port", KOptionType.INT),
    CONN_TIMEOUT("connection timeout", KOptionType.INT),
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

    USE_PASSWD("using password", "using password"),
    USER_PASSWD("user-passwd", "User plain password"),

    USE_KEYTAB("use-keytab", "use keytab"),
    USE_DFT_KEYTAB("-i", "use default client keytab (with -k)"),
    KEYTAB_FILE("keytab-file", "filename of keytab to use", KOptionType.FILE),

    KRB5_CACHE("krb5-cache", "K5 cache name", KOptionType.FILE),
    SERVICE_PRINCIPAL("service-principal", "service principal", KOptionType.STR),
    SERVER_PRINCIPAL("server-principal", "server principal", KOptionType.STR),
    ARMOR_CACHE("armor-cache", "armor credential cache", KOptionType.STR),

    USE_PKINIT("use-pkinit", "using pkinit"),
    PKINIT_X509_IDENTITY("x509-identities", "X509 user private key and cert", KOptionType.STR),
    PKINIT_X509_PRIVATE_KEY("x509-privatekey", "X509 user private key", KOptionType.STR),
    PKINIT_X509_CERTIFICATE("x509-cert", "X509 user certificate", KOptionType.STR),
    PKINIT_X509_ANCHORS("x509-anchors", "X509 anchors", KOptionType.STR),
    PKINIT_USING_RSA("using-rsa-or-dh", "Using RSA or DH"),

    USE_PKINIT_ANONYMOUS("use-pkinit-anonymous", "X509 anonymous"),

    USE_TOKEN("use-id-token", "Using identity token"),
    TOKEN_USER_ID_TOKEN("user-id-token", "User identity token", KOptionType.STR),
    TOKEN_USER_AC_TOKEN("user-ac-token", "User access token", KOptionType.STR),
    USE_TGT("use tgt", "use tgt to get service ticket", KOptionType.OBJ);

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

    /**
     * {@inheritDoc}
     */
    @Override
    public String getOptionName() {
        return name();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setType(KOptionType type) {
        this.type = type;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public KOptionType getType() {
        return this.type;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setName(String name) {
        this.name = name;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getName() {
        if (name != null) {
            return name;
        }
        return name();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getDescription() {
        return this.description;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setValue(Object value) {
        this.value = value;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Object getValue() {
        return value;
    }

    /**
     * {@inheritDoc}
     */
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
