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

public enum KrbOption {
    LIFE_TIME("-l lifetime"),
    START_TIME("-s start time"),
    RENEWABLE_TIME("-r renewable lifetime"),
    FORWARDABLE("-f forwardable"),
    NOT_FORWARDABLE("-F not forwardable"),
    PROXIABLE("-p proxiable"),
    NOT_PROXIABLE("-P not proxiable"),
    ANONYMOUS("-n anonymous"),
    INCLUDE_ADDRESSES("-a include addresses"),
    NOT_INCLUDE_ADDRESSES("-A do not include addresses"),
    VALIDATE("-v validate"),
    RENEW("-R renew"),
    CANONICALIZE("-C canonicalize"),
    AS_ENTERPRISE_PN("-E client is enterprise principal name"),
    USE_KEYTAB("-k use keytab"),
    USE_DFT_KEYTAB("-i use default client keytab (with -k)"),
    USER_KEYTAB_FILE("-t filename of keytab to use"),
    KRB5_CACHE("-c Kerberos 5 cache name"),
    SERVICE("-S service"),
    ARMOR_CACHE("-T armor credential cache"),
    XATTR("-X <attribute>[=<value>]"),

    USER_PASSWD("user_passwd", "User plain password"),

    PKINIT_X509_IDENTITY("x509_identities", "X509 user private key and cert"),
    PKINIT_X509_PRIVATE_KEY("x509_privatekey", "X509 user private key"),
    PKINIT_X509_CERTIFICATE("x509_cert", "X509 user certificate"),
    PKINIT_X509_ANCHORS("x509_anchors", "X509 anchors"),
    PKINIT_X509_ANONYMOUS("x509_anonymous", "X509 anonymous"),
    PKINIT_USING_RSA("using_rsa_or_dh", "Using RSA or DH"),

    TOKEN_USING_IDTOKEN("using_id_token", "Using identity token"),
    TOKEN_USER_ID_TOKEN("user_id_token", "User identity token"),
    TOKEN_USER_AC_TOKEN("user_ac_token", "User access token"),

    ;

    private String name;
    private String description;
    private Object value;

    KrbOption(String description) {
        this.description = description;
    }

    KrbOption(String name, String description) {
        this.name = name;
        this.description = description;
    }

    public String getName() {
        if (name != null) {
            return name;
        }
        return name();
    }

    public String getDescription() {
        return this.description;
    }

    public void setValue(Object value) {
        this.value = value;
    }

    public Object getValue() {
        return value;
    }
}
