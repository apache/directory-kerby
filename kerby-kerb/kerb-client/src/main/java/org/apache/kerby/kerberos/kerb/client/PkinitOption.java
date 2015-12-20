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
import org.apache.kerby.KOptionInfo;
import org.apache.kerby.KOptionType;

/**
 * This defines all the options that come across the client side.
 */
public enum PkinitOption implements KOption {
    NONE(null),
    USE_PKINIT(new KOptionInfo("use-pkinit", "using pkinit")),
    X509_IDENTITY(new KOptionInfo("x509-identities", "X509 user private key and cert",
        KOptionType.STR)),
    X509_PRIVATE_KEY(new KOptionInfo("x509-privatekey", "X509 user private key",
        KOptionType.STR)),
    X509_CERTIFICATE(new KOptionInfo("x509-cert", "X509 user certificate", KOptionType.STR)),
    X509_ANCHORS(new KOptionInfo("x509-anchors", "X509 anchors", KOptionType.STR)),
    USING_RSA(new KOptionInfo("using-rsa-or-dh", "Using RSA or DH")),
    USE_ANONYMOUS(new KOptionInfo("use-pkinit-anonymous", "X509 anonymous"));

    private final KOptionInfo optionInfo;

    PkinitOption(KOptionInfo optionInfo) {
        this.optionInfo = optionInfo;
    }

    @Override
    public KOptionInfo getOptionInfo() {
        return optionInfo;
    }

    public static PkinitOption fromOptionName(String optionName) {
        if (optionName != null) {
            for (PkinitOption ko : values()) {
                if (ko.optionInfo != null
                    && ko.optionInfo.getName().equals(optionName)) {
                    return ko;
                }
            }
        }
        return NONE;
    }
}
