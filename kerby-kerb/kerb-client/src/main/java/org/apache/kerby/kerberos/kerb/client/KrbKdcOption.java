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

/**
 * This defines KDC options for client side API to use.
 */
public enum KrbKdcOption implements KOption {
    NONE(null),

    /* KDC flags */
    FORWARDABLE(new KOptionInfo("-f", "forwardable",
        KrbOptionGroup.KDC_FLAGS)),
    NOT_FORWARDABLE(new KOptionInfo("-F", "not forwardable",
        KrbOptionGroup.KDC_FLAGS)),
    PROXIABLE(new KOptionInfo("-p", "proxiable",
        KrbOptionGroup.KDC_FLAGS)),
    NOT_PROXIABLE(new KOptionInfo("-P", "not proxiable",
        KrbOptionGroup.KDC_FLAGS)),
    REQUEST_ANONYMOUS(new KOptionInfo("-n",
        "request anonymous", KrbOptionGroup.KDC_FLAGS)),
    VALIDATE(new KOptionInfo("-v", "validate",
        KrbOptionGroup.KDC_FLAGS)),
    RENEW(new KOptionInfo("-R", "renew",
        KrbOptionGroup.KDC_FLAGS)),
    RENEWABLE(new KOptionInfo("-r", "renewable-life",
        KrbOptionGroup.KDC_FLAGS)),
    RENEWABLE_OK(new KOptionInfo("renewable-ok", "renewable ok",
        KrbOptionGroup.KDC_FLAGS)),
    CANONICALIZE(new KOptionInfo("-C", "canonicalize",
        KrbOptionGroup.KDC_FLAGS)),
    ANONYMOUS(new KOptionInfo("-n", "anonymous",
              KrbOptionGroup.KDC_FLAGS));

    private final KOptionInfo optionInfo;

    KrbKdcOption(KOptionInfo optionInfo) {
        this.optionInfo = optionInfo;
    }

    @Override
    public KOptionInfo getOptionInfo() {
        return optionInfo;
    }

    public static KrbKdcOption fromOptionName(String optionName) {
        if (optionName != null) {
            for (KrbKdcOption ko : values()) {
                if (ko.optionInfo != null
                    && ko.optionInfo.getName().equals(optionName)) {
                    return ko;
                }
            }
        }
        return NONE;
    }
}
