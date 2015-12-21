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
 * This defines all the token options.
 */
public enum TokenOption implements KOption {
    NONE(null),

    USE_TOKEN(new KOptionInfo("use-id-token", "Using identity token")),
    USER_ID_TOKEN(new KOptionInfo("user-id-token", "User identity token",
        KOptionType.STR)),
    USER_AC_TOKEN(new KOptionInfo("user-ac-token", "User access token",
        KOptionType.STR));

    private final KOptionInfo optionInfo;

    TokenOption(KOptionInfo optionInfo) {
        this.optionInfo = optionInfo;
    }

    @Override
    public KOptionInfo getOptionInfo() {
        return optionInfo;
    }

    public static TokenOption fromOptionName(String optionName) {
        if (optionName != null) {
            for (TokenOption ko : values()) {
                if (ko.optionInfo != null
                    && ko.optionInfo.getName().equals(optionName)) {
                    return ko;
                }
            }
        }
        return NONE;
    }
}
