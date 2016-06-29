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
package org.apache.kerby.kerberos.kerb.admin.server.kpasswd;

import org.apache.kerby.KOption;
import org.apache.kerby.KOptionInfo;
import org.apache.kerby.KOptionType;

/**
 * KDC passwd startup options
 */
public enum PasswdServerOption implements KOption {
    NONE(null),
    INNER_ADMIN_IMPL(new KOptionInfo("inner KDC impl", "inner KDC impl", KOptionType.OBJ)),
    ADMIN_REALM(new KOptionInfo("passwd realm", "passwd realm", KOptionType.STR)),
    ADMIN_HOST(new KOptionInfo("passwd host", "passwd host", KOptionType.STR)),
    ADMIN_PORT(new KOptionInfo("passwd port", "passwd port", KOptionType.INT)),
    ALLOW_TCP(new KOptionInfo("allow tcp", "allow tcp", KOptionType.BOOL)),
    ADMIN_TCP_PORT(new KOptionInfo("passwd tcp port", "passwd tcp port", KOptionType.INT)),
    ALLOW_UDP(new KOptionInfo("allow udp", "allow udp", KOptionType.BOOL)),
    ADMIN_UDP_PORT(new KOptionInfo("passwd udp port", "passwd udp port", KOptionType.INT)),
    WORK_DIR(new KOptionInfo("work dir", "work dir", KOptionType.DIR)),
    ENABLE_DEBUG(new KOptionInfo("enable debug", "enable debug", KOptionType.BOOL));

    private final KOptionInfo optionInfo;

    PasswdServerOption(KOptionInfo optionInfo) {
        this.optionInfo = optionInfo;
    }

    @Override
    public KOptionInfo getOptionInfo() {
        return optionInfo;
    }
}
