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
package org.apache.kerby.kerberos.kerb.codec.pac;

public interface PacConstants {

    static final int PAC_VERSION = 0;

    static final int LOGON_INFO = 1;
    static final int CREDENTIAL_TYPE = 2;
    static final int SERVER_CHECKSUM = 6;
    static final int PRIVSVR_CHECKSUM = 7;

    static final int LOGON_EXTRA_SIDS = 0x20;
    static final int LOGON_RESOURCE_GROUPS = 0x200;

    static final long FILETIME_BASE = -11644473600000L;

    static final int MD5_KRB_SALT = 17;
    static final int MD5_BLOCK_LENGTH = 64;

}
