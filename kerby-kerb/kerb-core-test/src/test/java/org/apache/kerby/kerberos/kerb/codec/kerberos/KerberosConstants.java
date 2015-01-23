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
package org.apache.kerby.kerberos.kerb.codec.kerberos;

public interface KerberosConstants {

    static final String KERBEROS_OID = "1.2.840.113554.1.2.2";
    static final String KERBEROS_VERSION = "5";

    static final String KERBEROS_AP_REQ = "14";
    
    static final int AF_INTERNET = 2;
    static final int AF_CHANET = 5;
    static final int AF_XNS = 6;
    static final int AF_ISO = 7;
    
    static final int AUTH_DATA_RELEVANT = 1;
    static final int AUTH_DATA_PAC = 128;

    static final int DES_ENC_TYPE = 3;
    static final int RC4_ENC_TYPE = 23;
    static final String RC4_ALGORITHM = "ARCFOUR";
    static final String HMAC_ALGORITHM = "HmacMD5";
    static final int CONFOUNDER_SIZE = 8;
    static final int CHECKSUM_SIZE = 16;

}