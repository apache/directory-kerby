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
package org.apache.kerby.kerberos.kerb.spec.pa.token;

import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.kerberos.kerb.spec.KrbSequenceType;
import org.apache.kerby.kerberos.kerb.spec.common.KrbToken;

/**
 PA-TOKEN-REQUEST ::= SEQUENCE {
    token          [0]  OCTET STRING,
    tokenInfo      [1]  TokenInfo
 }
*/
public class PaTokenRequest extends KrbSequenceType {
    private static int TOKEN_INFO = 0;
    private static int TOKEN = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(TOKEN_INFO, TokenInfo.class),
            new Asn1FieldInfo(TOKEN, KrbToken.class)
    };

    public PaTokenRequest() {
        super(fieldInfos);
    }

    public KrbToken getToken() {
        return getFieldAs(TOKEN, KrbToken.class);
    }

    public void setToken(KrbToken token) {
        setFieldAs(TOKEN, token);
    }

    public String getTokenInfo() {
        return getFieldAsString(TOKEN_INFO);
    }

    public void setTokenInfo(TokenInfo tokenInfo) {
        setFieldAs(TOKEN_INFO, tokenInfo);
    }

}
