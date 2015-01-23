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
package org.apache.kerby.kerberos.kerb.spec.common;

import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.kerberos.kerb.spec.KrbSequenceType;

/**
 AD-TOKEN ::= SEQUENCE {
    token     [0]  OCTET STRING,
 }
*/
public class AdToken extends KrbSequenceType {
    private static int TOKEN = 0;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(TOKEN, KrbToken.class)
    };

    public AdToken() {
        super(fieldInfos);
    }

    public KrbToken getToken() {
        return getFieldAs(TOKEN, KrbToken.class);
    }

    public void setToken(KrbToken token) {
        setFieldAs(TOKEN, token);
    }

}
