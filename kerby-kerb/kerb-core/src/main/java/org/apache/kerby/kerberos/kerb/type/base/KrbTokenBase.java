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
package org.apache.kerby.kerberos.kerb.type.base;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;

/**
 * KRB-TOKEN_VALUE ::= SEQUENCE {
 * token-format [0] INTEGER,
 * token-value  [1] OCTET STRING,
 * }
 */
public class KrbTokenBase extends KrbSequenceType {

    protected enum KrbTokenField implements EnumType {
        TOKEN_FORMAT,
        TOKEN_VALUE;

        @Override
        public int getValue() {
            return ordinal();
        }

        @Override
        public String getName() {
            return name();
        }
    }

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[]{
            new ExplicitField(KrbTokenField.TOKEN_FORMAT, Asn1Integer.class),
            new ExplicitField(KrbTokenField.TOKEN_VALUE, Asn1OctetString.class)
    };
    
    /**
     * Default constructor.
     */
    public KrbTokenBase() {
        super(fieldInfos);
    }

    /**
     * Get token format.
     * @return The token format
     */
    public TokenFormat getTokenFormat() {
        Integer value = getFieldAsInteger(KrbTokenField.TOKEN_FORMAT);
        return TokenFormat.fromValue(value);
    }

    /**
     * Set token format.
     * @param tokenFormat The token format
     */
    public void setTokenFormat(TokenFormat tokenFormat) {
        setFieldAsInt(KrbTokenField.TOKEN_FORMAT, tokenFormat.getValue());
    }

    /**
     * Get token value.
     * @return The token value
     */
    public byte[] getTokenValue() {
        return getFieldAsOctets(KrbTokenField.TOKEN_VALUE);
    }

    /**
     * Set token value.
     * @param tokenValue The token value
     */
    public void setTokenValue(byte[] tokenValue) {
        setFieldAsOctets(KrbTokenField.TOKEN_VALUE, tokenValue);
    }

}
