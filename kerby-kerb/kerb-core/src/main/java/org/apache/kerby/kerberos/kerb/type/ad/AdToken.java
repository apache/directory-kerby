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
package org.apache.kerby.kerberos.kerb.type.ad;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;
import org.apache.kerby.kerberos.kerb.type.base.KrbToken;

/**
 * The AdToken component as defined in "Token Pre-Authentication for Kerberos", "draft-ietf-kitten-kerb-token-preauth-01" 
 * (not yet published, but stored in docs/Token-preauth.pdf) :
 * 
 * <pre>
 * 6.4. AD-TOKEN
 *   The new Authorization Data Type AD-TOKEN type contains token
 *   derivation and is meant to be encapsulated into AD-KDC-ISSUED type
 *   and to be put into tgt or service tickets. Application can safely
 *   ignore it if the application doesn't understand it. The token field
 *   SHOULD be ASN.1 encoded of the binary representation of the
 *   serialization result of the derivation token according to [JWT].
 *   
 *         AD-TOKEN ::= SEQUENCE {
 *            token     [0]  OCTET STRING,
 *         }
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AdToken extends KrbSequenceType {
    /**
     * The possible fields
     */
    protected enum AdTokenField implements EnumType {
        TOKEN;

        /**
         * {@inheritDoc}
         */
        @Override
        public int getValue() {
            return ordinal();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String getName() {
            return name();
        }
    }

    /** The AdToken's fields */
    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new ExplicitField(AdTokenField.TOKEN, KrbToken.class)
    };

    /**
     * Creates an instance of AdToken
     */
    public AdToken() {
        super(fieldInfos);
    }

    /**
     * @return The token
     */
    public KrbToken getToken() {
        return getFieldAs(AdTokenField.TOKEN, KrbToken.class);
    }

    /**
     * Sets the token
     * @param token The token to store
     */
    public void setToken(KrbToken token) {
        setFieldAs(AdTokenField.TOKEN, token);
    }
}
