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
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;

/**
 * The AuthorizationData component as defined in RFC 4120 :
 * 
 * <pre>
 * AuthorizationData       ::= SEQUENCE {
 *         ad-type         [0] Int32,
 *         ad-data         [1] OCTET STRING
 * }
 * </pre>
 * 
 * We just implement what is in the SEQUENCE OF.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AuthorizationDataEntry extends KrbSequenceType {
    /**
     * The possible fields
     */
    protected enum AuthorizationDataEntryField implements EnumType {
        AD_TYPE,
        AD_DATA;

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

    /** The AuthorizationDataEntry's fields */
    private static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new ExplicitField(AuthorizationDataEntryField.AD_TYPE, Asn1Integer.class),
            new ExplicitField(AuthorizationDataEntryField.AD_DATA, Asn1OctetString.class)
    };

    /**
     * Creates an AuthorizationDataEntry instance
     */
    public AuthorizationDataEntry() {
        super(fieldInfos);
    }

    /**
     * @return The AuthorizationType (AD_TYPE) field
     */
    public AuthorizationType getAuthzType() {
        Integer value = getFieldAsInteger(AuthorizationDataEntryField.AD_TYPE);
        
        return AuthorizationType.fromValue(value);
    }

    /**
     * Sets the AuthorizationType (AD_TYPE) field
     * @param authzType The AuthorizationType to set
     */
    public void setAuthzType(AuthorizationType authzType) {
        setFieldAsInt(AuthorizationDataEntryField.AD_TYPE, authzType.getValue());
    }

    /**
     * @return The AuthorizationType (AD_DATA) field
     */
    public byte[] getAuthzData() {
        return getFieldAsOctets(AuthorizationDataEntryField.AD_DATA);
    }

    /**
     * Sets the AuthorizationData (AD_DATA) field
     * @param authzData The AuthorizationData to set
     */
    public void setAuthzData(byte[] authzData) {
        setFieldAsOctets(AuthorizationDataEntryField.AD_DATA, authzData);
    }
}
