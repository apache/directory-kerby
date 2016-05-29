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

import java.io.IOException;

import org.apache.kerby.asn1.Asn1Dumper;
import org.apache.kerby.asn1.EnumType;

/**
 * Contributed to the Apache Kerby Project by: Prodentity - Corrales, NM
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache DirectoryProject</a>
 */
public class AuthorizationDataWrapper extends AuthorizationDataEntry {

    private AuthorizationData authorizationData;

    public enum WrapperType implements EnumType {
        AD_IF_RELEVANT(AuthorizationType.AD_IF_RELEVANT.getValue()), AD_MANDATORY_FOR_KDC(
                AuthorizationType.AD_MANDATORY_FOR_KDC.getValue());

        /** The internal value */
        private final int value;

        /**
         * Create a new enum
         */
        WrapperType(int value) {
            this.value = value;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public int getValue() {
            return value;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String getName() {
            return name();
        }

    }

    public AuthorizationDataWrapper(WrapperType type) {
        super(Enum.valueOf(AuthorizationType.class, type.name()));
    }

    public AuthorizationDataWrapper(WrapperType type, AuthorizationData authzData) throws IOException {
        super(Enum.valueOf(AuthorizationType.class, type.name()));
        authorizationData = authzData;
        if (authzData != null) {
            setAuthzData(authzData.encode());
        } else {
            setAuthzData(null);
        }
    }

    /**
     * @return The AuthorizationType (AD_DATA) field
     * @throws IOException
     */
    public AuthorizationData getAuthorizationData() throws IOException {
        AuthorizationData result;
        if (authorizationData != null) {
            result = authorizationData;
        } else {
            result = new AuthorizationData();
            result.decode(getAuthzData());
        }
        return result;
    }

    /**
     * Sets the AuthorizationData (AD_DATA) field
     * 
     * @param authzData The AuthorizationData to set
     * @throws IOException
     */
    public void setAuthorizationData(AuthorizationData authzData) throws IOException {
        setAuthzData(authzData.encode());
    }

    @Override
    public void dumpWith(Asn1Dumper dumper, int indents) {
        super.dumpWith(dumper, indents);
        dumper.newLine();
        try {
            getAuthorizationData().dumpWith(dumper, indents + 8);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
