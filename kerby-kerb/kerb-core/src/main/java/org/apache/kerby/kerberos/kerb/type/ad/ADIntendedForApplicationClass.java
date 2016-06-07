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
import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.kerberos.kerb.type.KerberosStrings;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;

/**
 * Asn1 Class for the "intended for application class" authorization type.
 *
 * RFC 4120
 * 
 * AD-INTENDED-FOR-APPLICATION-CLASS SEQUENCE { intended-application-class[0]
 * SEQUENCE OF GeneralString elements[1] AuthorizationData } AD elements
 * 
 * encapsulated within the intended-for-application-class element may be ignored
 * if the application server is not in one of the named classes of application
 * servers. Examples of application server classes include "FILESYSTEM", and
 * other kinds of servers.
 * 
 * This element and the elements it encapsulates may be safely ignored by
 * applications, application servers, and KDCs that do not implement this
 * element.
 * 
 * Contributed to the Apache Kerby Project by: Prodentity - Corrales, NM
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache DirectoryProject</a>
 */
public class ADIntendedForApplicationClass extends AuthorizationDataEntry {

    private IntendedForApplicationClass myIntForAppClass;

    private static class IntendedForApplicationClass extends KrbSequenceType {

        private AuthorizationData authzData;

        /**
         * The possible fields
         */
        protected enum IntendedForApplicationClassField implements EnumType {
            IFAC_intendedAppClass, IFAC_elements;

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

        /** The IntendedForApplicationClass's fields */
        private static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
                new ExplicitField(IntendedForApplicationClassField.IFAC_intendedAppClass, KerberosStrings.class),
                new ExplicitField(IntendedForApplicationClassField.IFAC_elements, AuthorizationData.class)};

        /**
         * Creates an IntendedForApplicationClass instance
         */
        IntendedForApplicationClass() {
            super(fieldInfos);
        }

        /**
         * Creates an IntendedForApplicationClass instance
         */
        IntendedForApplicationClass(KerberosStrings intendedAppClass) {
            super(fieldInfos);
            setFieldAs(IntendedForApplicationClassField.IFAC_intendedAppClass, intendedAppClass);
        }

        public KerberosStrings getIntendedForApplicationClass() {
            return getFieldAs(IntendedForApplicationClassField.IFAC_intendedAppClass, KerberosStrings.class);
        }

        /**
         * Sets the Intended Application Class value.
         */
        public void setIntendedForApplicationClass(KerberosStrings intendedAppClass) {
            setFieldAs(IntendedForApplicationClassField.IFAC_intendedAppClass, intendedAppClass);
            resetBodyLength();
        }

        public AuthorizationData getAuthzData() {
            if (authzData == null) {
                authzData = getFieldAs(IntendedForApplicationClassField.IFAC_elements, AuthorizationData.class);
            }
            return authzData;
        }

        public void setAuthzData(AuthorizationData authzData) {
            this.authzData = authzData;
            setFieldAs(IntendedForApplicationClassField.IFAC_elements, authzData);
            resetBodyLength();
        }
    }

    public ADIntendedForApplicationClass() {
        super(AuthorizationType.AD_INTENDED_FOR_APPLICATION_CLASS);
        myIntForAppClass = new IntendedForApplicationClass();
        myIntForAppClass.outerEncodeable = this;
    }

    public ADIntendedForApplicationClass(byte[] encoded) throws IOException {
        this();
        myIntForAppClass.decode(encoded);
    }

    public ADIntendedForApplicationClass(KerberosStrings intendedAppClass) throws IOException {
        this();
        myIntForAppClass.setIntendedForApplicationClass(intendedAppClass);
    }

    public KerberosStrings getIntendedForApplicationClass() {
        return myIntForAppClass.getIntendedForApplicationClass();
    }

    /**
     * Sets the Intended Application Class value.
     */
    public void setIntendedForApplicationClass(KerberosStrings intendedAppClass) {
        myIntForAppClass.setIntendedForApplicationClass(intendedAppClass);
    }

    public AuthorizationData getAuthorizationData() {
        return myIntForAppClass.getAuthzData();
    }

    public void setAuthorizationData(AuthorizationData authzData) {
        myIntForAppClass.setAuthzData(authzData);
    }

    @Override
    protected int encodingBodyLength() throws IOException {
        if (bodyLength == -1) {
            setAuthzData(myIntForAppClass.encode());
            bodyLength = super.encodingBodyLength();
        }
        return bodyLength;
    };

    @Override
    public void dumpWith(Asn1Dumper dumper, int indents) {
        super.dumpWith(dumper, indents);
        dumper.newLine();
        myIntForAppClass.dumpWith(dumper, indents + 8);
    }
}
