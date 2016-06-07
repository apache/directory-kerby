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
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;

/**
 * Asn1 Class for the "intended for server" authorization type.
 *
 * RFC 4120
 * 
 * AD-INTENDED-FOR-SERVER SEQUENCE { intended-server[0] SEQUENCE OF
 * PrincipalName elements[1] AuthorizationData }
 * 
 * AD elements encapsulated within the intended-for-server element may be
 * ignored if the application server is not in the list of principal names of
 * intended servers. Further, a KDC issuing a ticket for an application server
 * can remove this element if the application server is not in the list of
 * intended servers.
 * 
 * Application servers should check for their principal name in the
 * intended-server field of this element. If their principal name is not found,
 * this element should be ignored. If found, then the encapsulated elements
 * should be evaluated in the same manner as if they were present in the top
 * level authorization data field. Applications and application servers that do
 * not implement this element should reject tickets that contain authorization
 * data elements of this type.
 * 
 * Contributed to the Apache Kerby Project by: Prodentity - Corrales, NM
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache DirectoryProject</a>
 */
public class ADIntendedForServer extends AuthorizationDataEntry {

    private IntForSrvr myIntForSrvr;

    private static class IntForSrvr extends KrbSequenceType {

        private AuthorizationData authzData;

        protected enum IntForSrvrField implements EnumType {
            IFS_intendedServer, IFS_elements;

            @Override
            public int getValue() {
                return ordinal();
            }

            @Override
            public String getName() {
                return name();
            }
        }

        /** The IntendedForServer's fields */
        private static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
                new ExplicitField(IntForSrvrField.IFS_intendedServer, PrincipalList.class),
                new ExplicitField(IntForSrvrField.IFS_elements, AuthorizationData.class)};

        IntForSrvr() {
            super(fieldInfos);
        }

        IntForSrvr(PrincipalList principals) {
            super(fieldInfos);
            setFieldAs(IntForSrvrField.IFS_intendedServer, principals);
        }

        public PrincipalList getIntendedServer() {
            return getFieldAs(IntForSrvrField.IFS_intendedServer, PrincipalList.class);
        }

        public void setIntendedServer(PrincipalList principals) {
            setFieldAs(IntForSrvrField.IFS_intendedServer, principals);
            resetBodyLength();
        }

        public AuthorizationData getAuthzData() {
            if (authzData == null) {
                authzData = getFieldAs(IntForSrvrField.IFS_elements, AuthorizationData.class);
            }
            return authzData;
        }

        public void setAuthzData(AuthorizationData authzData) {
            this.authzData = authzData;
            setFieldAs(IntForSrvrField.IFS_elements, authzData);
            resetBodyLength();
        }
    }

    public ADIntendedForServer() {
        super(AuthorizationType.AD_INTENDED_FOR_SERVER);
        myIntForSrvr = new IntForSrvr();
        myIntForSrvr.outerEncodeable = this;
    }

    public ADIntendedForServer(byte[] encoded) throws IOException {
        this();
        myIntForSrvr.decode(encoded);
    }

    public ADIntendedForServer(PrincipalList principals) throws IOException {
        this();
        myIntForSrvr.setIntendedServer(principals);
    }

    public PrincipalList getIntendedServer() {
        return myIntForSrvr.getIntendedServer();
    }

    public void setIntendedServer(PrincipalList principals) {
        myIntForSrvr.setIntendedServer(principals);
    }

    public AuthorizationData getAuthorizationData() {
        return myIntForSrvr.getAuthzData();
    }

    public void setAuthorizationData(AuthorizationData authzData) {
        myIntForSrvr.setAuthzData(authzData);
    }

    @Override
    protected int encodingBodyLength() throws IOException {
        if (bodyLength == -1) {
            setAuthzData(myIntForSrvr.encode());
            bodyLength = super.encodingBodyLength();
        }
        return bodyLength;
    };

    @Override
    public void dumpWith(Asn1Dumper dumper, int indents) {
        super.dumpWith(dumper, indents);
        dumper.newLine();
        myIntForSrvr.dumpWith(dumper, indents + 8);
    }
}
