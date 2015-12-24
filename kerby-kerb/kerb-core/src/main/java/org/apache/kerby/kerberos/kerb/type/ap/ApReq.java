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
package org.apache.kerby.kerberos.kerb.type.ap;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessage;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessageType;
import org.apache.kerby.kerberos.kerb.type.ticket.Ticket;

/**
 AP-REQ          ::= [APPLICATION 14] SEQUENCE {
 pvno            [0] INTEGER (5),
 msg-type        [1] INTEGER (14),
 ap-options      [2] APOptions,
 ticket          [3] Ticket,
 authenticator   [4] EncryptedData -- Authenticator
 }
 */
public class ApReq extends KrbMessage {
    protected enum ApReqField implements EnumType {
        PVNO,
        MSG_TYPE,
        AP_OPTIONS,
        TICKET,
        AUTHENTICATOR;

        @Override
        public int getValue() {
            return ordinal();
        }

        @Override
        public String getName() {
            return name();
        }
    }

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new ExplicitField(ApReqField.PVNO, Asn1Integer.class),
            new ExplicitField(ApReqField.MSG_TYPE, Asn1Integer.class),
            new ExplicitField(ApReqField.AP_OPTIONS, ApOptions.class),
            new ExplicitField(ApReqField.TICKET, Ticket.class),
            new ExplicitField(ApReqField.AUTHENTICATOR, EncryptedData.class)
    };

    private Authenticator authenticator;

    public ApReq() {
        super(KrbMessageType.AP_REQ, fieldInfos);
    }

    public ApOptions getApOptions() {
        return getFieldAs(ApReqField.AP_OPTIONS, ApOptions.class);
    }

    public void setApOptions(ApOptions apOptions) {
        setFieldAs(ApReqField.AP_OPTIONS, apOptions);
    }

    public Ticket getTicket() {
        return getFieldAs(ApReqField.TICKET, Ticket.class);
    }

    public void setTicket(Ticket ticket) {
        setFieldAs(ApReqField.TICKET, ticket);
    }

    public Authenticator getAuthenticator() {
        return authenticator;
    }

    public void setAuthenticator(Authenticator authenticator) {
        this.authenticator = authenticator;
    }

    public EncryptedData getEncryptedAuthenticator() {
        return getFieldAs(ApReqField.AUTHENTICATOR, EncryptedData.class);
    }

    public void setEncryptedAuthenticator(EncryptedData encryptedAuthenticator) {
        setFieldAs(ApReqField.AUTHENTICATOR, encryptedAuthenticator);
    }
}

