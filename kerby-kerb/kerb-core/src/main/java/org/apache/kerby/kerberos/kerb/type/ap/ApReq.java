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
 * The AP-REQ message, as defined in RFC 4120 :
 * <pre>
 * AP-REQ          ::= [APPLICATION 14] SEQUENCE {
 *         pvno            [0] INTEGER (5),
 *         msg-type        [1] INTEGER (14),
 *         ap-options      [2] APOptions,
 *         ticket          [3] Ticket,
 *         authenticator   [4] EncryptedData -- Authenticator
 * }
 * </pre>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ApReq extends KrbMessage {
    /**
     * The possible fields
     */
    protected enum ApReqField implements EnumType {
        PVNO,
        MSG_TYPE,
        AP_OPTIONS,
        TICKET,
        AUTHENTICATOR;

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

    /** The ApReq's fields */
    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new ExplicitField(ApReqField.PVNO, Asn1Integer.class),
            new ExplicitField(ApReqField.MSG_TYPE, Asn1Integer.class),
            new ExplicitField(ApReqField.AP_OPTIONS, ApOptions.class),
            new ExplicitField(ApReqField.TICKET, Ticket.class),
            new ExplicitField(ApReqField.AUTHENTICATOR, EncryptedData.class)
    };

    /** The decrypted authenticator. Not used atm*/
    private Authenticator authenticator;

    /**
     * Creates a new instance of a AP-REQ message
     */
    public ApReq() {
        super(KrbMessageType.AP_REQ, fieldInfos);
    }

    /**
     * @return The AP-OPTIONS set
     */
    public ApOptions getApOptions() {
        return getFieldAs(ApReqField.AP_OPTIONS, ApOptions.class);
    }

    /**
     * Stores the AP-OPTIONS in the message
     * @param apOptions The AP-OPTIPNS to set
     */
    public void setApOptions(ApOptions apOptions) {
        setFieldAs(ApReqField.AP_OPTIONS, apOptions);
    }

    /**
     * @return The Ticket
     */
    public Ticket getTicket() {
        return getFieldAs(ApReqField.TICKET, Ticket.class);
    }

    /**
     * Stores the ticket in the message
     * @param ticket The ticket
     */
    public void setTicket(Ticket ticket) {
        setFieldAs(ApReqField.TICKET, ticket);
    }

    /**
     * @return the decrypted Authenticator
     */
    public Authenticator getAuthenticator() {
        return authenticator;
    }

    /**
     * Stores the decrypted Authenticator
     * @param authenticator the decrypted Authenticator
     */
    public void setAuthenticator(Authenticator authenticator) {
        this.authenticator = authenticator;
    }

    /**
     * @return The encrypted Authenticator
     */
    public EncryptedData getEncryptedAuthenticator() {
        return getFieldAs(ApReqField.AUTHENTICATOR, EncryptedData.class);
    }

    /**
     * Stores the encrypted authenticator in the message
     * @param encryptedAuthenticator The encrypted authenticator
     */
    public void setEncryptedAuthenticator(EncryptedData encryptedAuthenticator) {
        setFieldAs(ApReqField.AUTHENTICATOR, encryptedAuthenticator);
    }
}

