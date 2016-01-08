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

/**
 * The AP-REP message, as defined in RFC 4120 :
 * 
 * <pre>
 * AP-REP          ::= [APPLICATION 15] SEQUENCE {
 *         pvno            [0] INTEGER (5),
 *         msg-type        [1] INTEGER (15),
 *         enc-part        [2] EncryptedData -- EncAPRepPart
 * }
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ApRep extends KrbMessage {
    /**
     * The possible fields
     */
    protected enum ApRepField implements EnumType {
        PVNO,
        MSG_TYPE,
        ENC_PART;

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

    /** The ApRep's fields */
    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new ExplicitField(ApRepField.PVNO, Asn1Integer.class),
            new ExplicitField(ApRepField.MSG_TYPE, Asn1Integer.class),
            new ExplicitField(ApRepField.ENC_PART, EncryptedData.class)
    };

    /** The decrypted part of this message (Not used atm) */
    private EncAPRepPart encRepPart;

    /**
     * Creates an instance of ApRep
     */
    public ApRep() {
        super(KrbMessageType.AP_REP, fieldInfos);
    }


    /**
     * @return The decrypted EncRepPart 
     */
    public EncAPRepPart getEncRepPart() {
        return encRepPart;
    }

    /**
     * Set the decrypted EncRepPart into the message 
     * 
     * @param encRepPart The decrypted EncRepPart to store
     */
    public void setEncRepPart(EncAPRepPart encRepPart) {
        this.encRepPart = encRepPart;
    }

    /**
     * @return The encrypted part 
     */
    public EncryptedData getEncryptedEncPart() {
        return getFieldAs(ApRepField.ENC_PART, EncryptedData.class);
    }

    /**
     * Set the encrypted part into the message 
     * 
     * @param encPart The encrypted part to store
     */
    public void setEncryptedEncPart(EncryptedData encPart) {
        setFieldAs(ApRepField.ENC_PART, encPart);
    }
}
