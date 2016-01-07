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
import org.apache.kerby.kerberos.kerb.KrbConstant;
import org.apache.kerby.kerberos.kerb.type.KrbAppSequenceType;

/**
 * A base class for every possible Kerberos messages :
 * 
 * <ul>
 *   <li>AS-REQ    : [APPLICATION 10]</li>
 *   <li>AS-REP    : [APPLICATION 11]</li>
 *   <li>TGS-REQ   : [APPLICATION 12]</li>
 *   <li>TGS-REP   : [APPLICATION 13]</li>
 *   <li>AP-REQ    : [APPLICATION 14]</li>
 *   <li>AP-REP    : [APPLICATION 15]</li>
 *   <li>KRB-SAFE  : [APPLICATION 20]</li>
 *   <li>KRB-PRIV  : [APPLICATION 21]</li>
 *   <li>KRB-CRED  : [APPLICATION 22]</li>
 *   <li>KRB_ERROR : [APPLICATION 30]</li>
 * </ul>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class KrbMessage extends KrbAppSequenceType {
    /**
     * The possible fields. We declare the PVNO and MSG_TYPE fields, which are already
     * declared in every inherited classes, because we need to have access to them
     * in this class to implement the common setters and getters. We can't reuse them 
     * in the inherited classes either...
     */
    protected enum KrbMessageField implements EnumType {
        PVNO,
        MSG_TYPE;

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

    /** The PVNO fields. Default to KRB_V5 */
    private final int pvno = KrbConstant.KRB_V5;

    /**
     * Creates a new instance of a KrbMessage. It's not possible to invoque this
     * constructor directly.
     * 
     * @param msgType The Kerberos messag etype
     * @param fieldInfos The fields to use
     */
    protected KrbMessage(KrbMessageType msgType, Asn1FieldInfo[] fieldInfos) {
        super(msgType.getValue(), fieldInfos);
        setPvno(pvno);
        setMsgType(msgType);
    }

    /**
     * @return The PVNO field
     */
    public int getPvno() {
        return pvno;
    }

    /**
     * Sets the PVNO field
     * @param pvno The PVNO to set
     */
    protected void setPvno(int pvno) {
        setFieldAsInt(KrbMessageField.PVNO, pvno);
    }

    /**
     * @return The Kerberos message type field
     */
    public KrbMessageType getMsgType() {
        Integer value = getFieldAsInteger(KrbMessageField.MSG_TYPE);
        
        return KrbMessageType.fromValue(value);
    }

    /**
     * Sets the Kerberos Message Type field
     * @param msgType The Kerberos Message Type to set
     */
    public void setMsgType(KrbMessageType msgType) {
        setFieldAsInt(KrbMessageField.MSG_TYPE, msgType.getValue());
    }
}
