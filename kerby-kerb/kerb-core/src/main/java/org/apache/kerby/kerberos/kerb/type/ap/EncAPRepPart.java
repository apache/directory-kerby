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
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.KrbAppSequenceType;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;

/**
 * The EncAPRepPart, as defined in RFC 4120, section 5.5.2
 * <pre>
 * EncAPRepPart    ::= [APPLICATION 27] SEQUENCE {
 *         ctime           [0] KerberosTime,
 *         cusec           [1] Microseconds,
 *         subkey          [2] EncryptionKey OPTIONAL,
 *         seq-number      [3] UInt32 OPTIONAL
 * }
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class EncAPRepPart extends KrbAppSequenceType {
    /* The APPLICATION tag */
    public static final int TAG = 27;

    /**
     * The possible fields
     */
    protected enum EncAPRepPartField implements EnumType {
        CTIME,
        CUSEC,
        SUBKEY,
        SEQ_NUMBER;

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

    /** The EncAPRepPart's fields */
    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new ExplicitField(EncAPRepPartField.CTIME, KerberosTime.class),
            new ExplicitField(EncAPRepPartField.CUSEC, Asn1Integer.class),
            new ExplicitField(EncAPRepPartField.SUBKEY, EncryptionKey.class),
            new ExplicitField(EncAPRepPartField.SEQ_NUMBER, Asn1Integer.class)
    };

    /**
     * Creates an instance of ApRep
     */
    public EncAPRepPart() {
        super(TAG, fieldInfos);
    }

    
    /**
     * @return The current time on client host
     */
    public KerberosTime getCtime() {
        return getFieldAsTime(EncAPRepPartField.CTIME);
    }

    /**
     * Set the client time
     * @param ctime The client time
     */
    public void setCtime(KerberosTime ctime) {
        setFieldAs(EncAPRepPartField.CTIME, ctime);
    }

    /**
     * @return the microsecond part on the client's timestamp
     */
    public int getCusec() {
        return getFieldAsInt(EncAPRepPartField.CUSEC);
    }

    /**
     * Set the client's microsecond
     * @param cusec the client's microsecond
     */
    public void setCusec(int cusec) {
        setFieldAsInt(EncAPRepPartField.CUSEC, cusec);
    }

    /**
     * @return The encryption key
     */
    public EncryptionKey getSubkey() {
        return getFieldAs(EncAPRepPartField.SUBKEY, EncryptionKey.class);
    }

    /**
     * Set the encryption key
     * @param subkey the encryption key
     */
    public void setSubkey(EncryptionKey subkey) {
        setFieldAs(EncAPRepPartField.SUBKEY, subkey);
    }

    /**
     * @return The Sequence Number
     */
    public int getSeqNumber() {
        return getFieldAsInt(EncAPRepPartField.SEQ_NUMBER);
    }

    /**
     * Set the Sequence Number
     * @param seqNumber the Sequence Number
     */
    public void setSeqNumber(Integer seqNumber) {
        setFieldAsInt(EncAPRepPartField.SEQ_NUMBER, seqNumber);
    }
}
