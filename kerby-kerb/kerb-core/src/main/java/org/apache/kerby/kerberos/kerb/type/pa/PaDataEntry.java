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
package org.apache.kerby.kerberos.kerb.type.pa;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;

/**
 * The PaData component as defined in RFC 4120 :
 * 
 * <pre>
 * PA-DATA         ::= SEQUENCE {
 *         -- NOTE: first tag is [1], not [0]
 *         padata-type     [1] Int32,
 *         padata-value    [2] OCTET STRING -- might be encoded AP-REQ
 * }
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PaDataEntry extends KrbSequenceType {
    /**
     * The possible fields
     */
    protected enum PaDataEntryField implements EnumType {
        PADATA_TYPE,
        PADATA_VALUE;

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

    /** The PaDataEntrey's fields */
    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new ExplicitField(PaDataEntryField.PADATA_TYPE, 1, Asn1Integer.class),
            new ExplicitField(PaDataEntryField.PADATA_VALUE, 2, Asn1OctetString.class)
    };

    /**
     * Creates an empty PaDataEntry instance
     */
    public PaDataEntry() {
        super(fieldInfos);
    }

    /**
     * Creates a PaDataEntry instance with a type and a value
     * 
     * @param type the {@link PaDataType} to use
     * @param paData the data to store
     */
    public PaDataEntry(PaDataType type, byte[] paData) {
        super(fieldInfos);
        setPaDataType(type);
        setPaDataValue(paData);
    }

    /**
     * @return The {@link PaDataType} for this instance
     */
    public PaDataType getPaDataType() {
        Integer value = getFieldAsInteger(PaDataEntryField.PADATA_TYPE);
        
        return PaDataType.fromValue(value);
    }

    /**
     * Sets a {@link PaDataType} in this instance
     * 
     * @param paDataType The {@link PaDataType} type to store
     */
    public void setPaDataType(PaDataType paDataType) {
        setFieldAsInt(PaDataEntryField.PADATA_TYPE, paDataType.getValue());
    }

    /**
     * @return The data stored in this instance
     */
    public byte[] getPaDataValue() {
        return getFieldAsOctets(PaDataEntryField.PADATA_VALUE);
    }

    /**
     * Sets some data in this instance
     *  
     * @param paDataValue The data to store
     */
    public void setPaDataValue(byte[] paDataValue) {
        setFieldAsOctets(PaDataEntryField.PADATA_VALUE, paDataValue);
    }
}
