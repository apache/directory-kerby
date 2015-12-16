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
package org.apache.kerby.kerberos.kerb.type;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.type.Asn1TaggingSequence;

/**
 * This is for application specific sequence tagged with a number.
 */
public abstract class KrbAppSequenceType extends Asn1TaggingSequence {
    public KrbAppSequenceType(int tagNo, Asn1FieldInfo[] fieldInfos) {
        super(tagNo, fieldInfos, true, false); // Kerberos favors explicit
    }

    protected int getFieldAsInt(EnumType index) {
        Integer value = getFieldAsInteger(index);
        if (value != null) {
            return value.intValue();
        }
        return -1;
    }

    protected void setFieldAsString(EnumType index, String value) {
        setFieldAs(index, new KerberosString(value));
    }

    protected KerberosTime getFieldAsTime(EnumType index) {
        return getFieldAs(index, KerberosTime.class);
    }

    protected void setFieldAsTime(EnumType index, long value) {
        setFieldAs(index, new KerberosTime(value));
    }

    protected void setField(EnumType index, EnumType krbEnum) {
        setFieldAsInt(index, krbEnum.getValue());
    }
}
