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
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;

/**
 PA-ENC-TS-ENC           ::= SEQUENCE {
    patimestamp     [0] KerberosTime -- client's time --,
    pausec          [1] Microseconds OPTIONAL
 }
 */
public class PaEncTsEnc extends KrbSequenceType {
    protected enum PaEncTsEncField implements EnumType {
        PATIMESTAMP,
        PAUSEC;

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
            new ExplicitField(PaEncTsEncField.PATIMESTAMP, KerberosTime.class),
            new ExplicitField(PaEncTsEncField.PAUSEC, Asn1Integer.class)
    };

    public PaEncTsEnc() {
        super(fieldInfos);
    }

    public KerberosTime getPaTimestamp() {
        return getFieldAsTime(PaEncTsEncField.PATIMESTAMP);
    }

    public void setPaTimestamp(KerberosTime paTimestamp) {
        setFieldAs(PaEncTsEncField.PATIMESTAMP, paTimestamp);
    }

    public int getPaUsec() {
        return getFieldAsInt(PaEncTsEncField.PAUSEC);
    }

    public void setPaUsec(int paUsec) {
        setFieldAsInt(PaEncTsEncField.PAUSEC, paUsec);
    }

    public KerberosTime getAllTime() {
        KerberosTime paTimestamp = getPaTimestamp();
        return paTimestamp.extend(getPaUsec() / 1000);
    }
}
