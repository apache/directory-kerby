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
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.kerberos.kerb.type.base.HostAddress;

/**
  EncKrbPrivPart ::=   [APPLICATION 28] SEQUENCE {
                user-data[0]              OCTET STRING,
                timestamp[1]              KerberosTime OPTIONAL,
                usec[2]                   INTEGER OPTIONAL,
                seq-number[3]             INTEGER OPTIONAL,
                s-address[4]              HostAddress, -- sender's addr
                r-address[5]              HostAddress OPTIONAL
                                                      -- recip's addr
   }
 */
public class EncKrbPrivPart extends KrbAppSequenceType {
     public static final int TAG = 28;

    protected enum EncKrbPrivPartField implements EnumType {
        USER_DATA,
        TIMESTAMP,
        USEC,
        SEQ_NUMBER,
        S_ADDRESS,
        R_ADDRESS;

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
            new ExplicitField(EncKrbPrivPart.EncKrbPrivPartField.USER_DATA, Asn1OctetString.class),
            new ExplicitField(EncKrbPrivPart.EncKrbPrivPartField.TIMESTAMP, KerberosTime.class),
            new ExplicitField(EncKrbPrivPart.EncKrbPrivPartField.USEC, Asn1Integer.class),
            new ExplicitField(EncKrbPrivPart.EncKrbPrivPartField.SEQ_NUMBER, Asn1Integer.class),
            new ExplicitField(EncKrbPrivPart.EncKrbPrivPartField.S_ADDRESS, HostAddress.class),
            new ExplicitField(EncKrbPrivPart.EncKrbPrivPartField.R_ADDRESS, HostAddress.class)
    };

    public EncKrbPrivPart() {
        super(TAG, fieldInfos);
    }

    public byte[] getUserData() {
        return getFieldAsOctets(EncKrbPrivPart.EncKrbPrivPartField.USER_DATA);
    }

    public void setUserData(byte[] userData) {
        setFieldAsOctets(EncKrbPrivPart.EncKrbPrivPartField.USER_DATA, userData);
    }

    public KerberosTime getTimeStamp() {
        return getFieldAsTime(EncKrbPrivPart.EncKrbPrivPartField.TIMESTAMP);
    }

    public void setTimeStamp(KerberosTime timeStamp) {
        setFieldAs(EncKrbPrivPart.EncKrbPrivPartField.TIMESTAMP, timeStamp);
    }

    public int getUsec() {
        return getFieldAsInt(EncKrbPrivPart.EncKrbPrivPartField.USEC);
    }

    public void setUsec(int usec) {
        setFieldAsInt(EncKrbPrivPart.EncKrbPrivPartField.USEC, usec);
    }

    public int getSeqNumber() {
        return getFieldAsInt(EncKrbPrivPart.EncKrbPrivPartField.SEQ_NUMBER);
    }

    public void setSeqNumber(int seqNumber) {
        setFieldAsInt(EncKrbPrivPart.EncKrbPrivPartField.SEQ_NUMBER, seqNumber);
    }

    public HostAddress getSAddress() {
        return getFieldAs(EncKrbPrivPart.EncKrbPrivPartField.S_ADDRESS, HostAddress.class);
    }

    public void setSAddress(HostAddress hostAddress) {
        setFieldAs(EncKrbPrivPart.EncKrbPrivPartField.S_ADDRESS, hostAddress);
    }

    public HostAddress getRAddress() {
        return getFieldAs(EncKrbPrivPart.EncKrbPrivPartField.R_ADDRESS, HostAddress.class);
    }

    public void setRAddress(HostAddress hostAddress) {
        setFieldAs(EncKrbPrivPart.EncKrbPrivPartField.R_ADDRESS, hostAddress);
    }
}
