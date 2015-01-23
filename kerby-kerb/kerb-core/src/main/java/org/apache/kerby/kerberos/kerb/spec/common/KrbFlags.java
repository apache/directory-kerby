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
package org.apache.kerby.kerberos.kerb.spec.common;

import org.apache.kerby.asn1.type.Asn1BitString;
import org.apache.kerby.kerberos.kerb.spec.KrbEnum;

import java.io.IOException;

/**
 KrbFlags   ::= BIT STRING (SIZE (32..MAX))
 -- minimum number of bits shall be sent,
 -- but no fewer than 32
 */
public class KrbFlags extends Asn1BitString {
    private static final int MAX_SIZE = 32;
    private int flags;

    public KrbFlags() {
        this(0);
    }

    public KrbFlags(int value) {
        super();
        setFlags(value);
    }

    public void setFlags(int flags) {
        this.flags = flags;
        flags2Value();
    }

    public int getFlags() {
        return flags;
    }

    public boolean isFlagSet(int flag) {
        return (flags & (1 << flagPos(flag))) != 0;
    }

    public void setFlag(int flag)  {
        int newFlags = flags | 1 << flagPos(flag);
        setFlags(newFlags);
    }

    public void clearFlag(int flag) {
        int newFlags = flags & ~(1 << flagPos(flag));
        setFlags(newFlags);
    }

    public void clear() {
        setFlags(0);
    }

    public boolean isFlagSet(KrbEnum flag) {
        return isFlagSet(flag.getValue());
    }

    public void setFlag(KrbEnum flag)  {
        setFlag(flag.getValue());
    }

    public void setFlag(KrbEnum flag, boolean isSet)  {
        if (isSet) {
            setFlag(flag.getValue());
        } else {
            clearFlag(flag);
        }
    }

    public void clearFlag(KrbEnum flag) {
        clearFlag(flag.getValue());
    }

    private int flagPos(int flag)  {
        return MAX_SIZE - 1 - flag;
    }

    private void flags2Value() {
        byte[] bytes = new byte[4];
        bytes[0] = (byte) (flags >> 24);
        bytes[1] = (byte) ((flags >> 16) & 0xFF);
        bytes[2] = (byte) ((flags >> 8) & 0xFF);
        bytes[3] = (byte) (flags & 0xFF);

        setValue(bytes);
    }

    @Override
    protected void toValue() throws IOException {
        super.toValue();

        if (getPadding() != 0 || getValue().length != 4) {
            throw new IOException("Bad bitstring decoded as invalid krb flags");
        }

        byte[] valueBytes = getValue();
        flags = ((valueBytes[0] & 0xFF) << 24) | ((valueBytes[1] & 0xFF) << 16) |
                ((valueBytes[2] & 0xFF) << 8) | (0xFF & valueBytes[3]);
    }
}
