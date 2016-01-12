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
package org.apache.kerby.xdr.type;

import org.apache.kerby.xdr.XdrDataType;

import java.io.IOException;
<<<<<<< 5f54df40ccea4ed12465e44ff1e40cba860d6424
import java.util.Arrays;
=======
>>>>>>> finish xdr-boolean encode

/**
 * Xdr Boolean type from RFC 4506
 * Boolean type has the same representation as signed integers.
 */
public class XdrBoolean extends XdrSimple<Boolean> {
    private static final byte[] TRUE_BYTE = new byte[] {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01};
    private static final byte[] FALSE_BYTE = new byte[] {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};

    public static final XdrBoolean TRUE = new XdrBoolean(true);
    public static final XdrBoolean FALSE = new XdrBoolean(false);

    /**
     * Default constructor, generally for decoding as a container
     */
    public XdrBoolean() {
        this(null);
    }

    /**
     * Constructor with a value, generally for encoding of the value
     * @param value The boolean value
     */
    public XdrBoolean(Boolean value) {
        super(XdrDataType.BOOLEAN, value);
    }

    /**
     * The length of a signed integer is 4.
     * @return Length of a boolean type.
     */
    @Override
    protected int encodingHeaderLength() throws IOException {
        return 0;
    }

    @Override
    protected int encodingBodyLength() {
<<<<<<< 5f54df40ccea4ed12465e44ff1e40cba860d6424
        return 4;
=======
        return 4;//as signed integer??
    }

    /*
    @Override
    protected  byte[] headToByte() {
        return null;
>>>>>>> finish xdr-boolean encode
    }
    */

    /**
     * Encode boolean type to bytes.
     */
    @Override
    protected void toBytes() {
        setBytes(getValue() ? TRUE_BYTE : FALSE_BYTE);
    }

    /**
     * Decode bytes to boolean value.
     * @throws IOException Wrong bytes for boolean.
     */
    @Override
    protected void toValue() throws IOException {
        byte[] bytes = getBytes();
        if (Arrays.equals(bytes, TRUE_BYTE)) {
            setValue(true);
        }
        else if (Arrays.equals(bytes, FALSE_BYTE)) {
            setValue(false);
        }
        else {
            throw new IOException("Fail to decode boolean type: " + bytes.toString());
        }
    }
}
