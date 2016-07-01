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
package org.apache.kerby.kerberos.kerb.gss.impl;

import org.ietf.jgss.GSSException;
import org.ietf.jgss.MessageProp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class MicTokenV1 extends GssTokenV1 {
    public MicTokenV1(GssContext context,
                       byte[] inMsg,
                       int msgOffset,
                       int msgLength,
                       MessageProp messageProp) throws GSSException {
        super(TOKEN_MIC_V1, context);
        calcPrivacyInfo(messageProp, null, inMsg, msgOffset, msgLength, 0);
    }

    // This is called to construct MicToken from MicToken bytes
    MicTokenV1(GssContext context,
               MessageProp messageProp,
               byte[] inToken,
               int tokenOffset,
               int tokenLength) throws GSSException {
        super(TOKEN_MIC_V1, context, messageProp, inToken, tokenOffset, tokenLength);
    }

    public int getMic(byte[] outToken, int offset) throws GSSException, IOException {
        byte[] data = getMic();
        System.arraycopy(data, 0, outToken, offset, data.length);
        return data.length;
    }

    /**
     * Get bytes for this Mic token
     * @return
     */
    public byte[] getMic() throws GSSException {
        ByteArrayOutputStream os = new ByteArrayOutputStream(64);
        getMic(os);
        return os.toByteArray();
    }

    public void getMic(OutputStream os) throws GSSException {
        try {
            encodeHeader(os);
        } catch (IOException e) {
            throw new GSSException(GSSException.FAILURE, -1, "Error in output MicTokenV1 bytes:" + e.getMessage());
        }
    }

    public void verify(InputStream is) throws GSSException {
        byte[] data;
        try {
            data = new byte[is.available()];
            is.read(data);
        } catch (IOException e) {
            throw new GSSException(GSSException.FAILURE, -1,
                    "Read plain data for MicTokenV1 error:" + e.getMessage());
        }
        verify(data, 0, data.length);
    }

    public void verify(byte[] data, int offset, int len) throws GSSException {
        verifyToken(null, data, offset, len, 0);
    }

    protected int getTokenSizeWithoutGssHeader() {
        return getTokenHeaderSize();
    }
}
