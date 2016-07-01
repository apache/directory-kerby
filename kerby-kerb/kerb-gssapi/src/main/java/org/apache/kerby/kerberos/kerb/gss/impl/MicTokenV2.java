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

import java.io.IOException;
import java.io.OutputStream;

public class MicTokenV2 extends GssTokenV2 {
    private MessageProp prop;

    // This is called to construct MicToken from user input
    MicTokenV2(GssContext context,
             byte[] inMsg,
             int msgOffset,
             int msgLength,
             MessageProp messageProp) throws GSSException {
        super(TOKEN_MIC_V2, context);

        prop = messageProp;
        if (prop == null) {
            prop = new MessageProp(0, false);
        }

        generateCheckSum(prop, inMsg, msgOffset, msgLength);
    }

    // This is called to construct MicToken from MicToken bytes
    MicTokenV2(GssContext context,
             MessageProp messageProp,
             byte[] inToken,
             int tokenOffset,
             int tokenLength) throws GSSException {
        super(TOKEN_MIC_V2, context, messageProp, inToken, tokenOffset, tokenLength);
        this.prop = messageProp;
    }

    public int getMic(byte[] outToken, int offset) {
        encodeHeader(outToken, offset);
        System.arraycopy(checkSum, 0, outToken, TOKEN_HEADER_SIZE + offset, checkSum.length);
        return TOKEN_HEADER_SIZE + checkSum.length;
    }

    /**
     * Get bytes for this Mic token
     * @return
     */
    public byte[] getMic() {
        byte[] ret = new byte[TOKEN_HEADER_SIZE + checkSum.length];
        getMic(ret, 0);
        return ret;
    }

    public void getMic(OutputStream os) throws GSSException {
        try {
            encodeHeader(os);
            os.write(checkSum);
        } catch (IOException e) {
            throw new GSSException(GSSException.FAILURE, -1, "Output MicTokenV2 error:" + e.getMessage());
        }
    }

    /**
     * Calculate the checksum for inMsg and compare with it with this token, throw GssException if not equal
     * @param inMsg
     * @param msgOffset
     * @param msgLen
     * @throws GSSException
     */
    public void verify(byte[] inMsg, int msgOffset, int msgLen) throws GSSException {
        if (!verifyCheckSum(inMsg, msgOffset, msgLen)) {
            throw new GSSException(GSSException.BAD_MIC, -1, "Corrupt MIC token");
        }
    }
}
