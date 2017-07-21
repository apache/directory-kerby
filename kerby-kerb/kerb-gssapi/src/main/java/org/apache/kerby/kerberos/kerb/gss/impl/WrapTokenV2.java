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
import java.io.InputStream;
import java.io.OutputStream;


public class WrapTokenV2 extends GssTokenV2 {
    private MessageProp prop;

    // Generate a token from user input data
    WrapTokenV2(GssContext context,
              byte[] data,
              int dataOffset,
              int dataLength,
              MessageProp messageProp) throws GSSException {
        super(TOKEN_WRAP_V2, context);

        prop = messageProp;

        if (prop.getQOP() != 0) {
            prop.setQOP(0);
        }

        if (!context.getConfState()) {
            prop.setPrivacy(false);
        }

        generateCheckSum(prop, data, dataOffset, dataLength);

        if (prop.getPrivacy()) {
            byte[] toProcess = new byte[dataLength + TOKEN_HEADER_SIZE];
            System.arraycopy(data, dataOffset, toProcess, 0, dataLength);
            encodeHeader(toProcess, dataLength);

            tokenData = encryptor.encryptData(toProcess, getKeyUsage());
        } else {
            tokenData = data; // keep it for now
        }
    }

    /**
     * Get bytes of the token
     * @return
     */
    public byte[] wrap() {
        int dataSize = tokenData.length;
        int ckSize = checkSum == null ? 0 : checkSum.length;
        byte[] ret = new byte[TOKEN_HEADER_SIZE + dataSize + ckSize];
        encodeHeader(ret, 0);
        System.arraycopy(tokenData, 0, ret, TOKEN_HEADER_SIZE, dataSize);
        if (ckSize > 0) {
            System.arraycopy(checkSum, 0, ret, TOKEN_HEADER_SIZE + dataSize, ckSize);
        }
        return ret;
    }

    public void wrap(OutputStream os) throws GSSException {
        try {
            encodeHeader(os);
            os.write(tokenData);
            int ckSize = checkSum == null ? 0 : checkSum.length;
            if (ckSize > 0) {
                os.write(checkSum);
            }
        } catch (IOException e) {
            throw new GSSException(GSSException.FAILURE, -1, "Output token error:" + e.getMessage());
        }
    }

    // Reconstruct a token from token bytes
    public WrapTokenV2(GssContext context, MessageProp prop, byte[] token, int offset, int len) throws GSSException {
        super(TOKEN_WRAP_V2, context, prop, token, offset, len);
        this.prop = prop;
    }

    // Reconstruct a token from token bytes stream
    public WrapTokenV2(GssContext context, MessageProp prop, InputStream is) throws GSSException {
        super(TOKEN_WRAP_V2, context, prop, is);
        this.prop = prop;
    }

    /**
     * Get plain text data from token bytes
     * @param outBuffer
     * @param offset
     * @return plain text contained in the wrap token
     * @throws GSSException
     */
    public byte[] unwrap(byte[] outBuffer, int offset) throws GSSException {
        int lenToCopy;
        if (prop.getPrivacy()) {
            byte[] plainText = encryptor.decryptData(tokenData, getKeyUsage());
            lenToCopy = plainText.length - TOKEN_HEADER_SIZE;
            if (outBuffer == null) {
                outBuffer = new byte[lenToCopy];
                offset = 0;
            }
            System.arraycopy(plainText, 0, outBuffer, offset, lenToCopy);
        } else {
            lenToCopy = tokenData.length - encryptor.getCheckSumSize();
            if (outBuffer == null) {
                outBuffer = new byte[lenToCopy];
                offset = 0;
            }
            System.arraycopy(tokenData, 0, outBuffer, offset, lenToCopy);

            if (!verifyCheckSum(outBuffer, offset, lenToCopy)) {
                throw new GSSException(GSSException.BAD_MIC, -1, "Corrupt token checksum");
            }
        }
        return outBuffer;
    }

    public byte[] unwrap() throws GSSException {
        return unwrap(null, 0);
    }

    public void unwrap(OutputStream os) throws GSSException {
        byte[] data = unwrap();
        try {
            os.write(data);
        } catch (IOException e) {
            throw new GSSException(GSSException.FAILURE, -1, "Output token error:" + e.getMessage());
        }
    }

    public static int getMsgSizeLimit(int qop, boolean confReq, int maxTokSize, GssEncryptor encryptor)
            throws GSSException {
        if (confReq) {
            return maxTokSize - encryptor.getCheckSumSize() - TOKEN_HEADER_SIZE * 2 - CONFOUNDER_SIZE;
        } else {
            return maxTokSize - encryptor.getCheckSumSize() - TOKEN_HEADER_SIZE;
        }
    }
}
