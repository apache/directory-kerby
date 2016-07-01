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

import org.apache.kerby.kerberos.kerb.crypto.util.Random;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.MessageProp;
import sun.security.jgss.GSSHeader;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class WrapTokenV1 extends GssTokenV1 {
    public static final int CONFOUNDER_SIZE = 8;

    private boolean privacy;

    private byte[] inData;
    private int inOffset;
    private int inLen;

    private int paddingLen;
    private byte[] confounder;
    private int tokenBodyLen;

    private byte[] bodyData;
    private int bodyOffset;
    private int bodyLen;

    // for reconstruct
    private int rawDataLength;
    private byte[] rawData;
    private int rawDataOffset;


    // Generate wrap token according user data
    public WrapTokenV1(GssContext context,
                       byte[] inMsg,
                       int msgOffset,
                       int msgLength,
                       MessageProp prop) throws GSSException {
        super(TOKEN_WRAP_V1, context);

        paddingLen = getPaddingLength(msgLength);
        confounder = Random.makeBytes(CONFOUNDER_SIZE);
        tokenBodyLen = CONFOUNDER_SIZE + msgLength + paddingLen;

        calcPrivacyInfo(prop, confounder, inMsg, msgOffset, msgLength, paddingLen);

        if (!context.getConfState()) {
            prop.setPrivacy(false);
        }
        privacy = prop.getPrivacy();
        inData = inMsg;
        inOffset = msgOffset;
        inLen = msgLength;
    }

    // Reconstruct a token from token bytes
    public WrapTokenV1(GssContext context, MessageProp prop,
                       byte[] token, int offset, int len) throws GSSException {
        super(TOKEN_WRAP_V1, context, prop, token, offset, len);
        // adjust the offset to the beginning of the body
        bodyData = token;
        bodyOffset = offset + reconHeaderLen;
        bodyLen = len - reconHeaderLen;
        getRawData(prop);
    }

    // Reconstruct a token from token bytes stream
    public WrapTokenV1(GssContext context, MessageProp prop, InputStream is) throws GSSException {
        super(TOKEN_WRAP_V1, context, prop, is);
        byte[] token;
        int len;
        try {
            len = is.available();
            token = new byte[len];
            is.read(token);
        } catch (IOException e) {
            throw new GSSException(GSSException.FAILURE, -1, "Read wrap token V1 error:" + e.getMessage());
        }
        bodyData = token;
        bodyOffset = 0;
        bodyLen = len;
        getRawData(prop);
    }

    private void getRawData(MessageProp prop) throws GSSException {
        privacy = prop.getPrivacy();
        tokenBodyLen = getGssHeader().getMechTokenLength() - getTokenHeaderSize();

        if (bodyLen < tokenBodyLen) {
            throw new GSSException(GSSException.FAILURE, -1, "Insufficient data for Wrap token V1");
        }

        if (privacy) {
            rawData = encryptor.encryptTokenV1(null, bodyData, bodyOffset, tokenBodyLen, 0,
                    encryptor.isArcFourHmac() ? getPlainSequenceBytes() : null, false);
            paddingLen = rawData[rawData.length - 1];
            rawDataOffset = CONFOUNDER_SIZE;
        } else {
            rawData = bodyData;
            paddingLen = bodyData[bodyOffset + tokenBodyLen - 1];
            rawDataOffset = bodyOffset + CONFOUNDER_SIZE;
        }
        rawDataLength = tokenBodyLen - CONFOUNDER_SIZE - paddingLen;

        verifyToken(null, rawData, rawDataOffset - CONFOUNDER_SIZE, tokenBodyLen, 0);
    }

    // Get plain text data from token data bytes
    public byte[] unwrap() throws GSSException {
        byte[] ret = new byte[rawDataLength];
        System.arraycopy(rawData, rawDataOffset, ret, 0, rawDataLength);
        return ret;
    }

    public void unwrap(OutputStream os) throws GSSException {
        try {
            os.write(rawData, rawDataOffset, rawDataLength);
        } catch (IOException e) {
            throw new GSSException(GSSException.FAILURE, -1,
                    "Error in output wrap token v1 data bytes:" + e.getMessage());
        }
    }

    public byte[] wrap() throws GSSException {
        ByteArrayOutputStream os = new ByteArrayOutputStream(getTokenSizeWithoutGssHeader() + inLen + 64);
        wrap(os);
        return os.toByteArray();
    }

    public void wrap(OutputStream os) throws GSSException {
        try {
            encodeHeader(os);
            if (privacy) {
                byte[] enc = encryptor.encryptTokenV1(confounder, inData, inOffset, inLen, paddingLen,
                        encryptor.isArcFourHmac() ? getPlainSequenceBytes() : null, true);
                os.write(enc);
            } else {
                os.write(confounder);
                os.write(inData, inOffset, inLen);
                os.write(getPaddingBytes(paddingLen));
            }
        } catch (IOException e) {
            throw new GSSException(GSSException.FAILURE, -1, "Error in output wrap token v1 bytes:" + e.getMessage());
        }
    }

    protected int getTokenSizeWithoutGssHeader() {
        return tokenBodyLen + getTokenHeaderSize();
    }

    private int getPaddingLength(int dataLen) {
        if (encryptor.isArcFourHmac()) {
            return 1;
        }
        return 8 - (dataLen % 8);
    }

    private byte[] getPaddingBytes(int len) {
        byte[] ret = new byte[len];
        int i = 0;
        while (i < len) {
            ret[i++] = (byte) len;
        }
        return ret;
    }

    public static int getMsgSizeLimit(int qop, boolean confReq, int maxTokSize, GssEncryptor encryptor)
            throws GSSException {
        return GSSHeader.getMaxMechTokenSize(objId, maxTokSize)
                - encryptor.getCheckSumSize()
                - TOKEN_HEADER_COMM_SIZE - TOKEN_HEADER_SEQ_SIZE
                - CONFOUNDER_SIZE - 8;
    }
}
