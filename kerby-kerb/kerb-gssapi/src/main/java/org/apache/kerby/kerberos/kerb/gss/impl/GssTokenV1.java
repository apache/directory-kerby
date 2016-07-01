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
import sun.security.jgss.GSSHeader;
import sun.security.util.ObjectIdentifier;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;

/**
 * This class implements the token formats defined in RFC 1964 and its updates
 *
 * The GSS Wrap token has the following format:
 *
 * Byte no          Name           Description
 * 0..1           TOK_ID          0201
 *
 * 2..3           SGN_ALG         Checksum algorithm indicator.
 *                                00 00 DES MAC MD5
 *                                01 00 MD2.5
 *                                02 00 DES MAC
 *                                04 00 HMAC SHA1 DES3-KD
 *                                11 00 RC4-HMAC used by Microsoft Windows, RFC 4757
 * 4..5           SEAL_ALG        ff ff none
 *                                00 00 DES
 *                                02 00 DES3-KD
 *                                10 00 RC4-HMAC
 * 6..7           Filler          FF FF
 * 8..15          SND_SEQ         Encrypted sequence number field.
 * 16..23         SNG_CKSUM       Checksum of plaintext padded data,
 *                                calculated according to algorithm
 *                                specified in SGN_ALG field.
 * 24..           Data            Encrypted or plaintext padded data
 *
 *
 *
 * Use of the GSS MIC token has the following format:

 * Byte no          Name           Description
 * 0..1           TOK_ID          0101
 * 2..3           SGN_ALG         Integrity algorithm indicator.
 * 4..7           Filler          Contains ff ff ff ff
 * 8..15          SND_SEQ         Sequence number field.
 * 16..23         SGN_CKSUM       Checksum of "to-be-signed data",
 *                                calculated according to algorithm
 *                                specified in SGN_ALG field.
 *
 */
abstract class GssTokenV1 extends GssTokenBase {
    // SGN ALG
    public static final int SGN_ALG_DES_MAC_MD5 = 0;
    public static final int SGN_ALG_MD25 = 0x0100;
    public static final int SGN_ALG_DES_MAC = 0x0200;
    public static final int SGN_ALG_HMAC_SHA1_DES3_KD = 0x0400;
    public static final int SGN_ALG_RC4_HMAC = 0x1100;

    // SEAL ALG
    public static final int SEAL_ALG_NONE = 0xFFFF;
    public static final int SEAL_ALG_DES = 0x0;  // "DES/CBC/NoPadding"
    public static final int SEAL_ALG_DES3_KD = 0x0200;
    public static final int SEAL_ALG_RC4_HMAC = 0x1000;

    public static final int KG_USAGE_SEAL = 22;
    public static final int KG_USAGE_SIGN = 23;
    public static final int KG_USAGE_SEQ = 24;
    public static final int KG_USAGE_MS_SIGN = 15;

    private boolean isInitiator;
    private boolean confState;
    private int sequenceNumber;

    protected GssEncryptor encryptor;

    private GSSHeader gssHeader;

    public static final int TOKEN_HEADER_COMM_SIZE = 8;
    public static final int TOKEN_HEADER_SEQ_SIZE = 8;

    // Token commHeader data
    private int tokenType;
    private byte[] commHeader = new byte[TOKEN_HEADER_COMM_SIZE];
    private int sgnAlg;
    private int sealAlg;

    private byte[] plainSequenceBytes;
    private byte[] encryptedSequenceNumber = new byte[TOKEN_HEADER_SEQ_SIZE];
    private byte[] checkSum;
    private int checkSumSize;

    protected int reconHeaderLen; // only used for certain reason

    public static ObjectIdentifier objId;

    static {
        try {
            objId = new ObjectIdentifier("1.2.840.113554.1.2.2");
        } catch (IOException ioe) { // NOPMD
        }
    }

    protected int getTokenHeaderSize() {
        return TOKEN_HEADER_COMM_SIZE + TOKEN_HEADER_SEQ_SIZE + checkSumSize;
    }

    protected byte[] getPlainSequenceBytes() {
        byte[] ret = new byte[4];
        ret[0] = plainSequenceBytes[0];
        ret[1] = plainSequenceBytes[1];
        ret[2] = plainSequenceBytes[2];
        ret[3] = plainSequenceBytes[3];
        return ret;
    }

    // Generate a new token
    GssTokenV1(int tokenType, GssContext context) throws GSSException {
        initialize(tokenType, context, false);
        createTokenHeader();
    }

    // Reconstruct a token
    GssTokenV1(int tokenType, GssContext context, MessageProp prop,
               byte[] token, int offset, int size) throws GSSException {
        int proxLen = size > 64 ? 64 : size;
        InputStream is = new ByteArrayInputStream(token, offset, proxLen);
        reconstructInitializaion(tokenType, context, prop, is);
        reconHeaderLen = gssHeader.getLength() + getTokenHeaderSize();
    }

    // Reconstruct a token
    GssTokenV1(int tokenType, GssContext context, MessageProp prop, InputStream is) throws GSSException {
        reconstructInitializaion(tokenType, context, prop, is);
    }

    private void reconstructInitializaion(int tokenType, GssContext context, MessageProp prop, InputStream is)
            throws GSSException {
        initialize(tokenType, context, true);
        if (!confState) {
            prop.setPrivacy(false);
        }

        try {
            gssHeader = new GSSHeader(is);
        } catch (IOException e) {
            throw new GSSException(GSSException.DEFECTIVE_TOKEN, -1, "Invalid token:" + e.getMessage());
        }

        if (!gssHeader.getOid().equals((Object) objId)) {
            throw new GSSException(GSSException.DEFECTIVE_TOKEN, -1, "Invalid token OID");
        }

        reconstructTokenHeader(is, prop);
    }

    private void initialize(int tokenType,
                            GssContext context,
                            boolean reconstruct) throws GSSException {
        this.tokenType = tokenType;
        this.isInitiator = context.isInitiator();
        this.confState = context.getConfState();
        this.encryptor = context.getGssEncryptor();
        this.checkSumSize = encryptor.getCheckSumSize();
        if (!reconstruct) {
            this.sequenceNumber = context.incMySequenceNumber();
        } else {
            checkSum = new byte[checkSumSize];
        }
    }

    protected void calcPrivacyInfo(MessageProp prop, byte[] confounder, byte[] data,
                                   int dataOffset, int dataLength, int paddingLen) throws GSSException {
        prop.setQOP(0);
        if (!confState) {
            prop.setPrivacy(false);
        }

        checkSum = calcCheckSum(confounder, commHeader, data, dataOffset, dataLength, paddingLen);
        encryptSequenceNumber();
    }

    protected void verifyToken(byte[] confounder, byte[] data, int dataOffset, int dataLength, int paddingLen)
            throws GSSException {
        byte[] sum = calcCheckSum(confounder, commHeader, data, dataOffset, dataLength, paddingLen);
        if (!MessageDigest.isEqual(checkSum, sum)) {
            throw new GSSException(GSSException.BAD_MIC, -1,
                    "Corrupt token checksum for " + (tokenType == TOKEN_MIC_V1 ? "Mic" : "Wrap") + "TokenV1");
        }
    }

    private byte[] calcCheckSum(byte[] confounder, byte[] header, byte[] data,
                                int dataOffset, int dataLength, int paddingLen) throws GSSException {
        return encryptor.calculateCheckSum(confounder, header, data, dataOffset, dataLength, paddingLen,
                tokenType == TOKEN_MIC_V1);
    }

    private void encryptSequenceNumber() throws GSSException {
        plainSequenceBytes = new byte[8];
        if (encryptor.isArcFourHmac()) {
            writeBigEndian(plainSequenceBytes, 0, sequenceNumber);
        } else {
            plainSequenceBytes[0] = (byte) sequenceNumber;
            plainSequenceBytes[1] = (byte) (sequenceNumber >>> 8);
            plainSequenceBytes[2] = (byte) (sequenceNumber >>> 16);
            plainSequenceBytes[3] = (byte) (sequenceNumber >>> 24);
        }

        // Hex 0 - sender is the context initiator, Hex FF - sender is the context acceptor
        if (!isInitiator) {
            plainSequenceBytes[4] = (byte) 0xFF;
            plainSequenceBytes[5] = (byte) 0xFF;
            plainSequenceBytes[6] = (byte) 0xFF;
            plainSequenceBytes[7] = (byte) 0xFF;
        }

        encryptedSequenceNumber = encryptor.encryptSequenceNumber(plainSequenceBytes, checkSum, true);
    }

    public void encodeHeader(OutputStream os) throws GSSException, IOException {
        // | GSSHeader | TokenHeader |
        GSSHeader gssHeader = new GSSHeader(objId, getTokenSizeWithoutGssHeader());
        gssHeader.encode(os);
        os.write(commHeader);
        os.write(encryptedSequenceNumber);
        os.write(checkSum);
    }

    private void createTokenHeader() {
        commHeader[0] = (byte) (tokenType >>> 8);
        commHeader[1] = (byte) tokenType;

        sgnAlg = encryptor.getSgnAlg();
        commHeader[2] = (byte) (sgnAlg >>> 8);
        commHeader[3] = (byte) sgnAlg;

        if (tokenType == TOKEN_WRAP_V1) {
            sealAlg = encryptor.getSealAlg();
            commHeader[4] = (byte) (sealAlg >>> 8);
            commHeader[5] = (byte) sealAlg;
        } else {
            commHeader[4] = (byte) 0xFF;
            commHeader[5] = (byte) 0xFF;
        }

        commHeader[6] = (byte) 0xFF;
        commHeader[7] = (byte) 0xFF;
    }

    // Re-construct token commHeader
    private void reconstructTokenHeader(InputStream is, MessageProp prop) throws GSSException {
        try {
            if (is.read(commHeader) != commHeader.length
                    || is.read(encryptedSequenceNumber) != encryptedSequenceNumber.length
                    || is.read(checkSum) != checkSum.length) {
                throw new GSSException(GSSException.FAILURE, -1,
                        "Insufficient in reconstruct token header");
            }
            initTokenHeader(commHeader, prop);

            plainSequenceBytes = encryptor.encryptSequenceNumber(encryptedSequenceNumber, checkSum, false);
            byte dirc = isInitiator ? (byte) 0xFF : 0;
            // Hex 0 - sender is the context initiator, Hex FF - sender is the context acceptor
            if (!(plainSequenceBytes[4] == dirc && plainSequenceBytes[5] == dirc
                    && plainSequenceBytes[6] == dirc && plainSequenceBytes[7] == dirc)) {
                throw new GSSException(GSSException.BAD_MIC, -1,
                        "Corrupt token sequence for " + (tokenType == TOKEN_MIC_V1 ? "Mic" : "Wrap") + "TokenV1");
            }
        } catch (IOException e) {
            throw new GSSException(GSSException.FAILURE, -1,
                    "Error in reconstruct token header:" + e.getMessage());
        }
    }

    private void initTokenHeader(byte[] tokenBytes, MessageProp prop) throws GSSException {
        int tokenIDRecv = (((int) tokenBytes[0]) << 8) + tokenBytes[1];
        if (tokenType != tokenIDRecv) {
            throw new GSSException(GSSException.DEFECTIVE_TOKEN, -1,
                    "Token ID should be " + tokenType + " instead of " + tokenIDRecv);
        }

        sgnAlg = (((int) tokenBytes[2]) << 8) + tokenBytes[3];
        sealAlg = (((int) tokenBytes[4]) << 8) + tokenBytes[5];

        if (tokenBytes[6] != (byte) 0xFF || tokenBytes[7] != (byte) 0xFF) {
            throw new GSSException(GSSException.DEFECTIVE_TOKEN, -1, "Invalid token head filler");
        }

        prop.setQOP(0);
        prop.setPrivacy(sealAlg != SEAL_ALG_NONE);
    }

    protected GSSHeader getGssHeader() {
        return gssHeader;
    }

    abstract int getTokenSizeWithoutGssHeader();
}
