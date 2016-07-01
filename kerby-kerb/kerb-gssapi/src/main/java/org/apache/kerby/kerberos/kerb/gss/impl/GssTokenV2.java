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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;

/**
 * This class implements the token formats defined in RFC 4121.
 */
abstract class GssTokenV2 extends GssTokenBase {
    public static final int CONFOUNDER_SIZE = 16;
    public static final int TOKEN_HEADER_SIZE = 16;
    private static final int OFFSET_EC = 4;
    private static final int OFFSET_RRC = 6;

    // context states
    private boolean isInitiator = true;
    private boolean acceptorSubKey = false;
    private boolean confState = true;
    private int sequenceNumber;

    // token data
    protected int tokenType;
    private byte[] header = new byte[TOKEN_HEADER_SIZE];
    protected byte[] tokenData;

    protected byte[] checkSum;
    private int ec;
    private int rrc;

    static final int KG_USAGE_ACCEPTOR_SEAL = 22;
    static final int KG_USAGE_ACCEPTOR_SIGN = 23;
    static final int KG_USAGE_INITIATOR_SEAL = 24;
    static final int KG_USAGE_INITIATOR_SIGN = 25;
    private int keyUsage;

    private static final int FLAG_SENT_BY_ACCEPTOR = 1;
    private static final int FLAG_SEALED = 2;
    private static final int FLAG_ACCEPTOR_SUBKEY = 4;

    protected GssEncryptor encryptor;


    // Create a new token
    GssTokenV2(int tokenType, GssContext context) throws GSSException {
        initialize(tokenType, context, false);
    }

    private void initialize(int tokenType, GssContext context, boolean reconstruct) throws GSSException {
        this.tokenType = tokenType;
        this.isInitiator = context.isInitiator();
        this.acceptorSubKey = context.getKeyComesFrom() == GssContext.ACCEPTOR_SUBKEY;
        this.confState = context.getConfState();

        boolean usageFlag = reconstruct ? !this.isInitiator : this.isInitiator;
        if (tokenType == TOKEN_WRAP_V2) {
            keyUsage = usageFlag ? KG_USAGE_INITIATOR_SEAL : KG_USAGE_ACCEPTOR_SEAL;
        } else if (tokenType == TOKEN_MIC_V2) {
            keyUsage = usageFlag ? KG_USAGE_INITIATOR_SIGN : KG_USAGE_ACCEPTOR_SIGN;
        }

        encryptor = context.getGssEncryptor();

        if (!reconstruct) {
            this.sequenceNumber = context.incMySequenceNumber();
        }
    }

    // Reconstruct token from bytes received
    GssTokenV2(int tokenType, GssContext context,
               MessageProp prop, byte[] token, int offset, int len) throws GSSException {
        this(tokenType, context, prop, new ByteArrayInputStream(token, offset, len));
    }

    // Reconstruct token from input stream
    GssTokenV2(int tokenType, GssContext context,
               MessageProp prop, InputStream is) throws GSSException {
        initialize(tokenType, context, true);

        if (!confState) {
            prop.setPrivacy(false);
        }

        reconstructTokenHeader(prop, is);

        int minSize;
        if (tokenType == TOKEN_WRAP_V2 && prop.getPrivacy()) {
            minSize = CONFOUNDER_SIZE + TOKEN_HEADER_SIZE + encryptor.getCheckSumSize();
        } else {
            minSize = encryptor.getCheckSumSize();
        }

        try {
            int tokenLen = is.available();

            if (tokenType == TOKEN_MIC_V2) {
                tokenLen = minSize;
                tokenData = new byte[tokenLen];
                is.read(tokenData);
            } else {
                if (tokenLen >= minSize) {
                    tokenData = new byte[tokenLen];
                    is.read(tokenData);
                } else {
                    throw new GSSException(GSSException.DEFECTIVE_TOKEN, -1, "Invalid token length");
                }
            }

            if (tokenType == TOKEN_WRAP_V2) {
                tokenData = rotate(tokenData);
            }

            if (tokenType == TOKEN_MIC_V2
                    || tokenType == TOKEN_WRAP_V2 && !prop.getPrivacy()) {
                int checksumLen = encryptor.getCheckSumSize();

                if (tokenType != TOKEN_MIC_V2 && checksumLen != ec) {
                    throw new GSSException(GSSException.DEFECTIVE_TOKEN, -1, "Invalid EC");
                }

                checkSum = new byte[checksumLen];
                System.arraycopy(tokenData, tokenLen - checksumLen, checkSum, 0, checksumLen);
            }
        } catch (IOException e) {
            throw new GSSException(GSSException.DEFECTIVE_TOKEN, -1, "Invalid token");
        }
    }

    private byte[] rotate(byte[] data) {
        int dataLen = data.length;
        if (rrc % dataLen != 0) {
            rrc = rrc % dataLen;
            byte[] newBytes = new byte[dataLen];

            System.arraycopy(data, rrc, newBytes, 0, dataLen - rrc);
            System.arraycopy(data, 0, newBytes, dataLen - rrc, rrc);
            data = newBytes;
        }
        return data;
    }

    public int getKeyUsage() {
        return keyUsage;
    }

    public void generateCheckSum(MessageProp prop, byte[] data, int offset, int len) throws GSSException {
        // generate token header
        createTokenHeader(prop.getPrivacy());

        if (tokenType == TOKEN_MIC_V2
                || !prop.getPrivacy() && tokenType == TOKEN_WRAP_V2) {
            checkSum = getCheckSum(data, offset, len);
        }

        if (!prop.getPrivacy() && tokenType == TOKEN_WRAP_V2) {
            header[4] = (byte) (checkSum.length >>> 8);
            header[5] = (byte) (checkSum.length & 0xFF);
        }
    }

    public byte[] getCheckSum(byte[] data, int offset, int len) throws GSSException {
        int confidentialFlag = header[2] & 2;
        if (confidentialFlag == 0 && tokenType == TOKEN_WRAP_V2) {
            header[4] = 0;
            header[5] = 0;
            header[6] = 0;
            header[7] = 0;
        }
        return encryptor.calculateCheckSum(header, data, offset, len, keyUsage);
    }

    public boolean verifyCheckSum(byte[] data, int offset, int len) throws GSSException {
        byte[] dataCheckSum = getCheckSum(data, offset, len);
        return MessageDigest.isEqual(checkSum, dataCheckSum);
    }

    // Create a new header
    private void createTokenHeader(boolean privacy) {
        header[0] = (byte) (tokenType >>> 8);
        header[1] = (byte) tokenType;

        int flags = isInitiator ? 0 : FLAG_SENT_BY_ACCEPTOR;
        flags |= privacy && tokenType != TOKEN_MIC_V2 ? FLAG_SEALED : 0;
        flags |= acceptorSubKey ? FLAG_ACCEPTOR_SUBKEY : 0;

        header[2] = (byte) (flags & 0xFF);
        header[3] = (byte) 0xFF;

        if (tokenType == TOKEN_WRAP_V2) {
            header[4] = (byte) 0;
            header[5] = (byte) 0;
            header[6] = (byte) 0;
            header[7] = (byte) 0;
        } else if (tokenType == TOKEN_MIC_V2) {
            header[4] = (byte) 0xFF;
            header[5] = (byte) 0xFF;
            header[6] = (byte) 0xFF;
            header[7] = (byte) 0xFF;
        }
        writeBigEndian(header, 12, sequenceNumber);
    }

    // Reconstruct a token header
    private void reconstructTokenHeader(MessageProp prop, InputStream is) throws GSSException {
        try {
            if (is.read(header, 0, header.length) != header.length) {
                throw new GSSException(GSSException.FAILURE, -1, "Token header can not be read");
            }
            int tokenIDRecv = (((int) header[0]) << 8) + header[1];
            if (tokenIDRecv != tokenType) {
                throw new GSSException(GSSException.DEFECTIVE_TOKEN, -1,
                        "Token ID should be " + tokenType + " instead of " + tokenIDRecv);
            }

            int senderFlag = isInitiator ? FLAG_SENT_BY_ACCEPTOR : 0;
            int senderFlagRecv = header[2] & FLAG_SENT_BY_ACCEPTOR;
            if (senderFlagRecv != senderFlag) {
                throw new GSSException(GSSException.DEFECTIVE_TOKEN, -1, "Invalid acceptor flag");
            }

            int confFlagRecv = header[2] & FLAG_SEALED;
            if (confFlagRecv == FLAG_SEALED && tokenType == TOKEN_WRAP_V2) {
                prop.setPrivacy(true);
            } else {
                prop.setPrivacy(false);
            }

            if (tokenType == TOKEN_WRAP_V2) {
                if (header[3] != (byte) 0xFF) {
                    throw new GSSException(GSSException.DEFECTIVE_TOKEN, -1, "Invalid token filler");
                }

                ec = readBigEndian(header, OFFSET_EC, 2);
                rrc = readBigEndian(header, OFFSET_RRC, 2);
            } else if (tokenType == TOKEN_MIC_V2) {
                for (int i = 3; i < 8; i++) {
                    if ((header[i] & 0xFF) != 0xFF) {
                        throw new GSSException(GSSException.DEFECTIVE_TOKEN, -1, "Invalid token filler");
                    }
                }
            }

            prop.setQOP(0);
            sequenceNumber = readBigEndian(header, 0, 8);
        } catch (IOException e) {
            throw new GSSException(GSSException.FAILURE, -1, "Phrase token header failed");
        }
    }

    public int encodeHeader(byte[] buf, int offset) {
        System.arraycopy(header, 0, buf, offset, TOKEN_HEADER_SIZE);
        return TOKEN_HEADER_SIZE;
    }

    public void encodeHeader(OutputStream os) throws IOException {
        os.write(header);
    }
}
