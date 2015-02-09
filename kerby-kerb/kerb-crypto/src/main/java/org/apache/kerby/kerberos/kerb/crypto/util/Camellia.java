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
package org.apache.kerby.kerberos.kerb.crypto.util;

/**
 * Camellia - based on RFC 3713, about half the size of CamelliaEngine.
 *
 * This is based on CamelliaEngine.java from bouncycastle library.
 */

public class Camellia {
    private static final int BLOCK_SIZE = 16;
    private int[] state = new int[4]; // for encryption and decryption

    private CamelliaKey camKey;

    public void setKey(boolean forEncryption, byte[] key) {
        camKey = new CamelliaKey(key, forEncryption);
    }

    private void process128Block(byte[] in, int inOff,
                                byte[] out, int outOff) {
        for (int i = 0; i < 4; i++) {
            state[i] = BytesUtil.bytes2int(in, inOff + (i * 4), true);
            state[i] ^= camKey.kw[i];
        }

        camKey.f2(state, camKey.subkey, 0);
        camKey.f2(state, camKey.subkey, 4);
        camKey.f2(state, camKey.subkey, 8);
        camKey.fls(state, camKey.ke, 0);
        camKey.f2(state, camKey.subkey, 12);
        camKey.f2(state, camKey.subkey, 16);
        camKey.f2(state, camKey.subkey, 20);
        camKey.fls(state, camKey.ke, 4);
        camKey.f2(state, camKey.subkey, 24);
        camKey.f2(state, camKey.subkey, 28);
        camKey.f2(state, camKey.subkey, 32);

        state[2] ^= camKey.kw[4];
        state[3] ^= camKey.kw[5];
        state[0] ^= camKey.kw[6];
        state[1] ^= camKey.kw[7];

        BytesUtil.int2bytes(state[2], out, outOff, true);
        BytesUtil.int2bytes(state[3], out, outOff + 4, true);
        BytesUtil.int2bytes(state[0], out, outOff + 8, true);
        BytesUtil.int2bytes(state[1], out, outOff + 12, true);
    }

    private void processBlockLargerBlock(byte[] in, int inOff,
                                        byte[] out, int outOff) {
        for (int i = 0; i < 4; i++) {
            state[i] = BytesUtil.bytes2int(in, inOff + (i * 4), true);
            state[i] ^= camKey.kw[i];
        }

        camKey.f2(state, camKey.subkey, 0);
        camKey.f2(state, camKey.subkey, 4);
        camKey.f2(state, camKey.subkey, 8);
        camKey.fls(state, camKey.ke, 0);
        camKey.f2(state, camKey.subkey, 12);
        camKey.f2(state, camKey.subkey, 16);
        camKey.f2(state, camKey.subkey, 20);
        camKey.fls(state, camKey.ke, 4);
        camKey.f2(state, camKey.subkey, 24);
        camKey.f2(state, camKey.subkey, 28);
        camKey.f2(state, camKey.subkey, 32);
        camKey.fls(state, camKey.ke, 8);
        camKey.f2(state, camKey.subkey, 36);
        camKey.f2(state, camKey.subkey, 40);
        camKey.f2(state, camKey.subkey, 44);

        state[2] ^= camKey.kw[4];
        state[3] ^= camKey.kw[5];
        state[0] ^= camKey.kw[6];
        state[1] ^= camKey.kw[7];

        BytesUtil.int2bytes(state[2], out, outOff, true);
        BytesUtil.int2bytes(state[3], out, outOff + 4, true);
        BytesUtil.int2bytes(state[0], out, outOff + 8, true);
        BytesUtil.int2bytes(state[1], out, outOff + 12, true);
    }

    public void processBlock(byte[] in, int inOff) {
        byte[] out = new byte[BLOCK_SIZE];

        if (camKey.is128()) {
            process128Block(in, inOff, out, 0);
        } else {
            processBlockLargerBlock(in, inOff, out, 0);
        }

        System.arraycopy(out, 0, in, inOff, BLOCK_SIZE);
    }

    public void encrypt(byte[] data, byte[] iv) {
        byte[] cipher = new byte[BLOCK_SIZE];
        byte[] cipherState = new byte[BLOCK_SIZE];

        int blocksNum = (data.length + BLOCK_SIZE - 1) / BLOCK_SIZE;
        int lastBlockLen = data.length - (blocksNum - 1) * BLOCK_SIZE;
        if (blocksNum == 1) {
            cbcEnc(data, 0, 1, cipherState);
            return;
        }

        if (iv != null) {
            System.arraycopy(iv, 0, cipherState, 0, BLOCK_SIZE);
        }

        int contBlocksNum, offset = 0;
        while (blocksNum > 2) {
            contBlocksNum = (data.length - offset) / BLOCK_SIZE;
            if (contBlocksNum > 0) {
                // Encrypt a series of contiguous blocks in place if we can, but
                // don't touch the last two blocks.
                contBlocksNum = (contBlocksNum > blocksNum - 2) ? blocksNum - 2 : contBlocksNum;
                cbcEnc(data, offset, contBlocksNum, cipherState);
                offset += contBlocksNum * BLOCK_SIZE;
                blocksNum -= contBlocksNum;
            } else {
                cbcEnc(data, offset, 1, cipherState);
                offset += BLOCK_SIZE;
                blocksNum--;
            }
        }

        // Encrypt the last two blocks and store the results in reverse order
        byte[] blockN2 = new byte[BLOCK_SIZE];
        byte[] blockN1 = new byte[BLOCK_SIZE];

        System.arraycopy(data, offset, blockN2, 0, BLOCK_SIZE);
        cbcEnc(blockN2, 0, 1, cipherState);
        System.arraycopy(data, offset + BLOCK_SIZE, blockN1, 0, lastBlockLen);
        cbcEnc(blockN1, 0, 1, cipherState);

        System.arraycopy(blockN1, 0, data, offset, BLOCK_SIZE);
        System.arraycopy(blockN2, 0, data, offset + BLOCK_SIZE, lastBlockLen);

        if (iv != null) {
            System.arraycopy(cipherState, 0, iv, 0, BLOCK_SIZE);
        }
    }

    public void decrypt(byte[] data, byte[] iv) {
        byte[] cipher = new byte[BLOCK_SIZE];
        byte[] cipherState = new byte[BLOCK_SIZE];

        int blocksNum = (data.length + BLOCK_SIZE - 1) / BLOCK_SIZE;
        int lastBlockLen = data.length - (blocksNum - 1) * BLOCK_SIZE;
        if (blocksNum == 1) {
            cbcDec(data, 0, 1, cipherState);
            return;
        }

        if (iv != null) {
            System.arraycopy(iv, 0, cipherState, 0, BLOCK_SIZE);
        }

        int contBlocksNum, offset = 0;
        while (blocksNum > 2) {
            contBlocksNum = (data.length - offset) / BLOCK_SIZE;
            if (contBlocksNum > 0) {
                // Decrypt a series of contiguous blocks in place if we can, but
                // don't touch the last two blocks.
                contBlocksNum = (contBlocksNum > blocksNum - 2) ? blocksNum - 2 : contBlocksNum;
                cbcDec(data, offset, contBlocksNum, cipherState);
                offset += contBlocksNum * BLOCK_SIZE;
                blocksNum -= contBlocksNum;
            } else {
                cbcDec(data, offset, 1, cipherState);
                offset += BLOCK_SIZE;
                blocksNum--;
            }
        }

        // Decrypt the last two blocks
        byte[] blockN2 = new byte[BLOCK_SIZE];
        byte[] blockN1 = new byte[BLOCK_SIZE];
        System.arraycopy(data, offset, blockN2, 0, BLOCK_SIZE);
        System.arraycopy(data, offset + BLOCK_SIZE, blockN1, 0, lastBlockLen);
        if (iv != null) {
            System.arraycopy(blockN2, 0, iv, 0, BLOCK_SIZE);
        }

        byte[] tmpCipherState = new byte[BLOCK_SIZE];
        System.arraycopy(blockN1, 0, tmpCipherState, 0, BLOCK_SIZE);
        cbcDec(blockN2, 0, 1, tmpCipherState);
        System.arraycopy(blockN2, lastBlockLen, blockN1, lastBlockLen, BLOCK_SIZE - lastBlockLen);
        cbcDec(blockN1, 0, 1, cipherState);

        System.arraycopy(blockN1, 0, data, offset, BLOCK_SIZE);
        System.arraycopy(blockN2, 0, data, offset + BLOCK_SIZE, lastBlockLen);
    }

    /**
     * CBC encrypt nblocks blocks of data in place, using and updating iv.
     */
    public void cbcEnc(byte[] data, int offset, int blocksNum, byte[] cipherState) {
        byte[] cipher = new byte[BLOCK_SIZE];
        for (int i = 0; i < blocksNum; ++i) {
            System.arraycopy(data, offset + i * BLOCK_SIZE, cipher, 0, BLOCK_SIZE);
            BytesUtil.xor(cipherState, 0, cipher);
            processBlock(cipher, 0);
            System.arraycopy(cipher, 0, data, offset + i * BLOCK_SIZE, BLOCK_SIZE);
            System.arraycopy(cipher, 0, cipherState, 0, BLOCK_SIZE);
        }
    }

    /**
     * CBC encrypt nblocks blocks of data in place, using and updating iv.
     */
    public void cbcDec(byte[] data, int offset, int blocksNum, byte[] cipherState) {
        byte[] lastBlock = new byte[BLOCK_SIZE];
        byte[] cipher = new byte[BLOCK_SIZE];

        System.arraycopy(data, offset + (blocksNum - 1) * BLOCK_SIZE, lastBlock, 0, BLOCK_SIZE);
        for (int i = blocksNum; i > 0; i--) {
            System.arraycopy(data, offset + (i - 1) * BLOCK_SIZE, cipher, 0, BLOCK_SIZE);
            processBlock(cipher, 0);

            if (i == 1) {
                BytesUtil.xor(cipherState, 0, cipher);
            } else {
                BytesUtil.xor(data, offset + (i - 2) * BLOCK_SIZE, cipher);
            }

            System.arraycopy(cipher, 0, data, offset + (i - 1) * BLOCK_SIZE, BLOCK_SIZE);
        }
        System.arraycopy(lastBlock, 0, cipherState, 0, BLOCK_SIZE);
    }
}
