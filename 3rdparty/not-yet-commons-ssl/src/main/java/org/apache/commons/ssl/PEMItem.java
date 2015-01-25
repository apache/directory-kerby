/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/PEMItem.java $
 * $Revision: 121 $
 * $Date: 2007-11-13 21:26:57 -0800 (Tue, 13 Nov 2007) $
 *
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

package org.apache.commons.ssl;

import org.apache.kerby.util.Hex;

import java.util.Collections;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.TreeMap;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 13-Aug-2006
 */
public class PEMItem {
    public final static String DEK_INFO = "dek-info";

    private final byte[] derBytes;
    public final String pemType;
    public final Map properties;

    public final String dekInfo;
    public final byte[] iv;
    public final String cipher;
    public final boolean des2;
    public final String mode;
    public final int keySizeInBits;

    public PEMItem(byte[] derBytes, String type) {
        this(derBytes, type, null);
    }

    public PEMItem(byte[] derBytes, String type, Map properties) {
        this.derBytes = derBytes;
        this.pemType = type;
        if (properties == null) {
            properties = new TreeMap(); // empty map
        }
        this.properties = Collections.unmodifiableMap(properties);
        String di = (String) properties.get(DEK_INFO);
        String diCipher = "";
        String diIV = "";
        if (di != null) {
            StringTokenizer st = new StringTokenizer(di, ",");
            if (st.hasMoreTokens()) {
                diCipher = st.nextToken().trim().toLowerCase();
            }
            if (st.hasMoreTokens()) {
                diIV = st.nextToken().trim().toLowerCase();
            }
        }
        this.dekInfo = diCipher;
        this.iv = Hex.decode(diIV);
        if (!"".equals(diCipher)) {
            OpenSSL.CipherInfo cipherInfo = OpenSSL.lookup(diCipher);
            this.cipher = cipherInfo.javaCipher;
            this.mode = cipherInfo.blockMode;
            this.keySizeInBits = cipherInfo.keySize;
            this.des2 = cipherInfo.des2;
        } else {
            this.mode = "";
            cipher = "UNKNOWN";
            keySizeInBits = -1;
            des2 = false;
        }
    }

    public byte[] getDerBytes() {
        byte[] b = new byte[derBytes.length];
        System.arraycopy(derBytes, 0, b, 0, derBytes.length);
        return b;
    }

}
