/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/ASN1Structure.java $
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

import org.apache.commons.ssl.util.Hex;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 16-Nov-2005
 */
class ASN1Structure {
    List derIntegers = new LinkedList();
    Set oids = new TreeSet();
    String oid1;
    String oid2;
    String oid3;
    byte[] salt;
    byte[] iv;
    int iterationCount;
    int keySize;
    byte[] bigPayload;
    byte[] smallPayload;

    public String toString() {
        StringBuffer buf = new StringBuffer(256);
        buf.append("------ ASN.1 PKCS Structure ------");
        buf.append("\noid1:    ");
        buf.append(oid1);
        if (oid2 != null) {
            buf.append("\noid2:    ");
            buf.append(oid2);
        }
        buf.append("\nsalt:   ");
        if (salt != null) {
            buf.append(Hex.encode(salt));
        } else {
            buf.append("[null]");
        }
        buf.append("\nic:      ");
        buf.append(Integer.toString(iterationCount));
        if (keySize != 0) {
            buf.append("\nkeySize: ");
            buf.append(Integer.toString(keySize * 8));
        }
        if (oid2 != null) {
            buf.append("\noid3:    ");
            buf.append(oid3);
        }
        if (oid2 != null) {
            buf.append("\niv:      ");
            if (iv != null) {
                buf.append(Hex.encode(iv));
            } else {
                buf.append("[null]");
            }
        }
        if (bigPayload != null) {
            buf.append("\nbigPayload-length:   ");
            buf.append(bigPayload.length);
        }
        if (smallPayload != null) {
            buf.append("\nsmallPayload-length: ");
            buf.append(smallPayload.length);
        }
        if (!oids.isEmpty()) {
            Iterator it = oids.iterator();
            buf.append("\nAll oids:");
            while (it.hasNext()) {
                buf.append("\n");
                buf.append((String) it.next());
            }
        }
        return buf.toString();
    }
}
