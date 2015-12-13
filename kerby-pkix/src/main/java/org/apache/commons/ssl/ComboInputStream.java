/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/ComboInputStream.java $
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

import java.io.IOException;
import java.io.InputStream;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 22-Feb-2007
 */
public class ComboInputStream extends InputStream {
    private boolean headDone;
    private InputStream head;
    private InputStream tail;

    public ComboInputStream(InputStream head, InputStream tail) {
        this.head = head != null ? head : tail;
        this.tail = tail != null ? tail : head;
    }

    public int read() throws IOException {
        int c;
        if (headDone) {
            c = tail.read();
        } else {
            c = head.read();
            if (c == -1) {
                headDone = true;
                c = tail.read();
            }
        }
        return c;
    }

    public int available() throws IOException {
        return tail.available() + head.available();
    }

    public void close() throws IOException {
        try {
            head.close();
        } finally {
            if (head != tail) {
                tail.close();
            }
        }
    }

    public int read(byte[] b, int off, int len) throws IOException {
        int c;
        if (headDone) {
            c = tail.read(b, off, len);
        } else {
            c = head.read(b, off, len);
            if (c == -1) {
                headDone = true;
                c = tail.read(b, off, len);
            }
        }
        return c;
    }

}
