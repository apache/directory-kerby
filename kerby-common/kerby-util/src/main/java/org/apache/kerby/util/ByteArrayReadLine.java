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

package org.apache.kerby.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public class ByteArrayReadLine extends ReadLine {

    public ByteArrayReadLine(ByteArrayInputStream in) {
        super(in);
    }

    public String next() {
        return next(1);
    }

    public String next(int lines) {
        try {
            return super.next(lines);
        } catch (IOException ioe) {
            // impossible since we're using ByteArrayInputStream
            throw new RuntimeException("impossible", ioe);
        }
    }

    public byte[] nextAsBytes() {
        return nextAsBytes(1);
    }

    public byte[] nextAsBytes(int lines) {
        try {
            return super.nextAsBytes(lines);
        } catch (IOException ioe) {
            // impossible since we're using ByteArrayInputStream
            throw new RuntimeException("impossible", ioe);
        }
    }

}
