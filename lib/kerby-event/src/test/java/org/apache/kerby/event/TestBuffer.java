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
package org.apache.kerby.event;

import org.apache.kerby.transport.buffer.RecvBuffer;
import org.junit.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;

public class TestBuffer {

    @Test
    public void testRecvBuffer() {
        String testString = "HELLO WORLD";
        ByteBuffer testMessage = ByteBuffer.wrap(testString.getBytes());
        ByteBuffer tmp;

        RecvBuffer testBuffer = new RecvBuffer();
        testBuffer.write(testMessage);
        tmp = testBuffer.readMostBytes();
        assertThat(tmp.array()).isEqualTo(testString.getBytes());

        int nTimes = 10;
        testBuffer.clear();
        for (int i = 0; i < nTimes; ++i) {
            testBuffer.write(ByteBuffer.wrap(testString.getBytes()));
        }
        int expectedBytes = nTimes * testMessage.limit();
        tmp = testBuffer.readMostBytes();
        assertThat(tmp.limit()).isEqualTo(expectedBytes);
    }
}
