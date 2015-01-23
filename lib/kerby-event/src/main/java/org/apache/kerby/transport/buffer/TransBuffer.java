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
package org.apache.kerby.transport.buffer;

import java.nio.ByteBuffer;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

public class TransBuffer {

    private BlockingQueue<ByteBuffer> bufferQueue;

    public TransBuffer() {
        bufferQueue = new ArrayBlockingQueue<ByteBuffer>(2);
    }

    public void write(ByteBuffer buffer) {
        bufferQueue.add(buffer);
    }

    public void write(byte[] buffer) {
        write(ByteBuffer.wrap(buffer));
    }

    public ByteBuffer read() {
        return bufferQueue.poll();
    }

    public boolean isEmpty() {
        return bufferQueue.isEmpty();
    }
}
