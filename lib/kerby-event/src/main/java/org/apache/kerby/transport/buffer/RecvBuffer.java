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

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.Iterator;
import java.util.LinkedList;

public class RecvBuffer {

    private LinkedList<ByteBuffer> bufferQueue;

    public RecvBuffer() {
        bufferQueue = new LinkedList<ByteBuffer>();
    }

    public synchronized void write(ByteBuffer buffer) {
        bufferQueue.addLast(buffer);
    }

    /**
     * Put buffer as the first into the buffer queue
     */
    public synchronized void writeFirst(ByteBuffer buffer) {
        bufferQueue.addFirst(buffer);
    }

    /**
     * Read and return the first buffer if available
     */
    public synchronized ByteBuffer readFirst() {
        if (! bufferQueue.isEmpty()) {
            return bufferQueue.removeFirst();
        }
        return null;
    }

    /**
     * Read most available bytes into the dst buffer
     */
    public synchronized ByteBuffer readMostBytes() {
        int len = remaining();
        return readBytes(len);
    }

    /**
     * Read len bytes into the dst buffer if available
     */
    public synchronized ByteBuffer readBytes(int len) {
        if (remaining() < len) { // no enough data that's available
            throw new BufferOverflowException();
        }

        ByteBuffer result = null;

        ByteBuffer takenBuffer;
        if (bufferQueue.size() == 1) {
            takenBuffer = bufferQueue.removeFirst();

            if (takenBuffer.remaining() == len) {
                return takenBuffer;
            }

            result = BufferPool.allocate(len);
            for (int i = 0; i < len; i++) {
                result.put(takenBuffer.get());
            }
            // Has left bytes so put it back for future reading
            if (takenBuffer.remaining() > 0) {
                bufferQueue.addFirst(takenBuffer);
            }
        } else {
            result = BufferPool.allocate(len);

            Iterator<ByteBuffer> iter = bufferQueue.iterator();
            int alreadyGot = 0, toGet;
            while (iter.hasNext()) {
                takenBuffer = iter.next();
                iter.remove();

                toGet = takenBuffer.remaining() < len - alreadyGot ?
                    takenBuffer.remaining() : len -alreadyGot;
                byte[] toGetBytes = new byte[toGet];
                takenBuffer.get(toGetBytes);
                result.put(toGetBytes);

                if (takenBuffer.remaining() > 0) {
                    bufferQueue.addFirst(takenBuffer);
                }

                alreadyGot += toGet;
                if (alreadyGot == len) {
                    break;
                }
            }
        }
        result.flip();

        return result;
    }

    public boolean isEmpty() {
        return bufferQueue.isEmpty();
    }

    /**
     * Return count of remaining and left bytes that's available
     */
    public int remaining() {
        if (bufferQueue.isEmpty()) {
            return 0;
        } else if (bufferQueue.size() == 1) {
            return bufferQueue.getFirst().remaining();
        }

        int result = 0;
        Iterator<ByteBuffer> iter = bufferQueue.iterator();
        while (iter.hasNext()) {
            result += iter.next().remaining();
        }
        return result;
    }

    public synchronized void clear() {
        if (bufferQueue.isEmpty()) {
            return;
        } else if (bufferQueue.size() == 1) {
            BufferPool.release(bufferQueue.getFirst());
        }

        Iterator<ByteBuffer> iter = bufferQueue.iterator();
        while (iter.hasNext()) {
            BufferPool.release(iter.next());
        }
        bufferQueue.clear();
    }
}
