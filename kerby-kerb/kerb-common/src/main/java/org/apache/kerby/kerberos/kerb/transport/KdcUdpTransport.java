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
package org.apache.kerby.kerberos.kerb.transport;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Default implementation of {@link KrbTransport} using UDP.
 */
public class KdcUdpTransport extends KrbUdpTransport {
    private BlockingQueue<ByteBuffer> bufferQueue = new ArrayBlockingQueue<>(2);

    public KdcUdpTransport(DatagramChannel channel, InetSocketAddress remoteAddress) throws IOException {
        super(remoteAddress);
        setChannel(channel);
    }

    @Override
    public synchronized ByteBuffer receiveMessage() throws IOException {
        long timeout = 1000; // TODO: configurable or option
        ByteBuffer message;
        try {
            message = bufferQueue.poll(timeout, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            throw new IOException(e);
        }
        return message;
    }

    protected synchronized void onRecvMessage(ByteBuffer message) {
        if (message != null) {
            bufferQueue.add(message);
        }
    }
}
