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
package org.apache.kerby.transport;

import org.apache.kerby.event.Dispatcher;
import org.apache.kerby.transport.buffer.TransBuffer;
import org.apache.kerby.transport.event.TransportEvent;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

public abstract class Transport {
    private InetSocketAddress remoteAddress;
    protected Dispatcher dispatcher;
    private Object attachment;

    protected TransBuffer sendBuffer;

    private int readableCount = 0;
    private int writableCount = 0;

    public Transport(InetSocketAddress remoteAddress) {
        this.remoteAddress = remoteAddress;
        this.sendBuffer = new TransBuffer();
    }

    public void setDispatcher(Dispatcher dispatcher) {
        this.dispatcher = dispatcher;
    }

    public InetSocketAddress getRemoteAddress() {
        return remoteAddress;
    }

    public void sendMessage(ByteBuffer message) {
        if (message != null) {
            sendBuffer.write(message);
            dispatcher.dispatch(TransportEvent.createWritableTransportEvent(this));
        }
    }

    public void onWriteable() throws IOException {
        this.writableCount ++;

        if (! sendBuffer.isEmpty()) {
            ByteBuffer message = sendBuffer.read();
            if (message != null) {
                sendOutMessage(message);
            }
        }
    }

    public void onReadable() throws IOException {
        this.readableCount++;
    }

    protected abstract void sendOutMessage(ByteBuffer message) throws IOException;

    public void setAttachment(Object attachment) {
        this.attachment = attachment;
    }

    public Object getAttachment() {
        return attachment;
    }
}
