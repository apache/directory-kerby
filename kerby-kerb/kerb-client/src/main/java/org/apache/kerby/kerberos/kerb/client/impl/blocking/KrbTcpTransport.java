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
package org.apache.kerby.kerberos.kerb.client.impl.blocking;

import org.apache.kerby.kerberos.kerb.transport.AbstractKrbTransport;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SocketChannel;

/**
 * Default implementation of {@Link KrbTransport} using TCP in block mode.
 */
public class KrbTcpTransport
        extends AbstractKrbTransport implements KrbTransport {
    private SocketChannel socketChannel;
    private ReadableByteChannel wrappedChannel; // for timeout stuff.
    private InetSocketAddress remoteAddress;
    private ByteBuffer headerBuffer; // for message length
    private ByteBuffer messageBuffer; // for message body

    public KrbTcpTransport(InetSocketAddress remoteAddress) throws IOException {
        this.remoteAddress = remoteAddress;
        this.headerBuffer = ByteBuffer.allocate(4);
        this.messageBuffer = ByteBuffer.allocate(1024 * 1024); // TODO.
        doConnect();
    }

    private void doConnect() throws IOException {
        socketChannel = SocketChannel.open();
        socketChannel.configureBlocking(true);
        socketChannel.socket().setSoTimeout(100); // TODO.
        socketChannel.connect(remoteAddress);

        InputStream inStream = socketChannel.socket().getInputStream();
        wrappedChannel = Channels.newChannel(inStream);
    }

    @Override
    public void sendMessage(ByteBuffer message) throws IOException {
        socketChannel.write(message);
    }

    @Override
    public ByteBuffer receiveMessage() {
        try {
            headerBuffer.clear();
            headerBuffer.position(0);
            headerBuffer.limit(4);
            wrappedChannel.read(headerBuffer);
            headerBuffer.flip();

            int msgLen = headerBuffer.getInt();
            if (msgLen > 0) {
                messageBuffer.clear();
                messageBuffer.position(0);
                messageBuffer.limit(msgLen);
                wrappedChannel.read(messageBuffer);
                messageBuffer.flip();

                return messageBuffer;
            }
        } catch (IOException e) {
            return null;
        }

        return null;
    }
}
