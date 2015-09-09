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
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;

/**
 * Default implementation of {@link KrbTransport} using UDP.
 */
public class KrbUdpTransport
        extends AbstractKrbTransport implements KrbTransport {
    private DatagramChannel channel;
    private InetSocketAddress remoteAddress;
    private ByteBuffer recvBuffer;

    public KrbUdpTransport(InetSocketAddress remoteAddress) throws IOException {
        this.remoteAddress = remoteAddress;

        DatagramChannel tmpChannel = DatagramChannel.open();
        tmpChannel.configureBlocking(true);
        tmpChannel.connect(remoteAddress);
        setChannel(tmpChannel);

        recvBuffer = ByteBuffer.allocate(65507);
    }

    protected void setChannel(DatagramChannel channel) {
        this.channel = channel;
    }

    @Override
    public void sendMessage(ByteBuffer message) throws IOException {
        channel.send(message, remoteAddress);
    }

    @Override
    public ByteBuffer receiveMessage() throws IOException {
        recvBuffer.clear();
        channel.receive(recvBuffer);
        recvBuffer.flip();
        return recvBuffer;
    }

    @Override
    public boolean isTcp() {
        return false;
    }

    @Override
    public InetAddress getRemoteAddress() {
        return remoteAddress.getAddress();
    }

    @Override
    public void release() {
        try {
            channel.close();
        } catch (IOException e) { //NOPMD
            System.err.println(e); //NOOP
        }
    }
}
