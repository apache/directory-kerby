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
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

/**
 * Default implementation of {@Link KrbTransport} combining TCP and UDP.
 */
public class KrbCombinedTransport
        extends AbstractKrbTransport implements KrbTransport {
    private KrbTransport tcpTransport;
    private KrbTransport udpTransport;

    private InetSocketAddress tcpAddress;
    private InetSocketAddress udpAddress;

    public KrbCombinedTransport(InetSocketAddress tcpAddress,
                                InetSocketAddress udpAddress) throws IOException {
        this.tcpAddress = tcpAddress;
        this.udpAddress = udpAddress;

        /**
         * Try TCP first.
         */
        try {
            this.tcpTransport = new KrbTcpTransport(tcpAddress);
        } catch (IOException e) {
            this.tcpTransport = null;
            this.udpTransport = new KrbUdpTransport(udpAddress);
        }
    }

    @Override
    public void sendMessage(ByteBuffer message) throws IOException {
        if (tcpTransport != null) {
            tcpTransport.sendMessage(message);
        } else if (udpTransport != null) {
            udpTransport.sendMessage(message);
        }
    }

    @Override
    public ByteBuffer receiveMessage() throws IOException {
        if (tcpTransport != null) {
            return tcpTransport.receiveMessage();
        } else if (udpTransport != null) {
            return udpTransport.receiveMessage();
        }
        return null;
    }
}
