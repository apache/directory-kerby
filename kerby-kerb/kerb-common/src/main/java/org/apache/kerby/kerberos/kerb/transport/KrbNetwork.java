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
import java.net.Socket;

/**
 * Krb client network support.
 */
@SuppressWarnings("PMD")
public class KrbNetwork {

    private InetSocketAddress tcpAddress;
    private InetSocketAddress udpAddress;

    public KrbTransport connect(InetSocketAddress tcpAddress,
                                InetSocketAddress udpAddress) throws IOException {
        this.tcpAddress = tcpAddress;
        this.udpAddress = udpAddress;

        /**
         * Try TCP first.
         */
        KrbTransport transport;
        if (tcpAddress != null) {
            try {
                transport = tcpConnect();
            } catch (IOException e) {
                transport = new KrbUdpTransport(udpAddress);
            }
        } else {
            transport = new KrbUdpTransport(udpAddress);
        }
        return transport;
    }

    private KrbTcpTransport tcpConnect() throws IOException {
        Socket socket = new Socket();
        socket.setSoTimeout(10 * 1000); // 10 seconds. TODO: from config
        socket.connect(tcpAddress);
        return new KrbTcpTransport(socket);
    }
}
