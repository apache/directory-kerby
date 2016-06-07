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
import java.net.Socket;

/**
 * Krb client network support.
 */
@SuppressWarnings("PMD")
public class KrbNetwork {

    private int socketTimeout = 10 * 1000;
    private TransportPair tpair;

    public KrbTransport connect(TransportPair tpair) throws IOException {
        this.tpair = tpair;

        /**
         * Try TCP first.
         */
        KrbTransport transport = null;
        if (tpair.tcpAddress != null) {
            try {
                transport = tcpConnect();
            } catch (IOException e1) {
                if (tpair.udpAddress != null) {
                    try {
                        transport = new KrbUdpTransport(tpair.udpAddress);
                    } catch (Exception e2) {
                        transport = null;
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            if (tpair.udpAddress != null) {
                try {
                    transport = new KrbUdpTransport(tpair.udpAddress);
                } catch (Exception e3) {
                    transport = null;
                }
            }
        }

        if (transport == null) {
            throw new IOException("Failed to establish the transport");
        }

        return transport;
    }

    private KrbTcpTransport tcpConnect() throws IOException {
        Socket socket = new Socket();
        socket.setSoTimeout(socketTimeout);
        socket.connect(tpair.tcpAddress);
        return new KrbTcpTransport(socket);
    }

    public void setSocketTimeout(int milliSeconds) {
        socketTimeout = milliSeconds;
    }
}
