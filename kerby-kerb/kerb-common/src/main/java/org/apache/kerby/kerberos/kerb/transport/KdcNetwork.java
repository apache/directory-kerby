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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.DatagramChannel;
import java.util.HashMap;
import java.util.Map;

/**
 * A combined and mixed network server handling UDP and TCP.
 */
@SuppressWarnings("PMD")
public abstract class KdcNetwork {
    private static final Logger LOG = LoggerFactory.getLogger(KdcNetwork.class);
    protected static final int MAX_MESSAGE_SIZE = 65507;
    private static final int KDC_TCP_TRANSPORT_TIMEOUT = 3 * 1000;
    private static final int KDC_TCP_SERVER_TIMEOUT = 100;
    private TransportPair tpair;
    private boolean isStopped;
    private ServerSocket tcpServer;
    private DatagramChannel udpServer;
    private Map<InetSocketAddress, KdcUdpTransport> transports =
            new HashMap<InetSocketAddress, KdcUdpTransport>();
    private ByteBuffer recvBuffer;

    public synchronized void init() {
        isStopped = false;
    }

    public synchronized void listen(TransportPair tpair) throws IOException {
        this.tpair = tpair;

        if (tpair.tcpAddress != null) {
            tcpServer = new ServerSocket();
            tcpServer.setSoTimeout(KDC_TCP_SERVER_TIMEOUT);
            tcpServer.bind(tpair.tcpAddress);
        }

        if (tpair.udpAddress != null) {
            udpServer = DatagramChannel.open();
            udpServer.configureBlocking(false);
            udpServer.bind(tpair.udpAddress);
            recvBuffer = ByteBuffer.allocate(MAX_MESSAGE_SIZE);
        }
    }

    public synchronized void start() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                KdcNetwork.this.run();
            }
        }).start();
    }

    //CHECKSTYLE:OFF
    private void run() {
        while (true) {
            synchronized (this) {
                if (isStopped) {
                    break;
                }
            }

            if (tpair.tcpAddress != null) {
                try {
                    checkAndAccept();
                } catch (SocketTimeoutException | ClosedChannelException | SocketException e) { //NOPMD
                    //NOOP as normal
                } catch (IOException e) {
                    throw new RuntimeException("Error occured while checking tcp connections", e);
                }
            }

            if (tpair.udpAddress != null) {
                try {
                    checkUdpMessage();
                } catch (SocketTimeoutException | ClosedChannelException | SocketException e) { //NOPMD
                    //NOOP as normal
                } catch (IOException e) {
                    throw new RuntimeException("Error occured while checking udp connections", e);
                }
            }
        }
    }
    //CHECKSTYLE:ON

    public synchronized void stop() {
        try {
            if (tcpServer != null) {
                tcpServer.close();
            }

            if (udpServer != null) {
                udpServer.close();
            }
        } catch (IOException e) {
            LOG.warn("KDC network stopping error " + e);
        }

        isStopped = true;
    }

    private void checkAndAccept() throws IOException {
        if (tcpServer.isClosed()) {
            return;
        }

        Socket socket;
        if ((socket = tcpServer.accept()) != null) {
            socket.setSoTimeout(KDC_TCP_TRANSPORT_TIMEOUT);
            KrbTransport transport = new KrbTcpTransport(socket);
            onNewTransport(transport);
        }
    }

    private void checkUdpMessage() throws IOException {
        if (!udpServer.isOpen()) {
            return;
        }

        InetSocketAddress fromAddress = (InetSocketAddress) udpServer.receive(recvBuffer);
        if (fromAddress != null) {
            recvBuffer.flip();
            KdcUdpTransport transport = transports.get(fromAddress);
            if (transport == null) {
                transport = new KdcUdpTransport(udpServer, fromAddress);
                transport.onRecvMessage(recvBuffer);
                onNewTransport(transport);
            } else {
                transport.onRecvMessage(recvBuffer);
            }
            recvBuffer = ByteBuffer.allocate(MAX_MESSAGE_SIZE);
        }
    }

    protected abstract void onNewTransport(KrbTransport transport);
}
