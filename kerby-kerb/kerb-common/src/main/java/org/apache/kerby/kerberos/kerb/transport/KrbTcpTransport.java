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

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.ByteBuffer;

/**
 * Default implementation of {@link KrbTransport} using TCP in block mode.
 */
public class KrbTcpTransport
        extends AbstractKrbTransport implements KrbTransport {
    private Socket socket;
    private DataOutputStream outputStream;
    private DataInputStream inputStream;
    private byte[] messageBuffer; // for message body

    public KrbTcpTransport(Socket socket) throws IOException {
        this.socket = socket;
        this.outputStream = new DataOutputStream(socket.getOutputStream());
        this.inputStream = new DataInputStream(socket.getInputStream());
        this.messageBuffer = new byte[1024 * 1024]; // TODO.
    }


    @Override
    public void sendMessage(ByteBuffer message) throws IOException {
        outputStream.write(message.array()); // TODO: may not be backed by array
    }

    @Override
    public ByteBuffer receiveMessage() throws IOException {
        int msgLen = inputStream.readInt();
        if (msgLen > 0) {
            inputStream.readFully(messageBuffer, 0, msgLen);
            return ByteBuffer.wrap(messageBuffer, 0, msgLen);
        }

        return null;
    }

    @Override
    public boolean isTcp() {
        return true;
    }

    @Override
    public InetAddress getRemoteAddress() {
        return socket.getInetAddress();
    }

    @Override
    public void release() {
        try {
            socket.close();
        } catch (IOException e) { //NOPMD
            System.err.println(e); // NOOP
        }
    }
}
