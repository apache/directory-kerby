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
package org.apache.kerby.kerberos.kerb.server.impl.event;

import org.apache.kerby.kerberos.kerb.server.KdcHandler;
import org.apache.kerby.kerberos.kerb.server.KdcContext;
import org.apache.kerby.transport.MessageHandler;
import org.apache.kerby.transport.Transport;
import org.apache.kerby.transport.event.MessageEvent;
import org.apache.kerby.transport.tcp.TcpTransport;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

/**
 * KDC handler to process client requests. Currently only one realm is supported.
 */
public class EventKdcHandler extends MessageHandler {

    private final KdcHandler myKdcHandler;

    public EventKdcHandler(KdcContext kdcContext) {
        this.myKdcHandler = new KdcHandler(kdcContext);
    }

    @Override
    protected void handleMessage(MessageEvent event) throws Exception {
        ByteBuffer message = event.getMessage();
        Transport transport = event.getTransport();

        InetSocketAddress clientAddress = transport.getRemoteAddress();
        boolean isTcp = transport instanceof TcpTransport;

        try {
            ByteBuffer krbResponse = myKdcHandler.handleMessage(message, isTcp,
                    clientAddress.getAddress());
            transport.sendMessage(krbResponse);
        } catch (Exception e) {
            //TODO: log the error
            System.out.println("Error occured while processing request:"
                    + e.getMessage());
        }
    }
}
