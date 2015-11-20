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
package org.apache.kerby.kerberos.kerb.server.impl;

import org.apache.kerby.kerberos.kerb.server.KdcContext;
import org.apache.kerby.kerberos.kerb.server.KdcHandler;
import org.apache.kerby.kerberos.kerb.transport.KrbTcpTransport;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;

public class DefaultKdcHandler extends KdcHandler implements Runnable {
    private static Logger logger = LoggerFactory.getLogger(DefaultKdcHandler.class);
    private final KrbTransport transport;

    public DefaultKdcHandler(KdcContext kdcContext, KrbTransport transport) {
        super(kdcContext);
        this.transport  = transport;
    }

    @Override
    public void run() {
        while (true) {
            try {
                ByteBuffer message = transport.receiveMessage();
                if (message == null) {
                    logger.debug("No valid request recved. Disconnect actively");
                    transport.release();
                    break;
                }
                handleMessage(message);
            } catch (IOException e) {
                transport.release();
                logger.debug("Transport or decoding error occurred, "
                        + "disconnecting abnormally", e);
                break;
            }
        }
    }

    protected void handleMessage(ByteBuffer message) {
        InetAddress clientAddress = transport.getRemoteAddress();
        boolean isTcp = transport instanceof KrbTcpTransport;

        try {
            ByteBuffer krbResponse = handleMessage(message, isTcp, clientAddress);
            transport.sendMessage(krbResponse);
        } catch (Exception e) {
            transport.release();
            logger.error("Error occured while processing request:", e);
        }
    }
}