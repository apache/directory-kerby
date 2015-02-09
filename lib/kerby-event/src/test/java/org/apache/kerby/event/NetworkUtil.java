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
package org.apache.kerby.event;

import java.io.IOException;
import java.net.ServerSocket;

/**
 * Some network and event testing utilities.
 */
public class NetworkUtil {

    /**
     * Get a server socket point for testing usage, either TCP or UDP.
     * @return server socket point
     */
    public static int getServerPort() {
        int serverPort = 0;

        try {
            ServerSocket serverSocket = new ServerSocket(0);
            serverPort = serverSocket.getLocalPort();
            serverSocket.close();
        } catch (IOException e) {
            throw new RuntimeException("Failed to get a server socket point");
        }

        return serverPort;
    }
}
