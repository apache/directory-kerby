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
package org.apache.kerby.kerberos.kerb.codec.spnego;

import java.io.IOException;

public class SpnegoInitToken extends SpnegoToken {

    public static final int DELEGATION = 0x40;
    public static final int MUTUAL_AUTHENTICATION = 0x20;
    public static final int REPLAY_DETECTION = 0x10;
    public static final int SEQUENCE_CHECKING = 0x08;
    public static final int ANONYMITY = 0x04;
    public static final int CONFIDENTIALITY = 0x02;
    public static final int INTEGRITY = 0x01;

    private String[] mechanisms;
    private int contextFlags;

    public SpnegoInitToken(byte[] token) throws IOException {

    }

    public int getContextFlags() {
        return contextFlags;
    }

    public boolean getContextFlag(int flag) {
        return (getContextFlags() & flag) == flag;
    }

    public String[] getMechanisms() {
        return mechanisms;
    }

}
