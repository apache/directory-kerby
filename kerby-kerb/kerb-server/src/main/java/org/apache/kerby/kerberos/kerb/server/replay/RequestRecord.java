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
package org.apache.kerby.kerberos.kerb.server.replay;

public class RequestRecord {
    private String clientPrincipal;
    private String serverPrincipal;
    private long requestTime;
    private int microseconds;

    public RequestRecord(String clientPrincipal, String serverPrincipal, long requestTime, int microseconds) {
        this.clientPrincipal = clientPrincipal;
        this.serverPrincipal = serverPrincipal;
        this.requestTime = requestTime;
        this.microseconds = microseconds;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        RequestRecord that = (RequestRecord) o;

        if (microseconds != that.microseconds) return false;
        if (requestTime != that.requestTime) return false;
        if (!clientPrincipal.equals(that.clientPrincipal)) return false;
        if (!serverPrincipal.equals(that.serverPrincipal)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = clientPrincipal.hashCode();
        result = 31 * result + serverPrincipal.hashCode();
        result = 31 * result + (int) (requestTime ^ (requestTime >>> 32));
        result = 31 * result + microseconds;
        return result;
    }
}
