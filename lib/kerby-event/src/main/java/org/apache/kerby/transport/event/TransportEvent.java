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
package org.apache.kerby.transport.event;

import org.apache.kerby.event.Event;
import org.apache.kerby.event.EventType;
import org.apache.kerby.transport.Transport;

public class TransportEvent extends Event {

    private Transport transport;

    public TransportEvent(Transport transport, EventType eventType) {
        super(eventType);
        this.transport = transport;
    }

    public TransportEvent(Transport transport, EventType eventType, Object eventData) {
        super(eventType, eventData);
        this.transport = transport;
    }

    public Transport getTransport() {
        return transport;
    }

    public static TransportEvent createWritableTransportEvent(Transport transport) {
        return new TransportEvent(transport, TransportEventType.TRANSPORT_WRITABLE);
    }

    public static TransportEvent createReadableTransportEvent(Transport transport) {
        return new TransportEvent(transport, TransportEventType.TRANSPORT_READABLE);
    }

    public static TransportEvent createNewTransportEvent(Transport transport) {
        return new TransportEvent(transport, TransportEventType.NEW_TRANSPORT);
    }

}
