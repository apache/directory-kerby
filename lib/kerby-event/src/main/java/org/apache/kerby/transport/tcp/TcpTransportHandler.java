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
package org.apache.kerby.transport.tcp;

import org.apache.kerby.event.Event;
import org.apache.kerby.event.EventType;
import org.apache.kerby.transport.Transport;
import org.apache.kerby.transport.event.TransportEventType;
import org.apache.kerby.transport.TransportHandler;
import org.apache.kerby.transport.event.TransportEvent;

import java.io.IOException;
import java.nio.channels.SelectionKey;

public class TcpTransportHandler extends TransportHandler {

    private StreamingDecoder streamingDecoder;

    public TcpTransportHandler(StreamingDecoder streamingDecoder) {
        this.streamingDecoder = streamingDecoder;
    }

    public StreamingDecoder getStreamingDecoder() {
        return streamingDecoder;
    }

    @Override
    public EventType[] getInterestedEvents() {
        return new TransportEventType[] {
                TransportEventType.TRANSPORT_READABLE,
                TransportEventType.TRANSPORT_WRITABLE
        };
    }

    @Override
    protected void doHandle(Event event) throws Exception {
        EventType eventType = event.getEventType();
        TransportEvent te = (TransportEvent) event;
        Transport transport = te.getTransport();
        if (eventType == TransportEventType.TRANSPORT_READABLE) {
            transport.onReadable();
        } else if (eventType == TransportEventType.TRANSPORT_WRITABLE) {
            transport.onWriteable();
        }
    }

    @Override
    public void helpHandleSelectionKey(SelectionKey selectionKey) throws IOException {
        if (selectionKey.isReadable()) {
            selectionKey.interestOps(SelectionKey.OP_READ | SelectionKey.OP_WRITE);
            TcpTransport transport = (TcpTransport) selectionKey.attachment();
            dispatch(TransportEvent.createReadableTransportEvent(transport));
        } else if (selectionKey.isWritable()) {
            selectionKey.interestOps(SelectionKey.OP_READ);
            TcpTransport transport = (TcpTransport) selectionKey.attachment();
            dispatch(TransportEvent.createWritableTransportEvent(transport));
        }
    }
}

