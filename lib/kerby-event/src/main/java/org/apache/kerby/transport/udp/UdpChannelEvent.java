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
package org.apache.kerby.transport.udp;

import org.apache.kerby.event.Event;
import org.apache.kerby.event.EventType;

import java.nio.channels.DatagramChannel;

public class UdpChannelEvent extends Event {

    private DatagramChannel channel;

    private UdpChannelEvent(DatagramChannel channel, EventType eventType) {
        super(eventType);
        this.channel = channel;
    }

    public DatagramChannel getChannel() {
        return channel;
    }

    public static UdpChannelEvent makeWritableChannelEvent(DatagramChannel channel) {
        return new UdpChannelEvent(channel, UdpEventType.CHANNEL_WRITABLE);
    }

    public static UdpChannelEvent makeReadableChannelEvent(DatagramChannel channel) {
        return new UdpChannelEvent(channel, UdpEventType.CHANNEL_READABLE);
    }
}
