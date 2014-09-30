package org.haox.transport.event.channel;

import org.haox.transport.event.TransportEventType;

import java.nio.channels.SelectableChannel;

public abstract class ChannelConnectEvent extends ChannelEvent {

    public ChannelConnectEvent(SelectableChannel channel) {
        super(channel, TransportEventType.CHANNEL_CONNECT);
    }
}
