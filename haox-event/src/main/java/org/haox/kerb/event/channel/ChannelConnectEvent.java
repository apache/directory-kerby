package org.haox.kerb.event.channel;

import org.haox.kerb.event.EventType;

import java.nio.channels.SelectableChannel;

public abstract class ChannelConnectEvent extends ChannelEvent {

    public ChannelConnectEvent(SelectableChannel channel) {
        super(channel, EventType.CHANNEL_CONNECT);
    }
}
