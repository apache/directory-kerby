package org.haox.transport.event.channel;

import org.haox.transport.event.TransportEventType;

import java.nio.channels.SelectableChannel;

public abstract class ChannelAcceptEvent extends ChannelEvent {

    public ChannelAcceptEvent(SelectableChannel channel) {
        super(channel, TransportEventType.CHANNEL_ACCEPT);
    }
}
