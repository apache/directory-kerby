package org.haox.event.channel;

import org.haox.event.EventType;

import java.nio.channels.SelectableChannel;

public abstract class ChannelAcceptEvent extends ChannelEvent {

    public ChannelAcceptEvent(SelectableChannel channel) {
        super(channel, EventType.CHANNEL_ACCEPT);
    }
}
