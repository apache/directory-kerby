package org.haox.kerb.event.channel;

import org.haox.kerb.event.EventType;

import java.nio.channels.SelectableChannel;

public abstract class ChannelAcceptEvent extends ChannelEvent {

    public ChannelAcceptEvent(SelectableChannel channel) {
        super(channel, EventType.CHANNEL_ACCEPT);
    }
}
