package org.haox.kerb.event.channel;

import org.haox.kerb.event.Event;
import org.haox.kerb.event.EventType;

import java.nio.channels.SelectableChannel;

public abstract class ChannelEvent extends Event {

    private SelectableChannel channel;

    public ChannelEvent(SelectableChannel channel, EventType eventType) {
        super(eventType);
        this.channel = channel;
    }

    public SelectableChannel getChannel() {
        return channel;
    }
}
