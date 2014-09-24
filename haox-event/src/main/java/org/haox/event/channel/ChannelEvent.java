package org.haox.event.channel;

import org.haox.event.Event;
import org.haox.event.EventType;

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
