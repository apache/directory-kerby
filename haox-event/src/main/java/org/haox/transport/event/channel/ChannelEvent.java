package org.haox.transport.event.channel;

import org.haox.event.Event;
import org.haox.transport.event.TransportEventType;

import java.nio.channels.SelectableChannel;

public abstract class ChannelEvent extends Event {

    private SelectableChannel channel;

    public ChannelEvent(SelectableChannel channel, TransportEventType eventType) {
        super(eventType);
        this.channel = channel;
    }

    public SelectableChannel getChannel() {
        return channel;
    }
}
