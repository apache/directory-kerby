package org.haox.transport.udp;

import org.haox.event.Event;
import org.haox.event.EventType;

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
