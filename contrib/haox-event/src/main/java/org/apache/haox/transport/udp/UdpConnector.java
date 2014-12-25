package org.apache.haox.transport.udp;

import org.apache.haox.event.AbstractEventHandler;
import org.apache.haox.event.Event;
import org.apache.haox.event.EventType;
import org.apache.haox.transport.Connector;
import org.apache.haox.transport.event.AddressEvent;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;

public class UdpConnector extends Connector {

    public UdpConnector() {
        this(new UdpTransportHandler());
    }

    public UdpConnector(UdpTransportHandler transportHandler) {
        super(transportHandler);

        setEventHandler(new AbstractEventHandler() {
            @Override
            protected void doHandle(Event event) throws Exception {
                if (event.getEventType() == UdpEventType.ADDRESS_CONNECT) {
                    doConnect((AddressEvent) event);
                }
            }

            @Override
            public EventType[] getInterestedEvents() {
                return new EventType[] {
                        UdpEventType.ADDRESS_CONNECT
                };
            }
        });
    }

    @Override
    protected void doConnect(InetSocketAddress sa) {
        AddressEvent event = UdpAddressEvent.createAddressConnectEvent(sa);
        dispatch(event);
    }

    private void doConnect(AddressEvent event) throws IOException {
        InetSocketAddress address = event.getAddress();
        DatagramChannel channel = DatagramChannel.open();
        channel.configureBlocking(false);
        channel.connect(address);

        channel.register(selector, SelectionKey.OP_READ | SelectionKey.OP_WRITE);

        UdpTransport transport = new UdpTransport(channel, address);
        onNewTransport(transport);
    }
}
