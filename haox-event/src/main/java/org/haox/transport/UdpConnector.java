package org.haox.transport;

import org.haox.event.AbstractEventHandler;
import org.haox.event.Dispatcher;
import org.haox.event.Event;
import org.haox.event.EventType;
import org.haox.transport.event.TransportEventType;
import org.haox.transport.event.channel.UdpAddressConnectEvent;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.util.HashMap;
import java.util.Map;

public class UdpConnector extends Connector {

    private Map<InetSocketAddress, UdpTransport> transports;

    public UdpConnector() {
        super();
        this.transports = new HashMap<InetSocketAddress, UdpTransport>();

        setEventHandler(new AbstractEventHandler() {
            @Override
            protected void doHandle(Event event) throws Exception {
                if (event.getEventType() == TransportEventType.UDP_ADDRESS_CONNECT) {
                    doConnect((UdpAddressConnectEvent) event);
                }
            }

            @Override
            public EventType[] getInterestedEvents() {
                return new EventType[] {
                        TransportEventType.UDP_ADDRESS_CONNECT
                };
            }
        });
    }

    @Override
    protected void doConnect(InetSocketAddress sa) throws IOException {
        UdpAddressConnectEvent event = new UdpAddressConnectEvent(sa);
        dispatch(event);
    }

    private void doConnect(UdpAddressConnectEvent event) throws IOException {
        InetSocketAddress address = event.getAddress();
        DatagramChannel channel = DatagramChannel.open();
        channel.configureBlocking(false);
        channel.connect(address);

        channel.register(selector, SelectionKey.OP_READ | SelectionKey.OP_WRITE);

        UdpTransport transport = new UdpTransport(channel, address, true);
        transports.put(address, transport);
        onNewTransport(transport);
    }

    @Override
    protected void dealKey(SelectionKey selectionKey) throws IOException {
        DatagramChannel channel =
                (DatagramChannel) selectionKey.channel();

        if (selectionKey.isReadable()) {
            doRead(channel);
        } else if (selectionKey.isWritable()) {
            doWrite(channel);
        }
    }

    private void doRead(DatagramChannel channel) throws IOException {
        ByteBuffer recvBuffer = ByteBuffer.allocate(65536); // to optimize
        InetSocketAddress fromAddress = (InetSocketAddress) channel.receive(recvBuffer);
        if (fromAddress != null) {
            recvBuffer.flip();
            UdpTransport transport = transports.get(fromAddress);
            if (transport == null) {
                throw new RuntimeException("Unexpected message from unknown transport of " + fromAddress);
            }
            transport.onInboundMessage(recvBuffer);
        }
    }

    private void doWrite(DatagramChannel channel) throws IOException {
        for (UdpTransport transport : transports.values()) {
            transport.onWriteable();
        }
    }
}
