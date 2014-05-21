package org.haox.kerb.transport.connect;

import org.haox.kerb.event.Event;
import org.haox.kerb.event.EventType;
import org.haox.kerb.event.channel.UdpAddressConnectEvent;
import org.haox.kerb.transport.UdpTransport;

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
    }

    @Override
    protected void doConnect(InetSocketAddress sa) throws IOException {
        UdpAddressConnectEvent event = new UdpAddressConnectEvent(sa);
        getDispatcher().dispatch(event);
    }

    @Override
    public void process(Event event) throws IOException {
        switch (event.getEventType()) {
            case UDP_ADDRESS_CONNECT:
                doConnect((UdpAddressConnectEvent) event);
        }
    }

    @Override
    public EventType[] getInterestedEvents() {
        return new EventType[] {
                EventType.UDP_ADDRESS_CONNECT
        };
    }

    private void doConnect(UdpAddressConnectEvent event) throws IOException {
        InetSocketAddress address = event.getAddress();
        DatagramChannel channel = DatagramChannel.open();
        channel.configureBlocking(false);
        channel.connect(address);

        channel.register(selector, SelectionKey.OP_READ);

        UdpTransport transport = new UdpTransport(channel, address, true);
        transports.put(address, transport);
        onNewTransport(transport);
    }

    @Override
    protected void dealKey(SelectionKey selectionKey) throws IOException {
        if (selectionKey.isReadable()) {
            doRead(selectionKey);
        }
    }

    private void doRead(SelectionKey selectionKey) throws IOException {
        DatagramChannel datagramChannel =
                (DatagramChannel) selectionKey.channel();
        ByteBuffer recvBuffer = ByteBuffer.allocate(65536); // to optimize
        InetSocketAddress fromAddress = (InetSocketAddress) datagramChannel.receive(recvBuffer);
        if (fromAddress != null) {
            recvBuffer.flip();
            UdpTransport transport = transports.get(fromAddress);
            if (transport == null) {
                throw new RuntimeException("Unexpected message from unknown transport of " + fromAddress);
            }
            transport.onInboundMessage(recvBuffer);
        }
    }
}
