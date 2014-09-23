package org.haox.kerb.transport.accept;

import org.haox.kerb.event.Event;
import org.haox.kerb.event.EventType;
import org.haox.kerb.event.channel.UdpAddressBindEvent;
import org.haox.kerb.transport.UdpTransport;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.util.HashMap;
import java.util.Map;

public class UdpAcceptor extends Acceptor {
    private Map<InetSocketAddress, UdpTransport> transports;

    public UdpAcceptor() {
        super();
        this.transports = new HashMap<InetSocketAddress, UdpTransport>();
    }

    @Override
    protected void doListen(InetSocketAddress socketAddress) {
        UdpAddressBindEvent event = new UdpAddressBindEvent(socketAddress);
        getDispatcher().dispatch(event);
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
                transport = new UdpTransport(datagramChannel, fromAddress);
                transport.setDispatcher(getDispatcher());
                transports.put(fromAddress, transport);
            }
            transport.onInboundMessage(recvBuffer);
        }
    }

    @Override
    public void process(Event event) throws IOException {
        switch (event.getEventType()) {
            case UDP_ADDRESS_BIND:
                doBind((UdpAddressBindEvent) event);
        }
    }

    @Override
    public EventType[] getInterestedEvents() {
        return new EventType[] {
            EventType.UDP_ADDRESS_BIND
        };
    }

    private void doBind(UdpAddressBindEvent event) throws IOException {
        DatagramChannel serverSocketChannel = DatagramChannel.open();
        serverSocketChannel.configureBlocking(false);
        DatagramSocket serverSocket = serverSocketChannel.socket();
        serverSocket.bind(event.getAddress());
        serverSocketChannel.register(selector, SelectionKey.OP_READ);
    }

}
