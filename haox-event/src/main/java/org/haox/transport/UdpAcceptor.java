package org.haox.transport;

import org.haox.event.AbstractEventHandler;
import org.haox.event.Event;
import org.haox.event.EventType;
import org.haox.transport.event.TransportEventType;
import org.haox.transport.event.channel.UdpAddressBindEvent;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.util.HashMap;
import java.util.Map;

public class UdpAcceptor extends Acceptor {
    private DatagramChannel serverChannel;
    private Map<InetSocketAddress, UdpTransport> transports;

    public UdpAcceptor() {
        super();
        this.transports = new HashMap<InetSocketAddress, UdpTransport>();

        setEventHandler(new AbstractEventHandler() {
            @Override
            protected void doHandle(Event event) throws Exception {
                if (event.getEventType() ==  TransportEventType.UDP_ADDRESS_BIND) {
                    doBind((UdpAddressBindEvent) event);
                }
            }

            @Override
            public EventType[] getInterestedEvents() {
                return new TransportEventType[] {
                        TransportEventType.UDP_ADDRESS_BIND
                };
            }
        });
    }

    @Override
    protected void doListen(InetSocketAddress socketAddress) {
        UdpAddressBindEvent event = new UdpAddressBindEvent(socketAddress);
        dispatch(event);
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
                transport = new UdpTransport(channel, fromAddress, false);
                transports.put(fromAddress, transport);
                onNewTransport(transport);
            }
            transport.onInboundMessage(recvBuffer);
        }
    }

    private void doWrite(DatagramChannel channel) throws IOException {
        for (UdpTransport transport : transports.values()) {
            transport.onWriteable();
        }
    }

    private void doBind(UdpAddressBindEvent event) throws IOException {
        serverChannel = DatagramChannel.open();
        serverChannel.configureBlocking(false);
        serverChannel.bind(event.getAddress());
        serverChannel.register(selector, SelectionKey.OP_READ | SelectionKey.OP_WRITE);
    }

    @Override
    public void stop() {
        super.stop();

        try {
            serverChannel.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
