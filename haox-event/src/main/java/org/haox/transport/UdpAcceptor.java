package org.haox.transport;

import org.haox.event.AbstractEventHandler;
import org.haox.event.Dispatcher;
import org.haox.event.Event;
import org.haox.event.EventType;
import org.haox.transport.event.TransportEventType;
import org.haox.transport.event.channel.UdpAddressBindEvent;

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

    public UdpAcceptor(Dispatcher dispatcher) {
        super(dispatcher);
        this.transports = new HashMap<InetSocketAddress, UdpTransport>();

        setEventHandler(new AbstractEventHandler(dispatcher) {
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

    private void doBind(UdpAddressBindEvent event) throws IOException {
        DatagramChannel serverSocketChannel = DatagramChannel.open();
        serverSocketChannel.configureBlocking(false);
        DatagramSocket serverSocket = serverSocketChannel.socket();
        serverSocket.bind(event.getAddress());
        serverSocketChannel.register(selector, SelectionKey.OP_READ);
    }

}
