package org.haox.transport.tcp;

import org.haox.event.AbstractEventHandler;
import org.haox.event.Event;
import org.haox.event.EventType;
import org.haox.transport.event.AddressEvent;
import org.haox.transport.Connector;
import org.haox.transport.Transport;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;

public class TcpConnector extends Connector {

    public TcpConnector(StreamingDecoder streamingDecoder) {
        super(new TcpTransportHandler(streamingDecoder));

        setEventHandler(new AbstractEventHandler() {
            @Override
            protected void doHandle(Event event) throws Exception {
                if (event.getEventType() ==  TcpEventType.ADDRESS_CONNECT) {
                    doConnect((AddressEvent) event);
                }
            }

            @Override
            public EventType[] getInterestedEvents() {
                return new EventType[] {
                        TcpEventType.ADDRESS_CONNECT
                };
            }
        });
    }

    @Override
    protected void doConnect(InetSocketAddress sa) throws IOException {
        AddressEvent event = TcpAddressEvent.createAddressConnectEvent(sa);
        dispatch(event);
    }

    private void doConnect(AddressEvent event) throws IOException {
        SocketChannel channel = SocketChannel.open();
        channel.configureBlocking(false);
        channel.connect(event.getAddress());
        channel.register(selector,
                SelectionKey.OP_CONNECT | SelectionKey.OP_READ | SelectionKey.OP_WRITE);
    }

    @Override
    protected void dealKey(SelectionKey selectionKey) throws IOException {
        if (selectionKey.isConnectable()) {
            doConnect(selectionKey);
        } else {
            super.dealKey(selectionKey);
        }
    }

    void doConnect(SelectionKey key) throws IOException {
        SocketChannel channel = (SocketChannel) key.channel();
        if (channel.isConnectionPending()) {
            channel.finishConnect();
        }

        channel.register(selector, SelectionKey.OP_READ | SelectionKey.OP_WRITE);
        Transport transport = new TcpTransport(channel,
                ((TcpTransportHandler) transportHandler).getStreamingDecoder());
        key.attach(transport);
        onNewTransport(transport);
    }
}
