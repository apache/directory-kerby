package org.haox.transport;

import org.haox.event.AbstractEventHandler;
import org.haox.event.Dispatcher;
import org.haox.event.Event;
import org.haox.event.EventType;
import org.haox.transport.event.TransportEventType;
import org.haox.transport.event.channel.TcpAddressConnectEvent;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;

public class TcpConnector extends Connector {

    public TcpConnector() {
        super();

        setEventHandler(new AbstractEventHandler() {
            @Override
            protected void doHandle(Event event) throws Exception {
                if (event.getEventType() ==  TransportEventType.TCP_ADDRESS_CONNECT) {
                    doConnect((TcpAddressConnectEvent) event);
                }
            }

            @Override
            public EventType[] getInterestedEvents() {
                return new TransportEventType[] {
                        TransportEventType.TCP_ADDRESS_CONNECT
                };
            }
        });
    }

    @Override
    protected void doConnect(InetSocketAddress sa) throws IOException {
        TcpAddressConnectEvent event = new TcpAddressConnectEvent(sa);
        dispatch(event);
    }

    private void doConnect(TcpAddressConnectEvent event) throws IOException {
        SocketChannel channel = SocketChannel.open();
        channel.configureBlocking(false);
        channel.connect(event.getAddress());
        channel.register(selector, SelectionKey.OP_CONNECT|SelectionKey.OP_READ|SelectionKey.OP_WRITE);
    }

    @Override
    protected void dealKey(SelectionKey selectionKey) throws IOException {
        if (selectionKey.isConnectable()) {
            doConnect(selectionKey);
        } else if (selectionKey.isReadable()) {
            doRead(selectionKey);
        } else if (selectionKey.isWritable()) {
            doWrite(selectionKey);
        }
    }

    void doConnect(SelectionKey key) throws IOException {
        SocketChannel channel = (SocketChannel) key.channel();
        if (channel.isConnectionPending()) {
            channel.finishConnect();
        }

        channel.register(selector, SelectionKey.OP_READ | SelectionKey.OP_WRITE);
        Transport transport = new TcpTransport(channel, true);
        key.attach(transport);
        onNewTransport(transport);
    }

    void doRead(SelectionKey selectionKey) throws IOException {
        TcpTransport transport = (TcpTransport) selectionKey.attachment();
        transport.onReadable();
        selectionKey.interestOps(SelectionKey.OP_WRITE);
    }

    void doWrite(SelectionKey selectionKey) throws IOException {
        TcpTransport transport = (TcpTransport) selectionKey.attachment();
        transport.onWriteable();
        selectionKey.interestOps(SelectionKey.OP_READ);
    }

}
