package org.haox.transport.udp;

import org.haox.event.AbstractEventHandler;
import org.haox.event.Event;
import org.haox.event.EventType;
import org.haox.transport.Acceptor;
import org.haox.transport.event.AddressEvent;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;

public class UdpAcceptor extends Acceptor {

    private DatagramChannel serverChannel;

    public UdpAcceptor() {
        this(new UdpTransportHandler());
    }

    public UdpAcceptor(UdpTransportHandler udpTransportHandler) {
        super(udpTransportHandler);

        setEventHandler(new AbstractEventHandler() {
            @Override
            protected void doHandle(Event event) throws Exception {
                if (event.getEventType() ==  UdpEventType.ADDRESS_BIND) {
                    doBind((AddressEvent) event);
                }
            }

            @Override
            public EventType[] getInterestedEvents() {
                return new EventType[] {
                        UdpEventType.ADDRESS_BIND
                };
            }
        });
    }

    @Override
    protected void doListen(InetSocketAddress socketAddress) {
        AddressEvent event = UdpAddressEvent.createAddressBindEvent(socketAddress);
        dispatch(event);
    }

    private void doBind(AddressEvent event) throws IOException {
        serverChannel = DatagramChannel.open();
        serverChannel.configureBlocking(false);
        serverChannel.bind(event.getAddress());
        serverChannel.register(selector, SelectionKey.OP_READ);
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
