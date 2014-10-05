package org.haox;

import junit.framework.Assert;
import org.haox.event.*;
import org.haox.transport.Connector;
import org.haox.transport.Transport;
import org.haox.transport.event.MessageEvent;
import org.haox.transport.udp.UdpConnector;
import org.haox.transport.event.TransportEvent;
import org.haox.transport.event.TransportEventType;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.Iterator;
import java.util.Set;

public class TestUdpClient extends TestUdpBase {

    private EventHub eventHub;
    private EventWaiter eventWaiter;

    @Before
    public void setUp() throws IOException {
        setUpServer();
        setUpClient();
    }

    private void setUpServer() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    doRunServer();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }).start();
    }

    private void doRunServer() throws IOException {
        DatagramChannel serverSocketChannel;
        Selector selector = Selector.open();
        serverSocketChannel = DatagramChannel.open();
        serverSocketChannel.configureBlocking(false);
        DatagramSocket serverSocket = serverSocketChannel.socket();
        serverSocket.bind(new InetSocketAddress(serverPort));
        serverSocketChannel.register(selector, SelectionKey.OP_READ);

        while (true) {
            if (selector.selectNow() > 0) {
                Set<SelectionKey> selectionKeys = selector.selectedKeys();
                Iterator<SelectionKey> iterator = selectionKeys.iterator();
                while (iterator.hasNext()) {
                    SelectionKey selectionKey = iterator.next();
                    iterator.remove();
                    if (selectionKey.isReadable()) {
                        ByteBuffer recvBuffer = ByteBuffer.allocate(65536);
                        InetSocketAddress fromAddress = (InetSocketAddress) serverSocketChannel.receive(recvBuffer);
                        if (fromAddress != null) {
                            recvBuffer.flip();
                            serverSocketChannel.send(recvBuffer, fromAddress);
                        }
                    }
                }

                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private void setUpClient() throws IOException {
        eventHub = new EventHub();

        EventHandler messageHandler = new AbstractEventHandler() {
            @Override
            protected void doHandle(Event event) throws Exception {
                MessageEvent msgEvent = (MessageEvent) event;
                if (msgEvent.getEventType() == TransportEventType.INBOUND_MESSAGE) {
                    ByteBuffer buffer = msgEvent.getMessage();
                    clientRecvedMessage = recvBuffer2String(buffer);
                    System.out.println("Recved clientRecvedMessage: " + clientRecvedMessage);
                    Boolean result = TEST_MESSAGE.equals(clientRecvedMessage);
                    dispatch(new Event(TestEventType.FINISHED, result));
                }
            }

            @Override
            public EventType[] getInterestedEvents() {
                return new EventType[] {
                        TransportEventType.INBOUND_MESSAGE
                };
            }
        };
        eventHub.register(messageHandler);

        Connector connector = new UdpConnector();
        eventHub.register(connector);

        eventWaiter = eventHub.waitEvent(
                TestEventType.FINISHED,
                TransportEventType.NEW_TRANSPORT);

        eventHub.start();
        connector.connect(serverHost, serverPort);
    }

    @Test
    public void testUdpTransport() {
        Event event = eventWaiter.waitEvent(TransportEventType.NEW_TRANSPORT);
        Transport transport = ((TransportEvent) event).getTransport();
        transport.sendMessage(ByteBuffer.wrap(TEST_MESSAGE.getBytes()));

        event = eventWaiter.waitEvent(TestEventType.FINISHED);
        Assert.assertTrue((Boolean) event.getEventData());
    }

    @After
    public void cleanup() {
        eventHub.stop();
    }
}
