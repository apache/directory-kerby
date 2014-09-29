package org.haox;

import junit.framework.Assert;
import org.haox.event.Event;
import org.haox.event.EventHub;
import org.haox.event.InternalEventHandler;
import org.haox.transport.*;
import org.haox.transport.event.MessageEvent;
import org.haox.transport.event.TransportEventType;
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
                        ByteBuffer recvBuffer = ByteBuffer.allocate(65536); // to optimize
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
        EventHub eventHub = new EventHub();

        MessageHandler messageHandler = new MessageHandler(eventHub) {
            @Override
            protected void doHandle(Event event) throws Exception {
                MessageEvent msgEvent = (MessageEvent) event;
                if (msgEvent.getEventType() == TransportEventType.INBOUND_MESSAGE) {
                    ByteBuffer buffer = msgEvent.getMessage().getContent();
                    clientRecvedMessage = recvBuffer2String(buffer);
                    System.out.println("Recved clientRecvedMessage: " + clientRecvedMessage);
                } else if (msgEvent.getEventType() == TransportEventType.OUTBOUND_MESSAGE) {
                    msgEvent.getTransport().sendMessage(msgEvent.getMessage());
                }
            }
        };
        eventHub.register(messageHandler);

        Connector connector = new UdpConnector(eventHub);
        eventHub.register((InternalEventHandler) connector);
        TransportHandler transportHandler = new TransportHandler(eventHub) {
            @Override
            protected void onNewTransport(Transport transport) {
                transport.sendMessage(new Message(ByteBuffer.wrap(TEST_MESSAGE.getBytes())));
            }
        };
        eventHub.register(transportHandler);

        eventHub.start();
        connector.connect(serverHost, serverPort);
    }

    @Test
    public void testUdpTransport() throws IOException, InterruptedException {
        while (true) {
            if (clientRecvedMessage == null) {
                Thread.sleep(1000);
            } else {
                System.out.println("Got clientRecvedMessage: " + clientRecvedMessage);
                break;
            }
        }
        Assert.assertEquals(TEST_MESSAGE, clientRecvedMessage);
    }
}
