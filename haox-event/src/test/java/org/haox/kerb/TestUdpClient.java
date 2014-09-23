package org.haox.kerb;

import junit.framework.Assert;
import org.haox.kerb.dispatch.AsyncDispatcher;
import org.haox.kerb.event.Event;
import org.haox.kerb.event.EventType;
import org.haox.kerb.event.MessageEvent;
import org.haox.kerb.handler.AsyncMessageHandler;
import org.haox.kerb.handler.AsyncTransportHandler;
import org.haox.kerb.handler.MessageHandler;
import org.haox.kerb.handler.TransportHandler;
import org.haox.kerb.message.Message;
import org.haox.kerb.transport.Transport;
import org.haox.kerb.transport.connect.Connector;
import org.haox.kerb.transport.connect.UdpConnector;
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
        AsyncDispatcher clientDispatcher = new AsyncDispatcher();
        clientDispatcher.start();

        MessageHandler messageHandler = new MessageHandler() {
            @Override
            public void process(Event event) {
                MessageEvent msgEvent = (MessageEvent) event;
                if (msgEvent.getEventType() == EventType.NEW_INBOUND_MESSAGE) {
                    synchronized (TestUdpClient.this) {
                        ByteBuffer buffer = msgEvent.getMessage().getContent();
                        clientRecvedMessage = recvBuffer2String(buffer);
                        System.out.println("Recved clientRecvedMessage: " + clientRecvedMessage);
                    }
                } else if (msgEvent.getEventType() == EventType.NEW_OUTBOUND_MESSAGE) {
                    try {
                        msgEvent.getTransport().sendMessage(msgEvent.getMessage());
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        };
        clientDispatcher.register(new AsyncMessageHandler(messageHandler));

        Connector connector = new UdpConnector();
        clientDispatcher.register(connector);
        TransportHandler transportHandler = new TransportHandler() {
            @Override
            protected void onNewTransport(Transport transport) {
                synchronized (TestUdpClient.this) {
                    transport.postMessage(new Message(ByteBuffer.wrap(TEST_MESSAGE.getBytes())));
                }
            }
        };
        clientDispatcher.register(new AsyncTransportHandler(transportHandler));

        connector.connect(serverHost, serverPort);
    }

    @Test
    public void testUdpTransport() throws IOException, InterruptedException {
        while (true) {
            synchronized (this) {
                if (clientRecvedMessage == null) {
                    Thread.sleep(1000);
                } else {
                    System.out.println("Got clientRecvedMessage: " + clientRecvedMessage);
                    break;
                }
            }
        }
        Assert.assertEquals(TEST_MESSAGE, clientRecvedMessage);
    }
}
