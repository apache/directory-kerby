package org.haox.transport;

import org.haox.event.Dispatcher;
import org.haox.transport.event.InboundMessageEvent;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

public abstract class Transport {
    private InetSocketAddress remoteAddress;
    private boolean isActive;
    private Dispatcher dispatcher;

    private BlockingQueue<Message> outMessageQueue;

    public Transport(InetSocketAddress remoteAddress, boolean isActive) {
        this.remoteAddress = remoteAddress;
        this.isActive = isActive;
        this.outMessageQueue = new ArrayBlockingQueue<Message>(2);
    }

    public void setDispatcher(Dispatcher dispatcher) {
        this.dispatcher = dispatcher;
    }

    public InetSocketAddress getRemoteAddress() {
        return remoteAddress;
    }

    public void sendMessage(Message message) {
        handleOutboundMessage(message);
    }

    protected void onReadable() {

    }

    protected void onWriteable() throws IOException {
        if (! outMessageQueue.isEmpty()) {
            Message message = null;
            try {
                message = outMessageQueue.take();
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
            sendOutMessage(message);
        }
    }

    protected void handleInboundMessage(Message message) {
        dispatcher.dispatch(new InboundMessageEvent(this, message));
    }

    protected void handleOutboundMessage(Message message) {
        try {
            outMessageQueue.put(message);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    protected abstract void sendOutMessage(Message message) throws IOException;
}
