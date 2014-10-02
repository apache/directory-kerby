package org.haox.transport;

import org.haox.event.Dispatcher;
import org.haox.transport.buffer.SendBuffer;
import org.haox.transport.event.InboundMessageEvent;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

public abstract class Transport {
    private InetSocketAddress remoteAddress;
    private boolean isActive;
    private Dispatcher dispatcher;

    private SendBuffer sendBuffer;

    public Transport(InetSocketAddress remoteAddress, boolean isActive) {
        this.remoteAddress = remoteAddress;
        this.isActive = isActive;
        this.sendBuffer = new SendBuffer();
    }

    public void setDispatcher(Dispatcher dispatcher) {
        this.dispatcher = dispatcher;
    }

    public InetSocketAddress getRemoteAddress() {
        return remoteAddress;
    }

    public void sendMessage(ByteBuffer message) {
        handleOutboundMessage(message);
    }

    protected void onReadable() {

    }

    protected void onWriteable() throws IOException {
        if (! sendBuffer.isEmpty()) {
            ByteBuffer message = sendBuffer.read();
            sendOutMessage(message);
        }
    }

    protected void handleInboundMessage(ByteBuffer message) {
        dispatcher.dispatch(new InboundMessageEvent(this, message));
    }

    protected void handleOutboundMessage(ByteBuffer message) {
        sendBuffer.write(message);
    }

    protected abstract void sendOutMessage(ByteBuffer message) throws IOException;
}
