package org.haox.transport.tcp;

import org.haox.event.Event;
import org.haox.event.EventType;
import org.haox.transport.Transport;
import org.haox.transport.event.TransportEventType;
import org.haox.transport.TransportHandler;
import org.haox.transport.event.TransportEvent;

import java.io.IOException;
import java.nio.channels.SelectionKey;

public class TcpTransportHandler extends TransportHandler {

    private StreamingDecoder streamingDecoder;

    public TcpTransportHandler(StreamingDecoder streamingDecoder) {
        this.streamingDecoder = streamingDecoder;
    }

    public StreamingDecoder getStreamingDecoder() {
        return streamingDecoder;
    }

    @Override
    public EventType[] getInterestedEvents() {
        return new TransportEventType[] {
                TransportEventType.TRANSPORT_READABLE,
                TransportEventType.TRANSPORT_WRITABLE
        };
    }

    @Override
    protected void doHandle(Event event) throws Exception {
        EventType eventType = event.getEventType();
        TransportEvent te = (TransportEvent) event;
        Transport transport = te.getTransport();
        if (eventType == TransportEventType.TRANSPORT_READABLE) {
            transport.onReadable();
        } else if (eventType == TransportEventType.TRANSPORT_WRITABLE) {
            transport.onWriteable();
        }
    }

    @Override
    public void helpHandleSelectionKey(SelectionKey selectionKey) throws IOException {
        if (selectionKey.isReadable()) {
            TcpTransport transport = (TcpTransport) selectionKey.attachment();
            dispatch(TransportEvent.createReadableTransportEvent(transport));
        } else if (selectionKey.isWritable()) {
            TcpTransport transport = (TcpTransport) selectionKey.attachment();
            dispatch(TransportEvent.createWritableTransportEvent(transport));
        }

        selectionKey.interestOps(SelectionKey.OP_WRITE | SelectionKey.OP_READ);
    }
}

