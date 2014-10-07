package org.haox.transport;

import org.haox.event.AbstractEventHandler;

import java.io.IOException;
import java.nio.channels.SelectionKey;

/**
 * Handling readable and writable events
 */
public abstract class TransportHandler extends AbstractEventHandler {

    public abstract void helpHandleSelectionKey(SelectionKey selectionKey) throws IOException;

}
