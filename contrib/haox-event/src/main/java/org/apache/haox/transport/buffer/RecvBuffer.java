package org.apache.haox.transport.buffer;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.Iterator;
import java.util.LinkedList;

public class RecvBuffer {

    private LinkedList<ByteBuffer> bufferQueue;

    public RecvBuffer() {
        bufferQueue = new LinkedList<ByteBuffer>();
    }

    public synchronized void write(ByteBuffer buffer) {
        bufferQueue.addLast(buffer);
    }

    /**
     * Put buffer as the first into the buffer queue
     */
    public synchronized void writeFirst(ByteBuffer buffer) {
        bufferQueue.addFirst(buffer);
    }

    /**
     * Read and return the first buffer if available
     */
    public synchronized ByteBuffer readFirst() {
        if (! bufferQueue.isEmpty()) {
            return bufferQueue.removeFirst();
        }
        return null;
    }

    /**
     * Read most available bytes into the dst buffer
     */
    public synchronized ByteBuffer readMostBytes() {
        int len = remaining();
        return readBytes(len);
    }

    /**
     * Read len bytes into the dst buffer if available
     */
    public synchronized ByteBuffer readBytes(int len) {
        if (remaining() < len) { // no enough data that's available
            throw new BufferOverflowException();
        }

        ByteBuffer result = null;

        ByteBuffer takenBuffer;
        if (bufferQueue.size() == 1) {
            takenBuffer = bufferQueue.removeFirst();

            if (takenBuffer.remaining() == len) {
                return takenBuffer;
            }

            result = BufferPool.allocate(len);
            for (int i = 0; i < len; i++) {
                result.put(takenBuffer.get());
            }
            // Has left bytes so put it back for future reading
            if (takenBuffer.remaining() > 0) {
                bufferQueue.addFirst(takenBuffer);
            }
        } else {
            result = BufferPool.allocate(len);

            Iterator<ByteBuffer> iter = bufferQueue.iterator();
            int alreadyGot = 0, toGet;
            while (iter.hasNext()) {
                takenBuffer = iter.next();
                iter.remove();

                toGet = takenBuffer.remaining() < len - alreadyGot ?
                    takenBuffer.remaining() : len -alreadyGot;
                byte[] toGetBytes = new byte[toGet];
                takenBuffer.get(toGetBytes);
                result.put(toGetBytes);

                if (takenBuffer.remaining() > 0) {
                    bufferQueue.addFirst(takenBuffer);
                }

                alreadyGot += toGet;
                if (alreadyGot == len) {
                    break;
                }
            }
        }
        result.flip();

        return result;
    }

    public boolean isEmpty() {
        return bufferQueue.isEmpty();
    }

    /**
     * Return count of remaining and left bytes that's available
     */
    public int remaining() {
        if (bufferQueue.isEmpty()) {
            return 0;
        } else if (bufferQueue.size() == 1) {
            return bufferQueue.getFirst().remaining();
        }

        int result = 0;
        Iterator<ByteBuffer> iter = bufferQueue.iterator();
        while (iter.hasNext()) {
            result += iter.next().remaining();
        }
        return result;
    }

    public synchronized void clear() {
        if (bufferQueue.isEmpty()) {
            return;
        } else if (bufferQueue.size() == 1) {
            BufferPool.release(bufferQueue.getFirst());
        }

        Iterator<ByteBuffer> iter = bufferQueue.iterator();
        while (iter.hasNext()) {
            BufferPool.release(iter.next());
        }
        bufferQueue.clear();
    }
}
