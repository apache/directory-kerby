package org.haox.event;

import org.haox.transport.buffer.RecvBuffer;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;

public class TestBuffer {

    @Test
    public void testRecvBuffer() {
        String testString = "HELLO WORLD";
        ByteBuffer testMessage = ByteBuffer.wrap(testString.getBytes());
        ByteBuffer tmp;

        RecvBuffer testBuffer = new RecvBuffer();
        testBuffer.write(testMessage);
        tmp = testBuffer.readMostBytes();
        Assert.assertArrayEquals(testString.getBytes(), tmp.array());

        int nTimes = 10;
        testBuffer.clear();
        for (int i = 0; i < nTimes; ++i) {
            testBuffer.write(ByteBuffer.wrap(testString.getBytes()));
        }
        int expectedBytes = nTimes * testMessage.limit();
        tmp = testBuffer.readMostBytes();
        Assert.assertEquals(expectedBytes, tmp.limit());
    }
}
