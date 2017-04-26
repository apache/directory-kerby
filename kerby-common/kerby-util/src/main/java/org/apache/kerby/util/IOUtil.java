/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.kerby.util;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.WritableByteChannel;
import java.nio.file.Files;

/**
 * Some IO and file related utilities.
 */
public final class IOUtil {
    private IOUtil() { }

    public static byte[] readInputStream(InputStream in) throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[1024];
            int length = 0;
            while ((length = in.read(buffer)) != -1) {
                baos.write(buffer, 0, length);
            }
            in.close();
            return baos.toByteArray();
        }
    }

    public static void readInputStream(InputStream in,
                                       byte[] buf) throws IOException {
        int toRead = buf.length;
        int off = 0;
        while (toRead > 0) {
            int ret = in.read(buf, off, toRead);
            if (ret < 0) {
                throw new IOException("Bad inputStream, premature EOF");
            }
            toRead -= ret;
            off += ret;
        }
        in.close();
    }

    /**
     * Read an input stream and return the content as string assuming UTF8.
     * @param in The input stream
     * @return The read String
     * @return The content
     * @throws IOException e
     */
    public static String readInput(InputStream in) throws IOException {
        byte[] content = readInputStream(in);
        return Utf8.toString(content);
    }

    /**
     * Read a file and return the content as string assuming UTF8.
     * @param file The file to read
     * @return The content as a UTF-8 String
     * @throws IOException If an error occurred
     */
    public static String readFile(File file) throws IOException {
        long len = 0;
        if (file.length() >= Integer.MAX_VALUE) {
            throw new IOException("Too large file, unexpected!");
        } else {
            len = file.length();
        }
        byte[] buf = new byte[(int) len];

        InputStream is = Files.newInputStream(file.toPath());
        readInputStream(is, buf);

        return Utf8.toString(buf);
    }

    /**
     * Write a file with the content assuming UTF8.
     * @param content The content
     * @param file The file to write
     * @throws IOException e
     */
    public static void writeFile(String content, File file) throws IOException {
        OutputStream outputStream = Files.newOutputStream(file.toPath());
        WritableByteChannel channel = Channels.newChannel(outputStream);

        ByteBuffer buffer = ByteBuffer.wrap(Utf8.toBytes(content));
        channel.write(buffer);
        outputStream.close();
    }
}
