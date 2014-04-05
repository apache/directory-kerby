package org.haox.config;

import java.io.*;
import java.net.URL;

public class Resource {
    public static enum Format {
        XML(XmlConfigLoader.class),
        INI(IniConfigLoader.class),
        JSON(JsonConfigLoader.class);

        private Class<? extends ConfigLoader> loaderClass;

        private Format(Class<? extends ConfigLoader> loaderClass) {
            this.loaderClass = loaderClass;
        }

        public Class<? extends ConfigLoader> getLoaderClass() {
            return loaderClass;
        }
    }

    private String name;
    private InputStream resourceStream;
    private Format format;

    public static Resource createXmlResource(File xmlFile) throws IOException {
        return new Resource(xmlFile.getName(), xmlFile, Format.XML);
    }

    public static Resource createIniResource(File iniFile) throws IOException {
        return new Resource(iniFile.getName(), iniFile, Format.INI);
    }

    public static Resource createJsonResource(File jsonFile) throws IOException {
        return new Resource(jsonFile.getName(), jsonFile, Format.JSON);
    }

    public static Resource createXmlResource(URL xmlUrl) throws IOException {
        return new Resource(xmlUrl, Format.XML);
    }

    public static Resource createIniResource(URL iniUrl) throws IOException {
        return new Resource(iniUrl, Format.INI);
    }

    public static Resource createJsonResource(URL jsonUrl) throws IOException {
        return new Resource(jsonUrl, Format.JSON);
    }

    private Resource(String name, File resourceFile, Format format) throws FileNotFoundException {
        this(name, new FileInputStream(resourceFile), format);
    }

    private Resource(URL resourceUrl, Format format) throws IOException {
        this(resourceUrl.toString(), resourceUrl.openStream(), format);
    }

    private Resource(String name, InputStream resourceStream, Format format) {
        this.name = name;
        this.resourceStream = resourceStream;
        this.format = format;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public InputStream getResourceStream() {
        return resourceStream;
    }

    public Format getFormat() {
        return format;
    }
}