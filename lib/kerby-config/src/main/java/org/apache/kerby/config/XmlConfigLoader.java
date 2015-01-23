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
package org.apache.kerby.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.*;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class XmlConfigLoader extends ConfigLoader {
    private static final Logger logger = LoggerFactory.getLogger(Config.class);

    @Override
    protected void loadConfig(ConfigImpl config, Resource resource) throws Exception {
        Element doc = loadResourceDocument(resource);
        loadConfig((ConfigImpl) config, doc);
    }

    private Element loadResourceDocument(Resource resource) throws Exception {
        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();

        docBuilderFactory.setIgnoringComments(true);
        docBuilderFactory.setNamespaceAware(true);
        try {
            docBuilderFactory.setXIncludeAware(true);
        } catch (UnsupportedOperationException e) {
            logger.error("Failed to set setXIncludeAware(true) for parser", e);
        }
        DocumentBuilder builder = docBuilderFactory.newDocumentBuilder();
        InputStream is = (InputStream) resource.getResource();
        Document doc = null;
        try {
            doc = builder.parse(is);
        } finally {
            is.close();
        }

        Element root = doc.getDocumentElement();
        validateConfig(root);

        return root;
    }

    private boolean validateConfig(Element root) {
        boolean valid = false;

        if ("config".equals(root.getTagName())) {
            valid = true;
        } else {
            logger.error("bad conf element: top-level element not <configuration>");
        }

        return valid;
    }

    private void loadConfig(ConfigImpl conifg, Element element) {
        String name;
        ConfigObject value;

        NodeList props = element.getChildNodes();
        for (int i = 0; i < props.getLength(); i++) {
            Node subNode = props.item(i);
            if (!(subNode instanceof Element)) {
                continue;
            }

            Element prop = (Element)subNode;
            name = getElementName(prop);
            if (name == null) {
                continue;
            }

            value = null;
            String tagName = prop.getTagName();
            if ("property".equals(tagName) && prop.hasChildNodes()) {
                value = loadProperty(prop);
            } else if ("config".equals(tagName) && prop.hasChildNodes()) {
                ConfigImpl cfg = new ConfigImpl(name);
                loadConfig(cfg, prop);
                value = new ConfigObject(cfg);
            }

            if (name != null) {
                conifg.set(name, value);
            }
        }
    }

    private static ConfigObject loadProperty(Element ele) {
        String value = null;
        if (ele.getFirstChild() instanceof Text) {
            value = ((Text)ele.getFirstChild()).getData();
            return new ConfigObject(value);
        }

        ConfigObject result = null;
        NodeList nodes = ele.getChildNodes();
        List<String> values = new ArrayList<String>(nodes.getLength());
        for (int i = 0; i < nodes.getLength(); i++) {
            value = null;
            Node valueNode = nodes.item(i);
            if (!(valueNode instanceof Element))
                continue;

            Element valueEle = (Element)valueNode;
            if ("value".equals(valueEle.getTagName()) && valueEle.hasChildNodes()) {
                value = ((Text)valueEle.getFirstChild()).getData();
            }

            if (value != null) {
                values.add(value);
            }
        }
        return new ConfigObject(values);
    }

    private static String getElementName(Element ele) {
        String name, value;
        Node node;
        Attr attr;

        NamedNodeMap nnm = ele.getAttributes();
        for (int i = 0; i < nnm.getLength(); ++i) {
            node = nnm.item(i);
            if (!(node instanceof Attr))
                continue;
            attr = (Attr) node;
            name = attr.getName();
            value = attr.getValue();

            if ("name".equals(name)) {
                return value;
            }
        }
        return null;
    }
}