package cn.ctyun.oos.iam.accesscontroller;

import java.io.IOException;
import java.io.StringReader;

import org.jdom.Document;
import org.jdom.Element;
import org.jdom.JDOMException;
import org.jdom.input.SAXBuilder;
import org.xml.sax.InputSource;

import cn.ctyun.oos.iam.server.result.AccessKeyResult;

public class AccessKeyResultUtilsDev {

    public static AccessKeyResult convertToAccessKeyResult(String xml) throws JDOMException, IOException {
        StringReader sr = new StringReader(xml);
        InputSource is = new InputSource(sr);
        Document doc = (new SAXBuilder()).build(is);
        Element root = doc.getRootElement();
        Element accessKeyResultElement = root.getChild("CreateAccessKeyResult");
        Element accessKeyElement = accessKeyResultElement.getChild("AccessKey");
        AccessKeyResult accessKeyResult = new AccessKeyResult();
        accessKeyResult.accessKeyId = accessKeyElement.getChild("AccessKeyId").getValue();
        accessKeyResult.secretAccessKey = accessKeyElement.getChild("SecretAccessKey").getValue();
        return accessKeyResult;
    }
}
