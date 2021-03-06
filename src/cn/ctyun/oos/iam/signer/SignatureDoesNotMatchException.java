package cn.ctyun.oos.iam.signer;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

import com.amazonaws.services.s3.internal.XmlWriter;

import cn.ctyun.common.BaseException;
import cn.ctyun.common.Consts;

public class SignatureDoesNotMatchException  extends BaseException {
    
    private static final long serialVersionUID = -3975058122395535975L;
    
    public String aWSAccessKeyId = "";
    public String stringToSign = "";
    public String signatureProvided= "";
    public String stringToSignBytes= "";
    
    public SignatureDoesNotMatchException(int status, String message, String reqId, String resource,
            String aWSAccessKeyId, String stringToSign,String signatureProvided, String stringToSignBytes) {
        this.code = "SignatureDoesNotMatch";
        this.status = status;
        this.message = message;
        this.reqId = reqId;
        this.resource = resource;
        this.aWSAccessKeyId = aWSAccessKeyId;
        this.stringToSign = stringToSign;
        this.signatureProvided = signatureProvided;
        this.stringToSignBytes = stringToSignBytes;
    }
    
    public XmlWriter toXmlWriter() throws UnsupportedEncodingException {
        XmlWriter xml = new XmlWriter();
        xml.start("Error");
        xml.start("Code").value(code).end();
        xml.start("Message").value(message).end();
        xml.start("AWSAccessKeyId").value(aWSAccessKeyId).end();
        xml.start("StringToSign").value(stringToSign).end();
        xml.start("SignatureProvided").value(signatureProvided).end();
        xml.start("StringToSignBytes").value(stringToSignBytes).end();
        xml.start("Resource").value(URLDecoder.decode(resource, Consts.STR_UTF8)).end();
        xml.start("RequestId").value(reqId).end();
        xml.start("HostId").value(domain).end();
        xml.end();
        return xml;
    }
}
