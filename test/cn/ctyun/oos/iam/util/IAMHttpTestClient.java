package cn.ctyun.oos.iam.util;

import java.io.OutputStream;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.io.IOUtils;

import cn.ctyun.oos.iam.test.HttpsRequestUtils;
import cn.ctyun.oos.iam.test.V4TestUtils;

/**
 * IAM HTTP 测试客户端
 * @author wangduo
 *
 */
public class IAMHttpTestClient {

    public static final String OOS_IAM_DOMAIN ="https://oos-cd-iam.ctyunapi.cn:9460/";
    public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
    public static final String regionName="cd";
    
    private String accessKey;
    private String secretKey;
    
    public IAMHttpTestClient(String accessKey, String secretKey) {
        this.accessKey = accessKey;
        this.secretKey = secretKey;
    }
    
    /**
     * 向IAM Server发起一个post请求
     * @param body
     * @return
     * @throws Exception
     */
    public String post(String body) throws Exception {
        
        URL url = new URL(OOS_IAM_DOMAIN);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        
        String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, url, "POST", "sts", regionName);
        headers.put("Authorization", authorization);
        
        HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
        OutputStream out = connection.getOutputStream();
        out.write(body.getBytes());
        out.flush();
        String xml = IOUtils.toString(connection.getInputStream());
        out.close();        
        if (connection != null) {
            connection.disconnect();
        }
        return xml;
    }
}
