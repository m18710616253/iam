package cn.ctyun.oos.accesscontroller;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import cn.ctyun.oos.iam.test.V4TestUtils;

public class OOSTestUtilsDev {
	
	public static final String OOS_IAM_DOMAIN="http://oos-cd.ctyunapi.cn:8080/";
	public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
	public static final String regionName="cd";
	
	public static HttpURLConnection invokeHttpsRequest(URL url, String method,String accessKey,String secretKey) {
		return invokeHttpsRequest(url, method, accessKey, secretKey, null, null);
	}

	   public static HttpURLConnection invokeHttpsRequest(URL url, String method,String accessKey,String secretKey, Map<String, String> query) {
	        return invokeHttpsRequest(url, method, accessKey, secretKey, query, null);
	    }
	
   public static HttpURLConnection invokeHttpsRequest(URL url, String method,String accessKey,String secretKey, Map<String, String> query, Map<String, String> header) {
        try {
            Map<String, String> headers = new HashMap<String, String>();
            headers.put("Content-Type", "application/x-www-form-urlencoded");
            
            String authorization = V4TestUtils.computeSignature(headers, query, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                    url, method, "s3", regionName);
            headers.put("Authorization", authorization);
            if (header != null) {
                headers.putAll(header);
            }
            HttpURLConnection connection = createConn(url, method, headers);
            return connection;
            
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        
    }
	
	   public static HttpURLConnection createConn(URL url, String method, Map<String, String> headers) throws Exception{
	        
	        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
	        conn.setRequestMethod(method);
	        if (headers != null) {
	            System.out.println("--------- Request headers ---------");
	            for (String headerKey : headers.keySet()) {
//	                System.out.println(headerKey + ": " + headers.get(headerKey));
	                conn.setRequestProperty(headerKey, headers.get(headerKey));
	            }
	        }
	        conn.setUseCaches(false);
	        conn.setDoInput(true);
	        conn.setDoOutput(true);
	        return conn;
	    }
	
}



