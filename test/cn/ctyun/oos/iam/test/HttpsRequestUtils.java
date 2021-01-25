package cn.ctyun.oos.iam.test;

import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class HttpsRequestUtils {
	
	public static HttpsURLConnection createConn(URL url, String method, Map<String, String> headers) throws Exception{
        
        SSLSocketFactory  ssf= MyX509TrustManager.getSSFactory();
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setSSLSocketFactory(ssf);
        conn.setRequestMethod(method);
        if (headers != null) {
            System.out.println("--------- Request headers ---------");
            for (String headerKey : headers.keySet()) {
//                System.out.println(headerKey + ": " + headers.get(headerKey));
                conn.setRequestProperty(headerKey, headers.get(headerKey));
            }
        }
        conn.setUseCaches(false);
        conn.setDoInput(true);
        conn.setDoOutput(true);
        return conn;
    }

}

class MyX509TrustManager   implements X509TrustManager {  
    
    public MyX509TrustManager(){}  
    @Override  
    public void checkClientTrusted(X509Certificate[] arg0, String arg1)  
            throws CertificateException {  
        // TODO Auto-generated method stub  
          
    }  
  
    @Override  
    public void checkServerTrusted(X509Certificate[] arg0, String arg1)  
            throws CertificateException {  
        // TODO Auto-generated method stub  
          
    }  
  
    @Override  
    public X509Certificate[] getAcceptedIssuers() {  
        // TODO Auto-generated method stub  
        return null;  
    }  
      
    public static SSLSocketFactory getSSFactory() throws NoSuchAlgorithmException, NoSuchProviderException, KeyManagementException{  
        TrustManager[] tm = { new MyX509TrustManager()};  
        SSLContext sslContext = SSLContext.getInstance("SSL", "SunJSSE");  
        sslContext.init(null, tm, new java.security.SecureRandom());  
        SSLSocketFactory ssf = sslContext.getSocketFactory();  
        return  ssf;  
    }  
    
}
