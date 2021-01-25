package cn.ctyun.oos.iam.test.oosaccesscontrol;

import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Map;
import org.apache.commons.lang.time.DateUtils;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.amazonaws.HttpMethod;
import com.amazonaws.SDKGlobalConfiguration;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.GeneratePresignedUrlRequest;
import com.sun.net.ssl.HostnameVerifier;

public class PreUtils {

	public static HttpURLConnection getPreUrlHttpConn(String bucketName, String objectName, String method,
			String accessKey, String secretKey, Map<String, String> querys, Map<String, String> headers,
			String signVersion, String host, int jettyport) {
		URL url = generateUrl(method, accessKey, secretKey, host, jettyport, bucketName, objectName, signVersion,
				querys);
		String preurlstr = url.toString().replace("https", "http");
		System.out.println(preurlstr);
		HttpURLConnection conn = null;
		try {
			URL preurl = new URL(preurlstr);
			conn = (HttpURLConnection) preurl.openConnection();
			conn.setUseCaches(false);
			conn.setDoOutput(true);
			conn.setRequestMethod(method);
			if (headers != null) {
				System.out.println("--------- Request headers ---------");
				for (String headerKey : headers.keySet()) {
//	                System.out.println(headerKey + ": " + headers.get(headerKey));
					conn.setRequestProperty(headerKey, headers.get(headerKey));
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return conn;
	}

	public static HttpURLConnection getPreUrlHttpsConn(String bucketName, String objectName, String method,
			String accessKey, String secretKey, Map<String, String> querys, Map<String, String> headers,
			String signVersion, String host, int jettyport) {
		URL url = generateUrl(method, accessKey, secretKey, host, jettyport, bucketName, objectName, signVersion,
				querys);
		System.out.println(url.toString());
		HttpsURLConnection conn = null;
		SSLContext sc;
		try {
			sc = SSLContext.getInstance("TLS");
			sc.init(null, trustAllCerts, null);
			HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
			conn = (HttpsURLConnection) url.openConnection();
			conn.setRequestMethod(method);
		} catch (Exception e) {
			e.printStackTrace();
		}

		if (headers != null) {
			System.out.println("--------- Request headers ---------");
			for (String headerKey : headers.keySet()) {
				conn.setRequestProperty(headerKey, headers.get(headerKey));
			}
		}
		conn.setUseCaches(false);
		conn.setDoInput(true);
		conn.setDoOutput(true);
		conn.setHostnameVerifier(new TrustAnyHostnameVerifier());
		return conn;
	}

	public static URL generateUrl(String method, String accessKey, String secretKey, String host, int jettyPort,
			String bucketName, String objectName, String signVersion, Map<String, String> querys) {

		AmazonS3 client = new AmazonS3Client(new AWSCredentials() {
			@Override
			public String getAWSAccessKeyId() {
				return accessKey;
			}

			@Override
			public String getAWSSecretKey() {
				return secretKey;
			}
		});
		client.setEndpoint(host + ":" + jettyPort);

		if ("PreV4".equals(signVersion)) {
			System.setProperty(SDKGlobalConfiguration.ENABLE_S3_SIGV4_SYSTEM_PROPERTY, "true");
		} else {
			System.setProperty(SDKGlobalConfiguration.ENABLE_S3_SIGV4_SYSTEM_PROPERTY, "false");
		}
		GeneratePresignedUrlRequest gpur = new GeneratePresignedUrlRequest(bucketName, objectName);
		switch (method) {
		case "PUT":
			gpur.setMethod(HttpMethod.PUT);
			break;
		case "GET":
			gpur.setMethod(HttpMethod.GET);
			break;
		case "HEAD":
			gpur.setMethod(HttpMethod.HEAD);
			break;
		case "DELETE":
			gpur.setMethod(HttpMethod.DELETE);
			break;
		case "POST":
			gpur.setMethod(HttpMethod.POST);
			break;
		default:
			System.out.println(method);
			break;
		}
		Date expire = DateUtils.addDays(new Date(), 5);
		gpur.setExpiration(expire);
		if (null != querys) {
			for (String key : querys.keySet()) {
				gpur.addRequestParameter(key, querys.get(key));
			}
		}
		URL url = client.generatePresignedUrl(gpur);
		return url;
	}

	// 定制Trust
	static TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {

		@Override
		public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType)
				throws CertificateException {
		}

		@Override
		public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType)
				throws CertificateException {
		}

		@Override
		public java.security.cert.X509Certificate[] getAcceptedIssuers() {
			return null;
		}

	} };

}

//定制Verifier
class TrustAnyHostnameVerifier implements HostnameVerifier, javax.net.ssl.HostnameVerifier {

	public boolean verify(String hostname, SSLSession session) {
		return true;
	}

	@Override
	public boolean verify(String arg0, String arg1) {
		// TODO Auto-generated method stub
		return true;
	}

}
