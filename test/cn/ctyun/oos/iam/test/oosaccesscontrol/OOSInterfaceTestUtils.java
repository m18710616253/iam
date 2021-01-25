package cn.ctyun.oos.iam.test.oosaccesscontrol;

import static org.junit.Assert.assertEquals;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.management.ObjectName;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.hdfs.qjournal.protocol.QJournalProtocolProtos.NewEpochRequestProto;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.amazonaws.AmazonClientException;
import com.amazonaws.auth.SigningAlgorithm;
import com.amazonaws.services.s3.internal.RestUtils;
import com.amazonaws.services.s3.internal.ServiceUtils;
import com.amazonaws.util.BinaryUtils;

import cn.ctyun.common.Consts;
import cn.ctyun.oos.iam.signer.OOSRequest;
import cn.ctyun.oos.iam.test.HttpsRequestUtils;
import cn.ctyun.oos.iam.test.V4TestUtils;
import common.time.TimeUtils;
import common.tuple.Pair;

public class OOSInterfaceTestUtils {
    static String HOST="oos-cd.ctyunapi.cn";
    static String HOST_OLDIAM="oos-cd-iam.ctyunapi.cn";
//    static int jettyPort=80;
    
    public static final String EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
    public static final String SCHEME = "AWS4";
    public static final String ALGORITHM = "HMAC-SHA256";
    public static final String TERMINATOR = "aws4_request";
    public static final String SERVICE_NAME = "s3";
    public static final String regionName="cd";
    
    static ContentType contentType = ContentType.create("text/plain", Consts.CS_UTF8);
    
    static SimpleDateFormat timeFormatter = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
    static SimpleDateFormat dateFormatter = new SimpleDateFormat("yyyyMMdd");
    
    
    public static Pair<Integer, String> Service_Get(String httpOrHttps,String signVersion, int jettyPort,String accessKey,String secretKey,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/";
        
        String method="GET";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, null, null, headers, null,EMPTY_BODY_SHA256,jettyPort);
   
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Region_Get(String httpOrHttps,String signVersion, int jettyPort,String accessKey,String secretKey,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/?regions";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("regions", "");
        String method="GET";
        
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, null, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);
        
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Bucket_Put(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,String bucketType,String metaregion,List<String> dateregions,String scheduleStrategy,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName;
        String method="PUT";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, null, headers, null,UNSIGNED_PAYLOAD,jettyPort);
        
        

            if (dateregions!=null&&dateregions.size()>0) {
                String body="<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">";
                if (metaregion!=null) {
                    String metaString="<MetadataLocationConstraint>\n" + 
                            "        <Location>"+metaregion+"</Location>\n" + 
                            "    </MetadataLocationConstraint >\n" + 
                            "";
                    body+=metaString;
                }
                
                String dateLocationString="";
                for (int i = 0; i < dateregions.size(); i++) {
                    dateLocationString+="<Location>"+dateregions.get(0)+"</Location>";
                }
                
                String regionTypeString="";
                if (bucketType!=null) {
                    regionTypeString="<Type>"+bucketType+"</Type>";
                }else {
                    regionTypeString="<Type>Local</Type>";
                }
                
                String scheduleStrategyString="";
                if (scheduleStrategy!=null) {
                    scheduleStrategyString="<ScheduleStrategy>"+scheduleStrategy+"</ScheduleStrategy>";
                }else {
                    scheduleStrategyString="<ScheduleStrategy>Allowed</ScheduleStrategy>";
                }
                
                String dateRegionString="<DataLocationConstraint>"+regionTypeString+"<LocationList>"+dateLocationString+"</LocationList>"+scheduleStrategyString+"</DataLocationConstraint>";
                
                body+=dateRegionString+"</CreateBucketConfiguration>";
                
                try {
                    OutputStream wr = conn.getOutputStream();
                    
                    wr.write(body.getBytes());
                    wr.flush();
                    wr.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            
            return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Bucket_GetLocation(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"?location";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("location", "");
        String method="GET";
        
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);
        
        return GetResult(conn);
    }
    
    public static Pair<Integer, String> Bucket_GetAcl(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"?acl";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("acl", "");
        String method="GET";
        
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);
        
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Bucket_Get(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName;
        String method="GET";
        
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, null, headers, null,EMPTY_BODY_SHA256,jettyPort);
        
        return GetResult(conn);
        
    }
    
    /*
     * 给普通用户list以自己ak开头的object
     */
    public static Pair<Integer, String> Bucket_GetPrefix(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"/?prefix="+accessKey;
        String method="GET";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("prefix", accessKey);
        
        HttpURLConnection conn=null;
        try {
            String canonicalString="";
            URL url = new URL(urlStr);
            if (headers==null) {
                headers = new HashMap<String, String>();
            }
            
            if (signVersion.equals("V4")) {
                System.out.println("V4");
                
                String authorization = V4TestUtils.computeSignature(headers, querys, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                        url, method, "s3", regionName);
                headers.put("Authorization", authorization);
                if (httpOrHttps.equals("https")) {
                    conn=HttpsRequestUtils.createConn(url, method, headers);
                    System.out.println(" url="+url.toString());
                }else {
                    conn=CreatehttpConn(url, method, headers);
                    System.out.println("url="+url.toString());
                }
                
            }else if (signVersion.startsWith("Pre")) {
                if("https".equals(httpOrHttps)) {
                    conn = PreUtils.getPreUrlHttpsConn(bucketName, null, method, accessKey, secretKey, querys, headers,signVersion,HOST,jettyPort);
                }else {
                    conn = PreUtils.getPreUrlHttpConn(bucketName, null, method, accessKey, secretKey, querys, headers,signVersion,HOST,jettyPort);
                }
            }else {
                System.out.println("V2");
                String date = TimeUtils.toGMTFormat(new Date());
                headers.put("Date", date);
                if (httpOrHttps.equals("https")) {
                    conn=HttpsRequestUtils.createConn(url, method, headers);
                    System.out.println("url="+url.toString());
                    
                }else {
                    conn=CreatehttpConn(url, method, headers);
                    System.out.println("url="+url.toString());
                }
                
                if (headers != null) {
                    for (String headerKey : headers.keySet()) {
                        conn.setRequestProperty(headerKey, headers.get(headerKey));
                    }
                }
                canonicalString = RestUtils.makeS3CanonicalString(method, 
                        toResourcePath(bucketName, null, true), new OOSRequest<>(conn), null);
                System.out.println("canonicalString=\r\n"+canonicalString);
                String signature = sign(canonicalString, secretKey, SigningAlgorithm.HmacSHA1);
                String authorization = "AWS " + accessKey + ":" + signature;
                conn.setRequestProperty("Authorization", authorization);  
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Bucket_Delete(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName;
        String method="DELETE";
        
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, null, headers, null,EMPTY_BODY_SHA256,jettyPort);
        
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Bucket_PutPolicy(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,String policyString,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"?policy";
        String method="PUT";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("policy", "");
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, null, headers, querys,UNSIGNED_PAYLOAD,jettyPort);
        
        try {
            OutputStream wr = conn.getOutputStream();
            
            wr.write(policyString.getBytes());
            wr.flush();
            wr.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return GetResult(conn);
    }
    
    public static Pair<Integer, String> Bucket_GetPolicy(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"?policy";
        String method="GET";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("policy", "");
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);
       
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Bucket_DeletePolicy(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"?policy";
        String method="DELETE";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("policy", "");
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);
       
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Bucket_PutWebsite(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"?website";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("website", "");
        
        String method="PUT";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, null, headers, querys,UNSIGNED_PAYLOAD,jettyPort);
        
        String websiteString="<WebsiteConfiguration xmlns='http://s3.amazonaws.com/doc/2006-03-01/'>\n" + 
                "<IndexDocument>\n" + 
                "<Suffix>index.html</Suffix>\n" + 
                "</IndexDocument>\n" + 
                "<ErrorDocument>\n" + 
                "<Key>404.html</Key>\n" + 
                "</ErrorDocument>\n" + 
                "</WebsiteConfiguration>\n" + 
                "";
        try {
            OutputStream wr = conn.getOutputStream();
            wr.write(websiteString.getBytes());
            wr.flush();
            wr.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Bucket_GetWebsite(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"?website";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("website", "");
        String method="GET";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);
        return GetResult(conn);
        
    }

    
    public static Pair<Integer, String> Bucket_DeleteWebsite(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"?website";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("website", "");
        String method="DELETE";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);

        return GetResult(conn);
    }
    
    public static Pair<Integer, String> Bucket_ListMultipartUploads(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"?uploads";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("uploads", "");
        String method="GET";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Bucket_PutLogging(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"?logging";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("logging", "");
        
        String method="PUT";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, null, headers, querys,UNSIGNED_PAYLOAD,jettyPort);
        
        String loggingString="<BucketLoggingStatus xmlns=\"http://doc.s3.amazonaws.com/2006-03-01\">\n" + 
                "<LoggingEnabled>\n" + 
                "<TargetBucket>"+bucketName+"</TargetBucket>\n" + 
                "<TargetPrefix>"+bucketName+"-access_log-/</TargetPrefix>\n" + 
                "</LoggingEnabled>\n" + 
                "</BucketLoggingStatus>\n" + 
                "";
        try {
            OutputStream wr = conn.getOutputStream();
            wr.write(loggingString.getBytes());
            wr.flush();
            wr.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Bucket_GetLogging(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"?logging";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("logging", "");
        String method="GET";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);
        return GetResult(conn);
        
    }
    
    public static int Bucket_Head(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName;
        String method="HEAD";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, null, headers, null,EMPTY_BODY_SHA256,jettyPort);
        int code=0 ;
        try {
            conn.connect();
            
            code = conn.getResponseCode();
        } catch (Exception e) {
            // TODO: handle exception
        }
        
        System.out.println("code="+code);
        
        return code;
        
    }
    
    public static Pair<Integer, String> Bucket_PutLifecycle(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String lifecycleString="<LifecycleConfiguration>\n" + 
                "    <Rule>\n" + 
                "        <ID>test_lifecycle_"+System.currentTimeMillis()+"</ID>\n" + 
                "        <Prefix>logs</Prefix>\n" + 
                "        <Status>Enabled</Status>\n" + 
                "        <Expiration>\n" + 
                "            <Days>30</Days>\n" + 
                "        </Expiration>\n" + 
                "</Rule>\n" + 
                "</LifecycleConfiguration>\n" + 
                "";
        MessageDigest md =null;
        try {
            md = MessageDigest.getInstance("MD5");
            md.update(lifecycleString.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        String contentMD5=BinaryUtils.toBase64(md.digest());
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"?lifecycle";
        if (headers==null) {
            headers=new HashMap<String, String>();
        }
        headers.put("Content-MD5", contentMD5);
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("lifecycle", "");
        
        String method="PUT";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, null, headers, querys,UNSIGNED_PAYLOAD,jettyPort);
        
        try {
            OutputStream wr = conn.getOutputStream();
            wr.write(lifecycleString.getBytes());
            wr.flush();
            wr.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Bucket_GetLifecycle(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"?lifecycle";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("lifecycle", "");
        String method="GET";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);
        return GetResult(conn);
        
    }

    
    public static Pair<Integer, String> Bucket_DeleteLifecycle(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"?lifecycle";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("lifecycle", "");
        String method="DELETE";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);

        return GetResult(conn);
    }

    public static Pair<Integer, String> Bucket_PutAccelerate(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"?accelerate";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("accelerate", "");
        
        String method="PUT";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, null, headers, querys,UNSIGNED_PAYLOAD,jettyPort);
        
        String accelerateString="<AccelerateConfiguration xmls=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n" + 
                "    <Status>Enabled</Status>\n" + 
                "    <IPWhiteLists>\n" + 
                "    <IP>36.111.88.0/24</IP>\n" + 
                "    <IP>114.80.1.136</IP>\n" + 
                "    </IPWhiteLists>\n" + 
                "</AccelerateConfiguration>\n" + 
                "";
        try {
            OutputStream wr = conn.getOutputStream();
            wr.write(accelerateString.getBytes());
            wr.flush();
            wr.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Bucket_GetAccelerate(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"?accelerate";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("accelerate", "");
        String method="GET";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Bucket_PutCors(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String corsString="<CORSConfiguration>\n" + 
                " <CORSRule>\n" + 
                "   <AllowedOrigin>http://www.example1.com</AllowedOrigin>\n" + 
                "\n" + 
                "   <AllowedMethod>PUT</AllowedMethod>\n" + 
                "   <AllowedMethod>POST</AllowedMethod>\n" + 
                "   <AllowedMethod>DELETE</AllowedMethod>\n" + 
                "\n" + 
                "   <AllowedHeader>*</AllowedHeader>\n" + 
                " </CORSRule>\n" + 
                " <CORSRule>\n" + 
                "   <AllowedOrigin>http://www.example2.com</AllowedOrigin>\n" + 
                "\n" + 
                "   <AllowedMethod>PUT</AllowedMethod>\n" + 
                "   <AllowedMethod>POST</AllowedMethod>\n" + 
                "   <AllowedMethod>DELETE</AllowedMethod>\n" + 
                "\n" + 
                "   <AllowedHeader>*</AllowedHeader>\n" + 
                " </CORSRule>\n" + 
                " <CORSRule>\n" + 
                "   <AllowedOrigin>*</AllowedOrigin>\n" + 
                "   <AllowedMethod>GET</AllowedMethod>\n" + 
                " </CORSRule>\n" + 
                "</CORSConfiguration>\n" + 
                "";
        MessageDigest md =null;
        try {
            md = MessageDigest.getInstance("MD5");
            md.update(corsString.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        String contentMD5=BinaryUtils.toBase64(md.digest());
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"?cors";
        if (headers==null) {
            headers=new HashMap<String, String>();
        } 
        headers.put("Content-MD5", contentMD5);
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("cors", "");
        
        String method="PUT";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, null, headers, querys,UNSIGNED_PAYLOAD,jettyPort);
        
        try {
            OutputStream wr = conn.getOutputStream();
            wr.write(corsString.getBytes());
            wr.flush();
            wr.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Bucket_GetCors(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"?cors";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("cors", "");
        String method="GET";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);
        return GetResult(conn);
        
    }

    
    public static Pair<Integer, String> Bucket_DeleteCors(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"?cors";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("cors", "");
        String method="DELETE";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);

        return GetResult(conn);
    }
    
    public static Pair<Integer, String> Object_Put(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,String objectName,String fileContentString,HashMap<String, String> headers) {
        
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"/"+objectName;
        String method="PUT";
        HashMap<String, String> map = new HashMap<String,String>();
        if (headers!=null) {
            map.putAll(headers);
        }
        
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, objectName, map, null,UNSIGNED_PAYLOAD,jettyPort);
        try {
            OutputStream wr = conn.getOutputStream();
            wr.write(fileContentString.getBytes());
            wr.flush();
            wr.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return GetResult(conn);
    }
    
    public static Pair<Integer, String> Object_Get(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,String objectName,HashMap<String, String> headers) {
        
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"/"+objectName;
        String method="GET";
        HashMap<String, String> map = new HashMap<String,String>();
        map.putAll(headers);
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, objectName, map, null,EMPTY_BODY_SHA256,jettyPort);
        
        return GetResult(conn);
    }
    
    public static int Object_Head(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,String objectName,HashMap<String, String> headers) {
        
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"/"+objectName;
        String method="HEAD";
        HashMap<String, String> map = new HashMap<String,String>();
        map.putAll(headers);
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, objectName, map, null,EMPTY_BODY_SHA256,jettyPort);
        int code=0;
        try {
            conn.connect();
            
            code = conn.getResponseCode();
        } catch (Exception e) {
            // TODO: handle exception
        }
        
        System.out.println("code="+code);
        
        return code;
    }
    
    public static Pair<Integer, String> Object_Delete(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,String objectName,HashMap<String, String> headers) {
        
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"/"+objectName;
        String method="DELETE";
        HashMap<String, String> map = new HashMap<String,String>();
        map.putAll(headers);
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, objectName, map, null,EMPTY_BODY_SHA256,jettyPort);
        
        return GetResult(conn);
    }
    
    public static Pair<Integer, String> Object_Copy(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,String srcOjectName,String desOjectName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"/"+desOjectName;
        String method="PUT";
        if (headers==null) {
            headers=new HashMap<String, String>();
        }
        headers.put("x-amz-copy-source","/"+bucketName+"/"+srcOjectName);//由参数传进来
        HashMap<String, String> map = new HashMap<String,String>();
        map.putAll(headers);
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, desOjectName, map, null,UNSIGNED_PAYLOAD,jettyPort);
        
        return GetResult(conn);
    }
    
    public static Pair<Integer, String> Object_InitialMultipartUpload(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,String objectName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"/"+objectName+"?uploads";
        String method="POST";
//        Map<String, String> headers = new HashMap<String, String>();
//        headers.put("content-type", "Content-Type=application/x-www-form-urlencoded");
        Map<String, String> query = new HashMap<String, String>();
        query.put("uploads", "");
        HashMap<String, String> map = new HashMap<String,String>();
        map.putAll(headers);
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, objectName, map, query,EMPTY_BODY_SHA256,jettyPort);
        return GetResult(conn);
    }
    
    public static Pair<Integer, String> Object_UploadPart(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,String objectName,String uploadId,int partNum,String partContent,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"/"+objectName+"?uploadId="+uploadId+"&partNumber="+partNum;
        String method="PUT";
        if (headers==null) {
            headers = new HashMap<String, String>();
        }
        HashMap<String, String> map = new HashMap<String,String>();
        map.putAll(headers);
        map.put("Content-Length", partContent.length()+"");
        Map<String, String> query = new HashMap<String, String>();
        query.put("partNumber", String.valueOf(partNum));
        query.put("uploadId", uploadId);
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, objectName, map, query,UNSIGNED_PAYLOAD,jettyPort);
       
       
        Pair<Integer, String> result= new Pair<Integer, String>();
        try {
            
            OutputStream wr = conn.getOutputStream();
            wr.write(partContent.getBytes());
            wr.flush();
            wr.close();
            
            conn.connect();
            
            int code = conn.getResponseCode();
            System.out.println("code="+code);
            result.first(code);
            String xml="";
            if (code==200||code==204) {
                String etag = conn.getHeaderField("ETag");
                xml=etag;
            }else {
                xml= IOUtils.toString(conn.getErrorStream());
            }
            
            System.out.println(xml);
            result.second(xml);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return result;
    }
    
    
    public static Pair<Integer, String> Object_CompleteMultipartUpload(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,String objectName,String uploadId,Map<String, String> partEtagMap,HashMap<String, String> headers) {
        
        String completeString="";
        String partAndEtagString="";
        for (String partKey : partEtagMap.keySet()) {
            
            partAndEtagString+="<Part>\n" + 
                    "<PartNumber>"+partKey+"</PartNumber>\n" + 
                    "<ETag>"+partEtagMap.get(partKey)+"</ETag>\n" + 
                    "</Part>\n" + 
                    "";
        }
        completeString="<CompleteMultipartUpload>"+partAndEtagString+"</CompleteMultipartUpload>";
        
        System.out.println(completeString);
        
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"/"+objectName+"?uploadId="+uploadId;
        String method="POST";
        if (headers==null) {
            headers = new HashMap<String, String>();
        } 
        HashMap<String, String> map = new HashMap<String,String>();
        map.putAll(headers);
        map.put("Content-Length", completeString.length()+"");
        map.put("content-type", "Content-Type=application/x-www-form-urlencoded");
        Map<String, String> query = new HashMap<String, String>();
        query.put("uploadId", uploadId);
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, objectName, map, query,UNSIGNED_PAYLOAD,jettyPort);
        
        try {
            OutputStream wr = conn.getOutputStream();
            wr.write(completeString.getBytes());
            wr.flush();
            wr.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        return GetResult(conn);
    }
    
    public static Pair<Integer, String> object_AbortMultipartUpload(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,String objectName,String uploadId,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"/"+objectName+"?uploadId="+uploadId;
        Map<String, String> querys = new HashMap<String, String>();
        querys.put("uploadId", uploadId);
        String method="DELETE";
        HashMap<String, String> map = new HashMap<String,String>();
        map.putAll(headers);
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, objectName, map, querys,EMPTY_BODY_SHA256,jettyPort);
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Object_ListPart(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,String objectName,String uploadId,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"/"+objectName+"?uploadId="+uploadId;
        Map<String, String> querys = new HashMap<String, String>();
        querys.put("uploadId", uploadId);
        String method="GET";
        HashMap<String, String> map = new HashMap<String,String>();
        map.putAll(headers);
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, objectName, map, querys,EMPTY_BODY_SHA256,jettyPort);
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Object_CopyPart(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,String objectName,String uploadId,int partNum,String srcObjectName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"/"+objectName+"?uploadId="+uploadId+"&partNumber="+partNum;
        String method="PUT";
        if (headers==null) {
            headers = new HashMap<String, String>();
        }
        HashMap<String, String> map = new HashMap<String,String>();
        map.putAll(headers);
        map.put("x-amz-copy-source", "/" + bucketName + "/" + srcObjectName);
        
        Map<String, String> query = new HashMap<String, String>();
        query.put("partNumber", String.valueOf(partNum));
        query.put("uploadId", uploadId);
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, objectName, map, query,UNSIGNED_PAYLOAD,jettyPort);
       
       
        Pair<Integer, String> result= new Pair<Integer, String>();
        try {
            conn.connect();
            
            int code = conn.getResponseCode();
            System.out.println("code="+code);
            result.first(code);
            String xml="";
            if (code==200||code==204) {
//                String etag = conn.getHeaderField("ETag");
//                xml=etag;
                xml= IOUtils.toString(conn.getInputStream());
            }else {
                xml= IOUtils.toString(conn.getErrorStream());
            }
            
            System.out.println(xml);
            result.second(xml);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return result;
    }
    
    public static Pair<Integer, String> Object_DeleteMulit(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,List<String>objectNames,HashMap<String, String> headers) {
        String objectsListString="";
        for (int i = 0; i < objectNames.size(); i++) {
            objectsListString+="<Object>\n" + 
                    "<Key>"+objectNames.get(i)+"</Key>\n" + 
                    "</Object>\n" + 
                    "";
        }
        String delobjectsString="<Delete>\n" + 
                "<Quiet>true</Quiet>\n" + objectsListString+
                "</Delete>\n" + 
                "";
        MessageDigest md =null;
        try {
            md = MessageDigest.getInstance("MD5");
            md.update(delobjectsString.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        String contentMD5=BinaryUtils.toBase64(md.digest());
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"?delete";
        if (headers==null) {
            headers=new HashMap<String, String>();
        }
        headers.put("content-type", "Content-Type=application/x-www-form-urlencoded");
        headers.put("Content-MD5", contentMD5);
        headers.put("Content-Length",String.valueOf(delobjectsString.length()));
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("delete", "");
        
        String method="POST";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, null, headers, querys,UNSIGNED_PAYLOAD,jettyPort);
        
        try {
            OutputStream wr = conn.getOutputStream();
            wr.write(delobjectsString.getBytes());
            wr.flush();
            wr.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Object_Post(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,String objectName,String fileContentString,HashMap<String, String> headers) {
        CloseableHttpClient  httpclient =null;
        if (httpOrHttps.equals("https")) {
            try {
                SSLContext sslcontext = HttpClientSSLRequestUtils.CreateIgnoreVerifySSL();
                SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext);
                httpclient = HttpClients.custom().setSSLSocketFactory(sslsf).build(); 
            } catch (Exception e) {
                e.printStackTrace();
            }  
        }else {
            httpclient = HttpClients.createDefault();
        }
        
        HashMap<String, String> map = new LinkedHashMap<String, String>();
        String policyStr="";
        if (signVersion.equals("V4")) {
            Date now = new Date();
            policyStr = buildPolicy(bucketName,objectName,accessKey,secretKey);
            String dateTimeStamp = timeFormatter.format(now);
            String stringToSign = policyStr;
            try {
                String scope =  dateFormatter.format(now) + "/" + regionName + "/" + "s3" + "/" + TERMINATOR;
                byte[] signingKey = V4TestUtils.createSignatureKey(secretKey, dateFormatter.format(now), regionName, "s3");
                byte[] signature = V4TestUtils.computeSignature(stringToSign, signingKey);
                String authorization = V4TestUtils.toHex(signature);
                map.put("x-amz-algorithm", "AWS4-HMAC-SHA256");
                map.put("X-Amz-Credential", accessKey + "/" + scope);
                map.put("x-amz-date", dateTimeStamp);
                map.put("key", objectName);
                map.put("policy", policyStr); 
                map.put("x-amz-signature",authorization);
                
            } catch (Exception e) {
                // TODO: handle exception
            }
            
        }else {
            policyStr = buildPolicy(bucketName,objectName);
            map.put("AWSAccessKeyId", accessKey);
            map.put("key", objectName);
            map.put("policy", policyStr); 
            map.put("signature",sign(policyStr, secretKey, SigningAlgorithm.HmacSHA1));
        }

        Pair<Integer, String> result= new Pair<Integer, String>();
        try {
            
            HttpPost httpPost = new HttpPost(httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName);
            MultipartEntityBuilder entity = buildEntity(map);
            entity.addBinaryBody("file", fileContentString.getBytes(), contentType, objectName);
            entity.addPart("submit", new StringBody("upload to oos", ContentType.DEFAULT_TEXT));
            httpPost.setEntity(entity.build());
            if (headers!=null) {
                for (String headerKey : headers.keySet()) {
                    httpPost.setHeader(headerKey, headers.get(headerKey));
              }
            }
            
            HttpResponse response = httpclient.execute(httpPost);
            StatusLine statusLine=response.getStatusLine();
            int responseCode=statusLine.getStatusCode();
            result.first(responseCode);
            HttpEntity resEntity = response.getEntity();
            String xml="";
            if (resEntity!=null) {
                xml= EntityUtils.toString(resEntity,"utf-8");
            }
            result.second(xml);
        }  catch (Exception e) {
            e.printStackTrace();
        }
        
        return result;
    }
    
    public static Pair<Integer, String> Object_Post2(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey,String bucketName,String objectName,String fileContentString) {
        String boundary="9431149156168";
        StringBuffer resSB = new StringBuffer("\r\n");  
        String endBoundary = "\r\n--" + boundary + "--\r\n"; 
        
        String policyString="";
        try {
            policyString=buildPolicy(bucketName,objectName);
        } catch (Exception e) {
            // TODO: handle exception
        }
        
        resSB.append("Content-Disposition: form-data; name=").append("\"AWSAccessKeyId\"").append("\r\n").append("\r\n").append(accessKey).append("\r\n").append("--").append(boundary).append("\r\n"); 
        resSB.append("Content-Disposition: form-data; name=").append("\"key\"").append("\r\n").append("\r\n").append(objectName).append("\r\n").append("--").append(boundary).append("\r\n"); 
        resSB.append("Content-Disposition: form-data; name=").append("\"policy\"").append("\r\n").append("\r\n").append(policyString).append("\r\n").append("--").append(boundary).append("\r\n");
        resSB.append("Content-Disposition: form-data; name=").append("\"signature\"").append("\r\n").append("\r\n").append(sign(policyString, secretKey, SigningAlgorithm.HmacSHA1)).append("\r\n").append("--").append(boundary).append("\r\n"); 
//        resSB.append("Content-Disposition: form-data; name=").append("\"success_action_status\"").append("\r\n").append("\r\n").append(200).append("\r\n").append("--").append(boundary).append("\r\n"); 
        resSB.append("Content-Disposition: form-data; name=").append("\"file\"").append("; filename=").append(objectName).append("\r\n").append("Content-Type: ").append("text/plain").append("\r\n\r\n"); 
        String boundaryMessage = resSB.toString(); 
        
        StringBuffer submit = new StringBuffer("\r\n");  
        submit.append("Content-Disposition: form-data; name=").append("\"submit\"").append("\r\n").append("\r\n").append("Upload to OOS"); 
        String submitMessage=submit.toString();
        
        String bodyString="--"+boundary+boundaryMessage+fileContentString+"\r\n--"+boundary+submitMessage+endBoundary;
        
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName;
        String method="POST";
        
        Map<String, String> headers=new HashMap<String, String>();
        headers.put("Content-Type", "multipart/form-data; boundary="+boundary);
//        headers.put("Content-Length", String.valueOf(bodyString.length()));
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, bucketName, null, headers, null,UNSIGNED_PAYLOAD,jettyPort);
        
        try {
            
            System.out.println(bodyString);
            OutputStream wr = conn.getOutputStream();
            wr.write(bodyString.getBytes("utf-8") ); 
            wr.flush();
            wr.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return GetResult(conn);
//        return null;
    }
    
    /*
     * 旧IAM
     */
    public static Pair<Integer, String> CreateAccessKey(String httpOrHttps,String signVersion, int oldIamPort,String accessKey,String secretKey,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST_OLDIAM+":"+oldIamPort+"/";
        
        String method="POST";
        String body="Action=CreateAccessKey";
        if (headers==null) {
            headers = new HashMap<String, String>();
        }
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, null, null, headers, null,EMPTY_BODY_SHA256,oldIamPort);
        try {
            OutputStream wr = conn.getOutputStream();
            wr.write(body.getBytes());
            wr.flush();
            wr.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return GetResult(conn);
    }
    
    /*
     * 旧IAM
     */
    public static Pair<Integer, String> DeleteAccessKey(String httpOrHttps,String signVersion, int oldIamPort,String accessKey,String secretKey,String accessKeyId,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST_OLDIAM+":"+oldIamPort+"/";
        
        String method="POST";
        String body="Action=DeleteAccessKey&AccessKeyId="+accessKeyId;
        if (headers==null) {
            headers = new HashMap<String, String>();
        }
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, null, null, headers, null,EMPTY_BODY_SHA256,oldIamPort);
        try {
            OutputStream wr = conn.getOutputStream();
            wr.write(body.getBytes());
            wr.flush();
            wr.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return GetResult(conn);
    }
    
    /*
     * 旧IAM
     */
    public static Pair<Integer, String> UpdateAccessKey(String httpOrHttps,String signVersion, int oldIamPort,String accessKey,String secretKey,String accessKeyId,String status,String isPrimary,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST_OLDIAM+":"+oldIamPort+"/";
        
        String method="POST";
        String body="Action=UpdateAccessKey&AccessKeyId="+accessKeyId+"&Status="+status+"&IsPrimary="+isPrimary;
        if (headers==null) {
            headers = new HashMap<String, String>();
        }
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, null, null, headers, null,EMPTY_BODY_SHA256,oldIamPort);
        try {
            OutputStream wr = conn.getOutputStream();
            wr.write(body.getBytes());
            wr.flush();
            wr.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return GetResult(conn);
    }
    
    /*
     * 旧IAM
     */
    public static Pair<Integer, String> ListAccessKey(String httpOrHttps,String signVersion, int oldIamPort,String accessKey,String secretKey,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST_OLDIAM+":"+oldIamPort+"/";
        
        String method="POST";
        String body="Action=ListAccessKey";
        if (headers==null) {
            headers = new HashMap<String, String>();
        }
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, accessKey, secretKey, method, null, null, headers, null,EMPTY_BODY_SHA256,oldIamPort);
        try {
            OutputStream wr = conn.getOutputStream();
            wr.write(body.getBytes());
            wr.flush();
            wr.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return GetResult(conn);
    }
    
    private static MultipartEntityBuilder buildEntity(HashMap<String, String> map) { 
        Iterator<String> it = map.keySet().iterator();
        MultipartEntityBuilder entity = MultipartEntityBuilder.create();
        entity.setMode(HttpMultipartMode.BROWSER_COMPATIBLE);
        entity.setCharset(Charset.forName("utf8"));
        while (it.hasNext()) {
            String key = (String) it.next();
            entity.addPart(key, new StringBody(map.get(key), contentType));
        }
        return entity;
    }
    
    private static String buildPolicy(String bucketName,String objectName){
        JSONObject jo = new JSONObject();
        try {
            
            jo.put("expiration", "2050-12-01T12:00:00.000Z");
            JSONArray ja = new JSONArray();
            ja.put(new JSONObject().put("bucket", bucketName));
            ja.put(new JSONObject().put("key", objectName));
            jo.put("conditions", ja);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        
        System.out.println(jo.toString());
        byte[] policyBytes = Base64.encodeBase64(jo.toString().getBytes(Consts.CS_UTF8));
        String policyStr = new String(policyBytes, Consts.CS_UTF8);
        return policyStr;
    }
    
    private static  String buildPolicy(String bucketName, String objectName,String ak,String sk)  {
        
        String bucket = bucketName;
        String region = regionName;
        JSONObject jo = new JSONObject();
        
        JSONArray ja = new JSONArray();
        try {
            jo.put("expiration", "2050-12-01T12:00:00.000Z");
            ja.put(new JSONObject().put("bucket", bucket));
            ja.put(new JSONObject().put("key", objectName));
            ja.put(new JSONObject().put("X-amz-algorithm", "AWS4-HMAC-SHA256"));
            ja.put(new JSONObject().put("x-Amz-credential", ak+"/"+dateFormatter.format(new Date())+"/"+region+"/"+SERVICE_NAME+"/"+TERMINATOR));
            ja.put(new JSONObject().put("x-amz-date", timeFormatter.format(new Date())));
            jo.put("conditions", ja);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        
        System.out.println(jo.toString());
        byte[] policyBytes = Base64.encodeBase64(jo.toString().getBytes(Consts.CS_UTF8));
        String policyStr = new String(policyBytes, Consts.CS_UTF8);
        System.out.println(policyStr);
        return policyStr;
    }
    
    public static HttpURLConnection CreateConn(String urlStr,String httpOrHttps,String signVersion,String accessKey,String secretKey,String method,String bucketName,String objectName,Map<String, String> headers,Map<String, String> querys,String bodyHash,int jettyPort) {
        HttpURLConnection conn=null;
        try {
            String canonicalString="";
            URL url = new URL(urlStr);
            if (headers==null) {
                headers = new HashMap<String, String>();
            }
            
            if (signVersion.equals("V4")) {
                System.out.println("V4");
                if (bodyHash==null) {
                    bodyHash=UNSIGNED_PAYLOAD;
                }
                String authorization = V4TestUtils.computeSignature(headers, querys, bodyHash, accessKey, secretKey, 
                        url, method, "s3", regionName);
                headers.put("Authorization", authorization);
                if (httpOrHttps.equals("https")) {
                    conn=HttpsRequestUtils.createConn(url, method, headers);
                    System.out.println(" url="+url.toString());
                }else {
                    conn=CreatehttpConn(url, method, headers);
                    System.out.println("url="+url.toString());
                }
                
            }else if (signVersion.startsWith("Pre")) {
            	if("https".equals(httpOrHttps)) {
            		conn = PreUtils.getPreUrlHttpsConn(bucketName, objectName, method, accessKey, secretKey, querys, headers,signVersion,HOST,jettyPort);
            	}else {
            		conn = PreUtils.getPreUrlHttpConn(bucketName, objectName, method, accessKey, secretKey, querys, headers,signVersion,HOST,jettyPort);
            	}
            }else {
                System.out.println("V2");
                String date = TimeUtils.toGMTFormat(new Date());
                headers.put("Date", date);
                if (httpOrHttps.equals("https")) {
                    conn=HttpsRequestUtils.createConn(url, method, headers);
                    System.out.println("url="+url.toString());
                    
                }else {
                    conn=CreatehttpConn(url, method, headers);
                    System.out.println("url="+url.toString());
                }
                
                if (headers != null) {
                    for (String headerKey : headers.keySet()) {
                        conn.setRequestProperty(headerKey, headers.get(headerKey));
                    }
                }
                canonicalString = RestUtils.makeS3CanonicalString(method, 
                        toResourcePath(bucketName, objectName, false), new OOSRequest<>(conn), null);
                System.out.println("canonicalString=\r\n"+canonicalString);
                String signature = sign(canonicalString, secretKey, SigningAlgorithm.HmacSHA1);
                String authorization = "AWS " + accessKey + ":" + signature;
                conn.setRequestProperty("Authorization", authorization);  
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return conn;
    }
    

    
    public static Pair<Integer, String> GetResult(HttpURLConnection conn) {
        Pair<Integer, String> result= new Pair<Integer, String>();
        try {
            conn.connect();
            
            int code = conn.getResponseCode();
            System.out.println("code="+code);
            result.first(code);
            String xml="";
            if (code==200||code==204) {
                xml=IOUtils.toString(conn.getInputStream());
                
            }else {
                xml= IOUtils.toString(conn.getErrorStream());
            }
            
            System.out.println(xml);
            result.second(xml);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return result;
    }
    
    public static String toResourcePath(String bucket, String key, boolean endWithSlash) {
        // refer to com.amazonaws.services.s3.AmazonS3Client.createSigner
        // 增加对斜杠的判断
        String resourcePath;
        if (endWithSlash)
            resourcePath = "/" + ((bucket != null && !bucket.equals("")) ? bucket + "/" : "")
                    + ((key != null) ? ServiceUtils.urlEncode(key) : "");
        else
            resourcePath = "/" + ((bucket != null && !bucket.equals("")) ? bucket : "")
                    + ((key != null) ? "/" + ServiceUtils.urlEncode(key) : "");
        return resourcePath;
    }
    
    public static String sign(String data, String key, SigningAlgorithm algorithm) {
        // refer to com.amazonaws.services.s3.internal.S3Signer
        try {
            Mac mac = Mac.getInstance(algorithm.toString());
            mac.init(new SecretKeySpec(key.getBytes(Consts.STR_UTF8), algorithm.toString()));
            byte[] bs = mac.doFinal(data.getBytes(Consts.STR_UTF8));
            return new String(Base64.encodeBase64(bs), Consts.STR_UTF8);
        } catch (UnsupportedEncodingException e) {
            throw new AmazonClientException("Unable to calculate a request signature: "
                    + e.getMessage(), e);
        } catch (Exception e) {
            throw new AmazonClientException("Unable to calculate a request signature: "
                    + e.getMessage(), e);
        }
    }
    
    public static HttpURLConnection CreatehttpConn(URL url, String method, Map<String, String> headers) throws Exception{
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod(method);
        if (headers != null) {
//            System.out.println("--------- Request headers ---------");
            for (String headerKey : headers.keySet()) {
//                System.out.println(headerKey + ": " + headers.get(headerKey));
                connection.setRequestProperty(headerKey, headers.get(headerKey));
            }
        }
        connection.setUseCaches(false);
        connection.setDoInput(true);
        connection.setDoOutput(true);
        return connection;
    }
    
}


