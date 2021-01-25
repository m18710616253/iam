package cn.ctyun.oos.utils.api;

import java.io.OutputStream;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.MessageDigest;

import java.text.SimpleDateFormat;
import java.util.Date;

import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import javax.net.ssl.SSLContext;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.eclipse.jetty.util.UrlEncoded;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.xml.sax.InputSource;

import com.amazonaws.auth.SigningAlgorithm;
import com.amazonaws.util.BinaryUtils;

import cn.ctyun.common.Consts;
import cn.ctyun.oos.utils.HttpClientSSLRequestUtils;
import cn.ctyun.oos.utils.HttpConnectionSSLRequestUtils;
import cn.ctyun.oos.utils.V2SignClient;
import cn.ctyun.oos.utils.V4SignClient;
import common.time.TimeUtils;
import common.tuple.Pair;

public class OOSAPITestUtils {
    
    public static final String EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
    public static final String SCHEME = "AWS4";
    public static final String ALGORITHM = "HMAC-SHA256";
    public static final String TERMINATOR = "aws4_request";
    public static final String SERVICE_NAME = "s3";
    public static final String HMAC_SHA256 = "HmacSHA256";
    
    static ContentType contentType = ContentType.create("text/plain", Consts.CS_UTF8);
    
    private static SimpleDateFormat timeFormatter = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
    private static SimpleDateFormat dateFormatter = new SimpleDateFormat("yyyyMMdd");
    
    static{
        TimeZone utc = TimeZone.getTimeZone("UTC");
        timeFormatter.setTimeZone(utc);
        dateFormatter.setTimeZone(utc);
    }
    
    
    public static Pair<Integer, String> Service_Get(String httpOrHttps, String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/";
        
        String method="GET";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName, accessKey, secretKey, method, null, null, headers, null,EMPTY_BODY_SHA256,jettyPort);
   
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Region_Get(String httpOrHttps,String host,int jettyPort,String signVersion, String regionName,String accessKey,String secretKey,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/?regions";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("regions", "");
        String method="GET";
        
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, null, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);
        
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Bucket_Put(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,String bucketType,String metaregion,List<String> dateregions,String scheduleStrategy,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName;
        String method="PUT";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, null, headers, null,UNSIGNED_PAYLOAD,jettyPort);

            if (dateregions!=null&&dateregions.size()>0) {
                String body="<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">";
                if (metaregion!=null) {
                    String metaString="<MetadataLocationConstraint>" + 
                            "<Location>"+metaregion+"</Location>" + 
                            "</MetadataLocationConstraint>" + 
                            "";
                    body+=metaString;
                }
                
                String dateLocationString="";
                for (int i = 0; i < dateregions.size(); i++) {
                    dateLocationString+="<Location>"+dateregions.get(i)+"</Location>";
                }
                
                String regionTypeString="";
                if (bucketType.equalsIgnoreCase("specified")) {
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
                System.out.println("body xml ="+body);
                
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
    
    public static Pair<Integer, String> Bucket_GetLocation(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"?location";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("location", "");
        String method="GET";
        
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);
        
        return GetResult(conn);
    }
    
    public static Pair<Integer, String> Bucket_GetAcl(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"?acl";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("acl", "");
        String method="GET";
        
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);
        
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Bucket_Get(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName;
        String method="GET";
        
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, null, headers, null,EMPTY_BODY_SHA256,jettyPort);
        
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Bucket_Get(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,String prefix,String maxkey,String marker,String delimiter, HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName;
        Map<String, String> querys=new HashMap<String, String>();
       
        if (prefix!=null||maxkey!=null||marker!=null||delimiter!=null) {
            urlStr=urlStr+"/?";
        }     
        if (prefix!=null) {
            if (urlStr.contains("=")) {
                urlStr=urlStr+"&prefix="+prefix;
            }else {
                urlStr=urlStr+"prefix="+prefix;
            }
            querys.put("prefix", prefix);
        }
        if (maxkey!=null) {
            if (urlStr.contains("=")) {
                urlStr=urlStr+"&max-keys="+maxkey;
            }else {
                urlStr=urlStr+"max-keys="+maxkey;
            }
            querys.put("max-keys", maxkey);
        }
        if (marker!=null) {
            if (urlStr.contains("=")) {
                urlStr=urlStr+"&marker="+marker;
            }else {
                urlStr=urlStr+"marker="+marker;
            }
            querys.put("marker", marker);
        } 
        if (delimiter!=null) {
            if (urlStr.contains("=")) {
                urlStr=urlStr+"&delimiter="+delimiter;
            }else {
                urlStr=urlStr+"delimiter="+delimiter;
            }
            querys.put("delimiter", delimiter);
        }
         
        String method="GET";

        
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);
        
        return GetResult(conn);
        
    }
    
    
    /*
     * 给普通用户list以自己ak开头的object
     */
    public static Pair<Integer, String> Bucket_GetPrefix(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"/?prefix="+accessKey;
        String method="GET";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("prefix", accessKey);
        
        HttpURLConnection conn=null;
        try {
            URL url = new URL(urlStr);
            if (headers==null) {
                headers = new HashMap<String, String>();
            }
            
            if (signVersion.equals("V4")) {
                System.out.println("V4");
                
                String authorization = V4SignClient.computeV4SignatureDefalut(headers, querys, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                        url, method, "s3", regionName);
                headers.put("Authorization", authorization);
                if (httpOrHttps.equals("https")) {
                    conn=HttpConnectionSSLRequestUtils.createhttpsConn(url, method, headers);
                    System.out.println(" url="+url.toString());
                }else {
                    conn=CreatehttpConn(url, method, headers);
                    System.out.println("url="+url.toString());
                }
                
            }else {
                System.out.println("V2");
                String date = TimeUtils.toGMTFormat(new Date());
                headers.put("Date", date);
                if (httpOrHttps.equals("https")) {
                    conn=HttpConnectionSSLRequestUtils.createhttpsConn(url, method, headers);
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
                String authorization = V2SignClient.computeV2SignatureDefalut(headers, querys, accessKey, secretKey, method, bucketName, null, true, null);
                conn.setRequestProperty("Authorization", authorization);  
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Bucket_Delete(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName;
        String method="DELETE";
        
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, null, headers, null,EMPTY_BODY_SHA256,jettyPort);
        
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Bucket_PutPolicy(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,String policyString,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"?policy";
        String method="PUT";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("policy", "");
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, null, headers, querys,UNSIGNED_PAYLOAD,jettyPort);
        
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
    
    public static Pair<Integer, String> Bucket_GetPolicy(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"?policy";
        String method="GET";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("policy", "");
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName, accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);
       
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Bucket_DeletePolicy(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"?policy";
        String method="DELETE";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("policy", "");
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);
       
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Bucket_PutWebsite(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"?website";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("website", "");
        
        String method="PUT";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, null, headers, querys,UNSIGNED_PAYLOAD,jettyPort);
        
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
    
    public static Pair<Integer, String> Bucket_GetWebsite(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"?website";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("website", "");
        String method="GET";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);
        return GetResult(conn);
        
    }

    
    public static Pair<Integer, String> Bucket_DeleteWebsite(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"?website";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("website", "");
        String method="DELETE";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);

        return GetResult(conn);
    }
    
    public static Pair<Integer, String> Bucket_ListMultipartUploads(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"?uploads";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("uploads", "");
        String method="GET";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Bucket_ListMultipartUploads(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,String prefix,String delimiter,String maxuploads,String keymarker,String uploadidmarker,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"?uploads";
        
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("uploads", "");
             
        if (prefix!=null) {
            urlStr=urlStr+"&prefix="+prefix;
            querys.put("prefix", prefix);
        }
        
        if (delimiter!=null) {
            urlStr=urlStr+"&delimiter="+delimiter;
            querys.put("delimiter", delimiter);
        }
        if (maxuploads!=null) {
            urlStr=urlStr+"&max-uploads="+maxuploads;
            querys.put("max-uploads", maxuploads);
        }
        if (keymarker!=null) {
            urlStr=urlStr+"&key-marker="+keymarker;
            querys.put("key-marker", keymarker);
        } 
        if (uploadidmarker!=null) {
            urlStr=urlStr+"&upload-id-marker="+uploadidmarker;
            querys.put("upload-id-marker", uploadidmarker);
        } 
        
        String method="GET";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Bucket_PutLogging(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,String targetBucket,String targetPrefix,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"?logging";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("logging", "");
        
        String method="PUT";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, null, headers, querys,UNSIGNED_PAYLOAD,jettyPort);
        
        String loggingString="<BucketLoggingStatus xmlns=\"http://doc.s3.amazonaws.com/2006-03-01\">\n" + 
                "<LoggingEnabled>\n" + 
                "<TargetBucket>"+targetBucket+"</TargetBucket>\n" + 
                "<TargetPrefix>"+targetPrefix+"</TargetPrefix>\n" + 
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
    
    public static Pair<Integer, String> Bucket_GetLogging(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"?logging";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("logging", "");
        String method="GET";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);
        return GetResult(conn);
        
    }
    
    public static int Bucket_Head(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName;
        String method="HEAD";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, null, headers, null,EMPTY_BODY_SHA256,jettyPort);
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
    
    public static Pair<Integer, String> Bucket_PutLifecycle(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,String prefix,String status,int expirationDays,HashMap<String, String> headers) {
        String lifecycleString="<LifecycleConfiguration>\n" + 
                "    <Rule>\n" + 
                "        <ID>test_lifecycle_"+System.currentTimeMillis()+"</ID>\n" + 
                "        <Prefix>"+prefix+"</Prefix>\n" + 
                "        <Status>"+status+"</Status>\n" + 
                "        <Expiration>\n" + 
                "            <Days>"+expirationDays+"</Days>\n" + 
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
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"?lifecycle";
        if (headers==null) {
            headers=new HashMap<String, String>();
        }
        headers.put("Content-MD5", contentMD5);
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("lifecycle", "");
        
        String method="PUT";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, null, headers, querys,UNSIGNED_PAYLOAD,jettyPort);
        
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
    
    public static Pair<Integer, String> Bucket_GetLifecycle(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"?lifecycle";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("lifecycle", "");
        String method="GET";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);
        return GetResult(conn);
        
    }

    
    public static Pair<Integer, String> Bucket_DeleteLifecycle(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"?lifecycle";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("lifecycle", "");
        String method="DELETE";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);

        return GetResult(conn);
    }

    public static Pair<Integer, String> Bucket_PutAccelerate(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,List<String> ipList,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"?accelerate";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("accelerate", "");
        
        String method="PUT";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, null, headers, querys,UNSIGNED_PAYLOAD,jettyPort);
       
        String ipString="";
        if (ipList!=null&&ipList.size()>0) {
            for (int i = 0; i < ipList.size(); i++) {
                ipString+="    <IP>"+ipList.get(i)+"</IP>\n";
            }
        }
        
        String accelerateString="<AccelerateConfiguration xmls=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n" + 
                "    <Status>Enabled</Status>\n" + 
                "    <IPWhiteLists>\n" + 
                ipString +
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
    
    public static Pair<Integer, String> Bucket_GetAccelerate(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"?accelerate";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("accelerate", "");
        String method="GET";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Bucket_PutCors(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
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
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"?cors";
        if (headers==null) {
            headers=new HashMap<String, String>();
        } 
        headers.put("Content-MD5", contentMD5);
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("cors", "");
        
        String method="PUT";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, null, headers, querys,UNSIGNED_PAYLOAD,jettyPort);
        
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
    
    public static Pair<Integer, String> Bucket_GetCors(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"?cors";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("cors", "");
        String method="GET";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);
        return GetResult(conn);
        
    }

    
    public static Pair<Integer, String> Bucket_DeleteCors(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"?cors";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("cors", "");
        String method="DELETE";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, null, headers, querys,EMPTY_BODY_SHA256,jettyPort);

        return GetResult(conn);
    }
    
    public static Pair<Integer, String> Object_Put(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,String objectName,String fileContentString,HashMap<String, String> headers)  {
        
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"/"+objectName;
        String method="PUT";
        HashMap<String, String> map = new HashMap<String,String>();
        if (headers!=null) {
            map.putAll(headers);
        }
        
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, objectName, map, null,UNSIGNED_PAYLOAD,jettyPort);
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
    
    public static Pair<Integer, String> Object_Get(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,String objectName,HashMap<String, String> headers) {
        
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"/"+objectName;
        String method="GET";
        HashMap<String, String> map = new HashMap<String,String>();
        if (headers!=null) {
            map.putAll(headers);
        }
        
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, objectName, map, null,EMPTY_BODY_SHA256,jettyPort);
        
        return GetResult(conn);
    }
    
    public static int Object_Head(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,String objectName,HashMap<String, String> headers) {
        
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"/"+objectName;
        String method="HEAD";
        HashMap<String, String> map = new HashMap<String,String>();
        if (headers!=null) {
            map.putAll(headers);
        }
        
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, objectName, map, null,EMPTY_BODY_SHA256,jettyPort);
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
    
    public static Pair<Integer, String> Object_Delete(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,String objectName,HashMap<String, String> headers) {
        
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"/"+objectName;
        String method="DELETE";
        HashMap<String, String> map = new HashMap<String,String>();
        if (headers!=null) {
            map.putAll(headers);
        } 
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, objectName, map, null,EMPTY_BODY_SHA256,jettyPort);
        
        return GetResult(conn);
    }
    
    public static Pair<Integer, String> Object_Copy(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,String srcOjectName,String desOjectName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"/"+desOjectName;
        String method="PUT";
        if (headers==null) {
            headers=new HashMap<String, String>();
        }
        headers.put("x-amz-copy-source","/"+bucketName+"/"+srcOjectName);//由参数传进来
        HashMap<String, String> map = new HashMap<String,String>();
        map.putAll(headers);
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, desOjectName, map, null,UNSIGNED_PAYLOAD,jettyPort);
        
        return GetResult(conn);
    }
    
    public static Pair<Integer, String> Object_InitialMultipartUpload(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,String objectName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"/"+objectName+"?uploads";
        String method="POST";
        if (headers==null) {
            headers = new HashMap<String, String>();
        } 
        headers.put("content-type", "Content-Type=application/x-www-form-urlencoded");
        Map<String, String> query = new HashMap<String, String>();
        query.put("uploads", "");
        HashMap<String, String> map = new HashMap<String,String>();
        map.putAll(headers);
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, objectName, map, query,EMPTY_BODY_SHA256,jettyPort);
        return GetResult(conn);
    }
    
    public static Pair<Integer, String> Object_UploadPart(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,String objectName,String uploadId,int partNum,String partContent,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"/"+objectName+"?uploadId="+uploadId+"&partNumber="+partNum;
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
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, objectName, map, query,UNSIGNED_PAYLOAD,jettyPort);
       
       
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
    
    
    public static Pair<Integer, String> Object_CompleteMultipartUpload(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,String objectName,String uploadId,Map<String, String> partEtagMap,HashMap<String, String> headers) {
        
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
        
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"/"+objectName+"?uploadId="+uploadId;
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
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, objectName, map, query,UNSIGNED_PAYLOAD,jettyPort);
        
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
    
    public static Pair<Integer, String> object_AbortMultipartUpload(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,String objectName,String uploadId,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"/"+objectName+"?uploadId="+uploadId;
        Map<String, String> querys = new HashMap<String, String>();
        querys.put("uploadId", uploadId);
        String method="DELETE";
        HashMap<String, String> map = new HashMap<String,String>();
        if (headers!=null) {
            map.putAll(headers);
        }
        
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, objectName, map, querys,EMPTY_BODY_SHA256,jettyPort);
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Object_ListPart(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,String objectName,String uploadId,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"/"+objectName+"?uploadId="+uploadId;
        Map<String, String> querys = new HashMap<String, String>();
        querys.put("uploadId", uploadId);
        String method="GET";
        HashMap<String, String> map = new HashMap<String,String>();
        if (headers!=null) {
            map.putAll(headers);
        }
       
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, objectName, map, querys,EMPTY_BODY_SHA256,jettyPort);
        return GetResult(conn);
        
    }
    
    public static Pair<Integer, String> Object_CopyPart(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,String objectName,String uploadId,int partNum,String srcObjectName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"/"+objectName+"?uploadId="+uploadId+"&partNumber="+partNum;
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
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, objectName, map, query,UNSIGNED_PAYLOAD,jettyPort);
       
       
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
    
    public static Pair<Integer, String> Object_DeleteMulit(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,List<String>objectNames,HashMap<String, String> headers) {
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
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName+"?delete";
        if (headers==null) {
            headers=new HashMap<String, String>();
        }
        headers.put("content-type", "Content-Type=application/x-www-form-urlencoded");
        headers.put("Content-MD5", contentMD5);
        headers.put("Content-Length",String.valueOf(delobjectsString.length()));
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("delete", "");
        
        String method="POST";
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, null, headers, querys,UNSIGNED_PAYLOAD,jettyPort);
        
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
    
    public static Pair<Integer, String> Object_Post(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,String objectName,String fileContentString,HashMap<String, String> headers) {
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
        
        if (headers==null) {
            headers = new LinkedHashMap<String, String>();
        }
        
        String policyStr="";
        if (signVersion.equals("V4")) {
            Date now = new Date();
            policyStr = buildPolicy(regionName,bucketName,objectName,accessKey,secretKey,headers);
            String dateTimeStamp = timeFormatter.format(now);
            String stringToSign = policyStr;
            try {
                String scope =  dateFormatter.format(now) + "/" + regionName + "/" + "s3" + "/" + TERMINATOR;
                byte[] signingKey = V4SignClient.createSignatureKey(secretKey, dateFormatter.format(now), regionName, "s3");
                byte[] signature = V4SignClient.sign(stringToSign, signingKey,HMAC_SHA256);
                String authorization = V4SignClient.toHex(signature);
                
                headers.put("x-amz-algorithm", "AWS4-HMAC-SHA256");
                headers.put("X-Amz-Credential", accessKey + "/" + scope);
                headers.put("x-amz-date", dateTimeStamp);
                headers.put("key", objectName);
                headers.put("policy", policyStr); 
                if (accessKey!=null) {
                    headers.put("x-amz-signature",authorization);
                }

            } catch (Exception e) {
                // TODO: handle exception
            }
            
        }else {
            policyStr = buildPolicy(bucketName,objectName,headers);
            if (accessKey!=null) {
                headers.put("AWSAccessKeyId", accessKey);
                headers.put("signature",V2SignClient.sign(policyStr, secretKey, SigningAlgorithm.HmacSHA1));
            }
            
            headers.put("key", objectName);
            headers.put("policy", policyStr); 
            
        }

        Pair<Integer, String> result= new Pair<Integer, String>();
        try {
            
            HttpPost httpPost = new HttpPost(httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName);
            MultipartEntityBuilder entity = buildEntity(headers);
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
    
    public static Pair<Integer, String> Object_Post2(String httpOrHttps,String host,int jettyPort,String signVersion,String regionName,String accessKey,String secretKey,String bucketName,String objectName,String fileContentString,Map<String, String> headers) {
        String boundary="9431149156168";
        StringBuffer resSB = new StringBuffer("\r\n");  
        String endBoundary = "\r\n--" + boundary + "--\r\n"; 
        
        String policyString="";
        try {
            policyString=buildPolicy(bucketName,objectName,headers);
        } catch (Exception e) {
            // TODO: handle exception
        }
        
        resSB.append("Content-Disposition: form-data; name=").append("\"AWSAccessKeyId\"").append("\r\n").append("\r\n").append(accessKey).append("\r\n").append("--").append(boundary).append("\r\n"); 
        resSB.append("Content-Disposition: form-data; name=").append("\"key\"").append("\r\n").append("\r\n").append(objectName).append("\r\n").append("--").append(boundary).append("\r\n"); 
        resSB.append("Content-Disposition: form-data; name=").append("\"policy\"").append("\r\n").append("\r\n").append(policyString).append("\r\n").append("--").append(boundary).append("\r\n");
        resSB.append("Content-Disposition: form-data; name=").append("\"signature\"").append("\r\n").append("\r\n").append(V2SignClient.sign(policyString, secretKey, SigningAlgorithm.HmacSHA1)).append("\r\n").append("--").append(boundary).append("\r\n"); 
//        resSB.append("Content-Disposition: form-data; name=").append("\"success_action_status\"").append("\r\n").append("\r\n").append(200).append("\r\n").append("--").append(boundary).append("\r\n"); 
        resSB.append("Content-Disposition: form-data; name=").append("\"file\"").append("; filename=").append(objectName).append("\r\n").append("Content-Type: ").append("text/plain").append("\r\n\r\n"); 
        String boundaryMessage = resSB.toString(); 
        
        StringBuffer submit = new StringBuffer("\r\n");  
        submit.append("Content-Disposition: form-data; name=").append("\"submit\"").append("\r\n").append("\r\n").append("Upload to OOS"); 
        String submitMessage=submit.toString();
        
        String bodyString="--"+boundary+boundaryMessage+fileContentString+"\r\n--"+boundary+submitMessage+endBoundary;
        
        String urlStr=httpOrHttps+"://"+host+":"+jettyPort+"/"+bucketName;
        String method="POST";
        
        if (headers==null) {
            headers=new HashMap<String, String>();
        }
        headers.put("Content-Type", "multipart/form-data; boundary="+boundary);
//        headers.put("Content-Length", String.valueOf(bodyString.length()));
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,accessKey, secretKey, method, bucketName, null, headers, null,UNSIGNED_PAYLOAD,jettyPort);
        
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
    
    private static String buildPolicy(String bucketName,String objectName,Map<String, String> headers){
        JSONObject jo = new JSONObject();
        try {
            
            jo.put("expiration", "2050-12-01T12:00:00.000Z");
            JSONArray ja = new JSONArray();
            ja.put(new JSONObject().put("bucket", bucketName));
            ja.put(new JSONObject().put("key", objectName));
            for(Map.Entry<String, String> entry : headers.entrySet()){
                String mapKey = entry.getKey();
                String mapValue = entry.getValue();
                ja.put(new JSONObject().put(mapKey, mapValue));
            }
            jo.put("conditions", ja);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        
        System.out.println(jo.toString());
        byte[] policyBytes = Base64.encodeBase64(jo.toString().getBytes(Consts.CS_UTF8));
        String policyStr = new String(policyBytes, Consts.CS_UTF8);
        return policyStr;
    }
    
    private static  String buildPolicy(String regionName,String bucketName, String objectName,String ak,String sk,Map<String, String> headers)  {
        
        String bucket = bucketName;
        String region = regionName;
        JSONObject jo = new JSONObject();
        
        JSONArray ja = new JSONArray();
        try {
            jo.put("expiration", "2050-12-01T12:00:00.000Z");
            ja.put(new JSONObject().put("bucket", bucket));
            ja.put(new JSONObject().put("key", objectName));
            for(Map.Entry<String, String> entry : headers.entrySet()){
                String mapKey = entry.getKey();
                String mapValue = entry.getValue();
                ja.put(new JSONObject().put(mapKey, mapValue));
            }
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
    
    public static HttpURLConnection CreateConn(String urlStr,String httpOrHttps,String signVersion,String regionName,String accessKey,String secretKey,String method,String bucketName,String objectName,Map<String, String> headers,Map<String, String> querys,String bodyHash,int jettyPort) {
        HttpURLConnection conn=null;
        try {
            URL url = new URL(urlStr);
            
            if (headers==null) {
                headers = new HashMap<String, String>();
            }
            
            if (querys==null) {
                querys = new HashMap<String, String>();
            }
            
            if (signVersion.equals("V4")) {
                System.out.println("V4");
                if (bodyHash==null) {
                    bodyHash=UNSIGNED_PAYLOAD;
                }
                String authorization = V4SignClient.computeV4SignatureDefalut(headers, querys, bodyHash, accessKey, secretKey, 
                        url, method, "s3", regionName);
                if (accessKey!=null) {
                    headers.put("Authorization", authorization);
                } 
                if (httpOrHttps.equals("https")) {
                    conn=HttpConnectionSSLRequestUtils.createhttpsConn(url, method, headers);
                    System.out.println(" url="+url.toString());
                }else {
                    conn=CreatehttpConn(url, method, headers);
                    System.out.println("url="+url.toString());
                }
                
            }else {
                System.out.println("V2");
                String date = TimeUtils.toGMTFormat(new Date());
                headers.put("Date", date);
                if (httpOrHttps.equals("https")) {
                    conn=HttpConnectionSSLRequestUtils.createhttpsConn(url, method, headers);
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
                String authorization = V2SignClient.computeV2SignatureDefalut(headers,querys,accessKey,secretKey,method,bucketName,objectName,false,null);
                if (accessKey!=null) {
                    conn.setRequestProperty("Authorization", authorization); 
                }   
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
    
//    public static String sign(String data, String key, SigningAlgorithm algorithm) {
//        // refer to com.amazonaws.services.s3.internal.S3Signer
//        try {
//            Mac mac = Mac.getInstance(algorithm.toString());
//            mac.init(new SecretKeySpec(key.getBytes(Consts.STR_UTF8), algorithm.toString()));
//            byte[] bs = mac.doFinal(data.getBytes(Consts.STR_UTF8));
//            return new String(Base64.encodeBase64(bs), Consts.STR_UTF8);
//        } catch (UnsupportedEncodingException e) {
//            throw new AmazonClientException("Unable to calculate a request signature: "
//                    + e.getMessage(), e);
//        } catch (Exception e) {
//            throw new AmazonClientException("Unable to calculate a request signature: "
//                    + e.getMessage(), e);
//        }
//    }
    
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
    
    public static String getMultipartUploadId(String xml) {
        String uploadId="";
        try {
            StringReader sr = new StringReader(xml);
            InputSource is = new InputSource(sr);
            Document doc = (new SAXBuilder()).build(is);
            Element root = doc.getRootElement();
            @SuppressWarnings("unchecked")
            List<Element> secondLevel=root.getChildren();
            
           uploadId=secondLevel.get(2).getText();
           System.out.println("uploadId="+uploadId);
        } catch (Exception e) {
            e.printStackTrace();;
        }
        
        return uploadId;
    }
    
    public static String getCopyPartEtag(String xml) {
        String etag="";
        try {
            StringReader sr = new StringReader(xml);
            InputSource is = new InputSource(sr);
            Document doc = (new SAXBuilder()).build(is);
            Element root = doc.getRootElement();
            @SuppressWarnings("unchecked")
            List<Element> secondLevel=root.getChildren();
            
            etag=secondLevel.get(1).getText();
        } catch (Exception e) {
            e.printStackTrace();;
        }
        
        return etag;
    }
    
}


