package cn.ctyun.oos.utils.api;

import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.IOUtils;

import com.amazonaws.util.BinaryUtils;

import cn.ctyun.oos.utils.HttpConnectionSSLRequestUtils;
import cn.ctyun.oos.utils.V2SignClient;
import cn.ctyun.oos.utils.V4SignClient;
import common.tuple.Pair;

public class OOSAPIPresignedUrlUtils {
    
    public static final String SERVICE_NAME = "s3";

    public static String Object_get_V2_PresignedUrl(String httpOrHttps,String host,int port,String regionName,String accessKey, String secretKey, String bucketName, String objectName, Map<String, String> headers,Map<String, String> querys) {
        URL url=null;
        try {
            url = new URL(httpOrHttps+"://"+host+":"+port+"/"+bucketName+"/"+objectName);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        
        String method="GET"; 
        long expiresIn=0L;
        if (querys==null) {
            querys= new HashMap<String, String>();
        }
        if (querys.containsKey("X-Amz-Expires")) {
            expiresIn=Long.parseLong(querys.get("X-Amz-Expires"));
        }else {
            expiresIn=7 * 24 * 60 * 60;
            
        }
        Date now = new Date();
        long expiresTime= now.getTime()+expiresIn;
        String expires= String.valueOf(expiresTime);
 
        String presignedUrl=V2SignClient.computeV2PresignedUrlDefalut(url, headers, querys, accessKey, secretKey, method, bucketName, objectName, false, expires);
        
        return presignedUrl;
    }
    
    
    
    public static String Object_InitialMultipartUpload_V2_PresignedUrl(String httpOrHttps,String host,int port,String regionName,String accessKey, String secretKey, String bucketName, String objectName,Map<String, String> headers,Map<String, String> querys) {
        URL url=null;
        try {
            url = new URL(httpOrHttps+"://"+host+":"+port+"/"+bucketName+"/"+objectName+"?uploads");
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        
        String method="POST"; 
        if (querys==null) {
            querys = new HashMap<String, String>();
        }
        querys.put("uploads", "");
        
        long expiresIn=0L;
        if (querys.containsKey("X-Amz-Expires")) {
            expiresIn=Long.parseLong(querys.get("X-Amz-Expires"));
        }else {
            expiresIn=7 * 24 * 60 * 60;
            
        }
        Date now = new Date();
        long expiresTime= now.getTime()+expiresIn;
        String expires= String.valueOf(expiresTime);
        
        String presignedUrl=V2SignClient.computeV2PresignedUrlDefalut(url, headers, querys, accessKey, secretKey, method, bucketName, objectName, false, expires);
    
        return presignedUrl;
    }
    
    public static String Object_ListPart_V2_PresignedUrl(String httpOrHttps,String host,int port,String regionName,String accessKey, String secretKey, String bucketName, String objectName, String uploadId,Map<String, String> headers,Map<String, String> querys){
        URL url=null;
        try {
            url = new URL(httpOrHttps+"://"+host+":"+port+"/"+bucketName+"/"+objectName+"?uploadId="+uploadId);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
       
        String method="GET";
        if (querys==null) {
            querys = new HashMap<String, String>();
        }

        querys.put("uploadId", uploadId);
        
        long expiresIn=0L;
        if (querys.containsKey("X-Amz-Expires")) {
            expiresIn=Long.parseLong(querys.get("X-Amz-Expires"));
        }else {
            expiresIn=7 * 24 * 60 * 60;
            
        }
        Date now = new Date();
        long expiresTime= now.getTime()+expiresIn;
        String expires= String.valueOf(expiresTime);
        
        String presignedUrl=V2SignClient.computeV2PresignedUrlDefalut(url, headers, querys, accessKey, secretKey, method, bucketName, objectName, false, expires);

        return presignedUrl;
        
    }
    
    public static String Object_CompleteMultipartUpload_V2_PresignedUrl(String httpOrHttps,String host,int port,String regionName,String accessKey, String secretKey, String bucketName, String objectName, String uploadId,Map<String, String> headers,Map<String, String> querys) {
        
        URL url=null;
        try {
            url = new URL(httpOrHttps+"://"+host+":"+port+"/"+bucketName+"/"+objectName+"?uploadId="+uploadId);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
       
        String method="POST";
        if (headers==null) {
            headers = new HashMap<String, String>();
        } 
        
        headers.put("content-type", "application/x-www-form-urlencoded");
        if (querys==null) {
            querys = new HashMap<String, String>();
        }

        querys.put("uploadId", uploadId);
        
        long expiresIn=0L;
        if (querys.containsKey("X-Amz-Expires")) {
            expiresIn=Long.parseLong(querys.get("X-Amz-Expires"));
        }else {
            expiresIn=7 * 24 * 60 * 60;
            
        }
        Date now = new Date();
        long expiresTime= now.getTime()+expiresIn;
        String expires= String.valueOf(expiresTime);
        
 
        String presignedUrl=V2SignClient.computeV2PresignedUrlDefalut(url, headers, querys, accessKey, secretKey, method, bucketName, objectName, false, expires);

        return presignedUrl;
    }
    
    public static String Object_DeleteMulit_V2_PresignedUrl(String httpOrHttps,String host,int port,String regionName,String accessKey, String secretKey, String bucketName, String bodyString, Map<String, String> headers,Map<String, String> querys) {
        
        URL url=null;
        try {
            url = new URL(httpOrHttps+"://"+host+":"+port+"/"+bucketName+"?delete");
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        
        String method="POST";
        
        if (querys==null) {
            querys=new HashMap<String, String>();
        }
        querys.put("delete", "");
        
        long expiresIn=0L;
        if (querys.containsKey("X-Amz-Expires")) {
            expiresIn=Long.parseLong(querys.get("X-Amz-Expires"));
        }else {
            expiresIn=7 * 24 * 60 * 60;
            
        }
        Date now = new Date();
        long expiresTime= now.getTime()+expiresIn;
        String expires= String.valueOf(expiresTime);
 
        String presignedUrl=V2SignClient.computeV2PresignedUrlDefalut(url, headers, querys, accessKey, secretKey, method, bucketName, null, false, expires);

        return presignedUrl;
    }
    
    
    public static String Object_Put_V4_PresignedUrl(String httpOrHttps,String host,int port,String regionName,String accessKey, String secretKey, String bucketName, String objectName, String objectContent, Map<String, String> headers,Map<String, String> querys)  {
        String method="PUT";
        URL url=null;
        try {
            url = new URL(httpOrHttps+"://"+host+":"+port+"/"+bucketName +"/" + URLEncoder.encode(objectName, "UTF-8"));
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        
        if (querys==null) {
            querys = new HashMap<String, String>();
        }
        if (!querys.containsKey("X-Amz-Expires")) {
            int expiresIn = 7 * 24 * 60 * 60;
            querys.put("X-Amz-Expires", "" + expiresIn);
        }
        
        String presignedUrl=V4SignClient.computeV4PresignedUrlDefalut(headers, querys, accessKey, secretKey, url, method, SERVICE_NAME, regionName);
        
        return presignedUrl;
    }
    
    public static String Object_Get_V4_PresignedUrl(String httpOrHttps,String host,int port,String regionName,String accessKey, String secretKey, String bucketName, String objectName, Map<String, String> headers,Map<String, String> querys){
        
        String method="GET";
        URL url=null;
        try {
            url = new URL(httpOrHttps+"://"+host+":"+port+"/"+bucketName +"/" + URLEncoder.encode(objectName, "UTF-8"));
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        
        if (querys==null) {
            querys = new HashMap<String, String>();
        }
        if (!querys.containsKey("X-Amz-Expires")) {
            int expiresIn = 7 * 24 * 60 * 60;
            querys.put("X-Amz-Expires", "" + expiresIn);
        }
        
        String presignedUrl=V4SignClient.computeV4PresignedUrlDefalut(headers, querys, accessKey, secretKey, url, method, SERVICE_NAME, regionName);
        
        return presignedUrl;
    }
    
    public static String Object_Head_V4_PresignedUrl(String httpOrHttps,String host,int port,String regionName,String accessKey, String secretKey, String bucketName, String objectName, Map<String, String> headers,Map<String, String> querys){
        String method="HEAD";
        URL url=null;
        try {
            url = new URL(httpOrHttps+"://"+host+":"+port+"/"+bucketName +"/" + URLEncoder.encode(objectName, "UTF-8"));
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        
        if (querys==null) {
            querys = new HashMap<String, String>();
        }
        if (!querys.containsKey("X-Amz-Expires")) {
            int expiresIn = 7 * 24 * 60 * 60;
            querys.put("X-Amz-Expires", "" + expiresIn);
        }
        
        String presignedUrl=V4SignClient.computeV4PresignedUrlDefalut(headers, querys, accessKey, secretKey, url, method, SERVICE_NAME, regionName);
        
        return presignedUrl;
        
    }
    
    
    public static String Object_Delete_V4_PresignedUrl(String httpOrHttps,String host,int port,String regionName,String accessKey, String secretKey, String bucketName, String objectName, Map<String, String> headers,Map<String, String> querys){
        
        String method="DELETE";
        URL url=null;
        try {
            url = new URL(httpOrHttps+"://"+host+":"+port+"/"+bucketName +"/" + URLEncoder.encode(objectName, "UTF-8"));
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        if (querys==null) {
            querys = new HashMap<String, String>();
        }
        if (!querys.containsKey("X-Amz-Expires")) {
            int expiresIn = 7 * 24 * 60 * 60;
            querys.put("X-Amz-Expires", "" + expiresIn);
        }
        
        String presignedUrl=V4SignClient.computeV4PresignedUrlDefalut(headers, querys, accessKey, secretKey, url, method, SERVICE_NAME, regionName);
        
        return presignedUrl;
    }
    
    
    public static String Object_InitialMultipartUpload_V4_PresignedUrl(String httpOrHttps,String host,int port,String regionName,String accessKey, String secretKey, String bucketName, String objectName, Map<String, String> headers,Map<String, String> querys){
        URL url=null;
        try {
            url = new URL(httpOrHttps+"://"+host+":"+port+"/"+bucketName+"/"+objectName+"?uploads");
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        
        String method="POST"; 
        if (querys==null) {
            querys = new HashMap<String, String>();
        }
        querys.put("uploads", "");
        
        if (!querys.containsKey("X-Amz-Expires")) {
            int expiresIn = 7 * 24 * 60 * 60;
            querys.put("X-Amz-Expires", "" + expiresIn);
        }
        
        String presignedUrl=V4SignClient.computeV4PresignedUrlDefalut(headers, querys, accessKey, secretKey, url, method, SERVICE_NAME, regionName);
        
        return presignedUrl;
    }
    
    public static String  Object_UploadPart_V4_PresignedUrl(String httpOrHttps,String host,int port,String regionName,String accessKey, String secretKey, String bucketName, String objectName, String uploadId,int partNum,String partContent,Map<String, String> headers,Map<String, String> querys){
        URL url=null;
        try {
            url = new URL(httpOrHttps+"://"+host+":"+port+"/"+bucketName+"/"+objectName+"?uploadId="+uploadId+"&partNumber="+partNum);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
       
        String method="PUT";
        
        if (headers==null) {
            headers = new HashMap<String, String>();
        }
        HashMap<String, String> map = new HashMap<String,String>();
        map.putAll(headers);
        map.put("Content-Length", partContent.length()+"");
        if (querys==null) {
            querys = new HashMap<String, String>();
        }
        querys.put("partNumber", String.valueOf(partNum));
        querys.put("uploadId", uploadId);
        
        if (!querys.containsKey("X-Amz-Expires")) {
            int expiresIn = 7 * 24 * 60 * 60;
            querys.put("X-Amz-Expires", "" + expiresIn);
        }
        
        String presignedUrl=V4SignClient.computeV4PresignedUrlDefalut(headers, querys, accessKey, secretKey, url, method, SERVICE_NAME, regionName);
        
        return presignedUrl;
    }
    
    public static String Object_ListPart_V4_PresignedUrl(String httpOrHttps,String host,int port,String regionName,String accessKey, String secretKey, String bucketName, String objectName, String uploadId, Map<String, String> headers,Map<String, String> querys){
        URL url=null;
        try {
            url = new URL(httpOrHttps+"://"+host+":"+port+"/"+bucketName+"/"+objectName+"?uploadId="+uploadId);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
       
        String method="GET";
        if (querys==null) {
            querys = new HashMap<String, String>();
        }

        querys.put("uploadId", uploadId);
        
        if (!querys.containsKey("X-Amz-Expires")) {
            int expiresIn = 7 * 24 * 60 * 60;
            querys.put("X-Amz-Expires", "" + expiresIn);
        }
        
        String presignedUrl=V4SignClient.computeV4PresignedUrlDefalut(headers, querys, accessKey, secretKey, url, method, SERVICE_NAME, regionName);
        
       return presignedUrl;
    }
   
    public static String Object_CompleteMultipartUpload_V4_PresignedUrl(String httpOrHttps,String host,int port,String regionName,String accessKey, String secretKey, String bucketName, String objectName, String uploadId, Map<String, String> headers,Map<String, String> querys){
        
        
        URL url=null;
        try {
            url = new URL(httpOrHttps+"://"+host+":"+port+"/"+bucketName+"/"+objectName+"?uploadId="+uploadId);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
       
        String method="POST";
        if (headers==null) {
            headers = new HashMap<String, String>();
        } 
        
        headers.put("content-type", "application/x-www-form-urlencoded");
        if (querys==null) {
            querys = new HashMap<String, String>();
        }

        querys.put("uploadId", uploadId);
        
        if (!querys.containsKey("X-Amz-Expires")) {
            int expiresIn = 7 * 24 * 60 * 60;
            querys.put("X-Amz-Expires", "" + expiresIn);
        }
 
        String presignedUrl=V4SignClient.computeV4PresignedUrlDefalut(headers, querys, accessKey, secretKey, url, method, SERVICE_NAME, regionName);
        
        return presignedUrl;
    }
    
    public static String Object_AboutMultipartUpload_V4_PresignedUrl(String httpOrHttps,String host,int port,String regionName,String accessKey, String secretKey, String bucketName, String objectName, String uploadId, Map<String, String> headers,Map<String, String> querys){
        URL url=null;
        try {
            url = new URL(httpOrHttps+"://"+host+":"+port+"/"+bucketName+"/"+objectName+"?uploadId="+uploadId);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
       
        String method="DELETE";
        
        if (querys==null) {
            querys = new HashMap<String, String>();
        }
        querys.put("uploadId", uploadId);
        
        if (!querys.containsKey("X-Amz-Expires")) {
            int expiresIn = 7 * 24 * 60 * 60;
            querys.put("X-Amz-Expires", "" + expiresIn);
        }
        
        String presignedUrl=V4SignClient.computeV4PresignedUrlDefalut(headers, querys, accessKey, secretKey, url, method, SERVICE_NAME, regionName);
        
        return presignedUrl;
    }
    
    
    
    public static HttpURLConnection creatConn(String presignedUrl,String method,Map<String, String> headers) {
        HttpURLConnection conn=null;
        try {
            if (presignedUrl.startsWith("https")) {
                conn=HttpConnectionSSLRequestUtils.createhttpsConn(new URL(presignedUrl), method, headers);
            }else {
                conn=CreatehttpConn(new URL(presignedUrl), method, headers);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        
        return conn;
    }
    
    public static HttpURLConnection CreatehttpConn(URL url, String method, Map<String, String> headers) {
       
        try {
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod(method);
            if (headers != null) {
//                System.out.println("--------- Request headers ---------");
                for (String headerKey : headers.keySet()) {
//                    System.out.println(headerKey + ": " + headers.get(headerKey));
                    connection.setRequestProperty(headerKey, headers.get(headerKey));
                }
            }
            
            connection.setUseCaches(false);
            connection.setDoInput(true);
            connection.setDoOutput(true);
            return connection;
        } catch (Exception e) {
            e.printStackTrace();
        }
        
       return null;
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
    
    public static String createCompleteMultipartUploadBody(Map<String, String> partEtagMap) {
        String completeString="";
        String partAndEtagString="";
        for (String partKey : partEtagMap.keySet()) {
            
            partAndEtagString+="<Part>" + 
                    "<PartNumber>"+partKey+"</PartNumber>" + 
                    "<ETag>"+partEtagMap.get(partKey)+"</ETag>" + 
                    "</Part>" + 
                    "";
        }
        completeString="<CompleteMultipartUpload>"+partAndEtagString+"</CompleteMultipartUpload>";
        
        return completeString;
    }
    
    public static String createDeleteMulitBody(List<String> objectNames,boolean quiet) {
        String objectsListString="";
        for (int i = 0; i < objectNames.size(); i++) {
            objectsListString+="<Object>" + 
                    "<Key>"+objectNames.get(i)+"</Key>" + 
                    "</Object>" + 
                    "";
        }
        String delobjectsString="<Delete>" + 
                "<Quiet>"+quiet+"</Quiet>" + objectsListString+
                "</Delete>" + 
                "";
        return delobjectsString;
    }
    
    public static String getMD5(String body) {
        MessageDigest md =null;
        try {
            md = MessageDigest.getInstance("MD5");
            md.update(body.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        String contentMD5=BinaryUtils.toBase64(md.digest());
        
        return contentMD5;
    }
    
}
