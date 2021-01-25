package cn.ctyun.oos.accesscontroller;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;

import org.apache.commons.io.IOUtils;
import org.apache.http.entity.ContentType;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.xml.sax.InputSource;

import com.amazonaws.util.BinaryUtils;

import cn.ctyun.common.Consts;
import cn.ctyun.oos.iam.test.V4TestUtils;

/**
 * v4签名
 * 需要启动jettyserver、disker、iam
 *
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SignatureV4Test {
    private static final String OOS_DOMAIN = "http://oos-sd.ctyunapi.cn/";
    private static final String OOS_HOST = "oos-sd.ctyunapi.cn";
    private static final String OOS_DOMAIN_IAM = "http://oos-sd-iam.ctyunapi.cn:9097/";
    private static final String OOS_HOST_IAM = "oos-sd-iam.ctyunapi.cn:9097";
    private static final String regionName = "sd";
    private static final String regionNameIam = "sd";
    
    private static final String accessKey = "test_user8_6463084869102845087@a.cn88";
    private static final String secretKey = "secretKey88";
    
    private static final String bucketName = "signaturev4";
    private static final String tmpBucket = "tmp-bucket";
    private static final String objectName = "test01中文繁體";
    private static final String copyObjectName = "test01-copy中文繁體";
    private static final String partObjectName = "test01-part中文繁體";
    private static final String objectContent = "hello world!12345!@#$%^&*()_+\":[]\\?>,.adsf中文繁體";
    private static SimpleDateFormat timeFormatter = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
    private static SimpleDateFormat dateFormatter = new SimpleDateFormat("yyyyMMdd");
    
    public static final String EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
    public static final String SCHEME = "AWS4";
    public static final String ALGORITHM = "HMAC-SHA256";
    public static final String TERMINATOR = "aws4_request";
    public static final String SERVICE_NAME = "s3";
    static ContentType contentType = ContentType.create("text/plain", Consts.CS_UTF8);
    
    static{
        TimeZone utc = TimeZone.getTimeZone("UTC");
        timeFormatter.setTimeZone(utc);
        dateFormatter.setTimeZone(utc);
    }
    
    //GetService
    @Test
    public void test01_getService_ok() throws Exception{
        URL url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN);
        HttpURLConnection connection = OOSTestUtilsDev.invokeHttpsRequest(url, "GET", accessKey, secretKey);
        connection.connect();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        assertTrue(xml.contains("ListAllMyBucketsResult")&&xml.contains(bucketName));
        if (connection != null) {
            connection.disconnect();
        }
    }
    
    //Put delete Bucket
    @Test
    public void test02_put_del_bucket_ok() throws Exception{
        URL url = new URL(OOS_DOMAIN + tmpBucket);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
        String authorization = V4TestUtils.computeSignature(headers, null, EMPTY_BODY_SHA256, accessKey, secretKey, 
                url, "PUT", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "PUT", headers);
        connection.connect();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        if (connection != null) {
            connection.disconnect();
        }
        //delete 
        URL url2 = new URL(OOS_DOMAIN + tmpBucket);
        Map<String, String> headers2 = new HashMap<String, String>();
        headers2.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
        String authorization2 = V4TestUtils.computeSignature(headers2, null, EMPTY_BODY_SHA256, accessKey, secretKey, 
                url2, "DELETE", "s3", regionName);
        headers2.put("Authorization", authorization2);
        HttpURLConnection connection2 = readyConn(url2, "DELETE", headers2);
        connection2.connect();
        int code2 = connection2.getResponseCode();
        String xml2 = IOUtils.toString(connection2.getInputStream());
        assertEquals(204, code2);
        System.out.println(xml2);
        if (connection2 != null) {
            connection2.disconnect();
        }
    }
    //Get Bucket location
    @Test
    public void test03_getBucketLocation_ok() throws Exception{
        URL url = new URL(OOS_DOMAIN + bucketName + "?location");
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
        Map<String, String> query = new HashMap<String, String>();
        query.put("location", "");
        String authorization = V4TestUtils.computeSignature(headers, query, EMPTY_BODY_SHA256, accessKey, secretKey, 
                url, "GET", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "GET", headers);
        connection.connect();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        assertTrue(xml.contains("BucketConfiguration") && xml.contains("LocationList"));
        if (connection != null) {
            connection.disconnect();
        }
    }
    //Get bucket acl
    @Test
    public void test04_getBucketAcl_ok() throws Exception{
        URL url = new URL(OOS_DOMAIN + bucketName + "?acl");
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
        Map<String, String> query = new HashMap<String, String>();
        query.put("acl", "");
        String authorization = V4TestUtils.computeSignature(headers, query, EMPTY_BODY_SHA256, accessKey, secretKey, 
                url, "GET", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "GET", headers);
        connection.connect();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        assertTrue(xml.contains("AccessControlPolicy") && xml.contains("Grantee"));
        if (connection != null) {
            connection.disconnect();
        }
    }
    
    //GET Bucket (List Objects)
    @Test
    public void test05_listObjects_ok() throws Exception{
        URL url = new URL(OOS_DOMAIN + bucketName );
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
        String authorization = V4TestUtils.computeSignature(headers, null, EMPTY_BODY_SHA256, accessKey, secretKey, 
                url, "GET", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "GET", headers);
        connection.connect();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        assertTrue(xml.contains("ListBucketResult") && xml.contains(bucketName));
        if (connection != null) {
            connection.disconnect();
        }
    }
    //put bucket policy,payload方式
    @Test
    public void test06_putBucketPolicy_ok() throws Exception{
        String policy = IOUtils.toString(new FileInputStream(System.getProperty("user.dir")+
                File.separator+"test"+File.separator+"cn"+File.separator+"ctyun"+
                File.separator+"oos"+File.separator+"server"+File.separator+"signaturev4" + File.separator +  "ipv4&6Policy"));
        URL url = new URL(OOS_DOMAIN + bucketName + "?policy");
        Map<String, String> headers = new HashMap<String, String>();
        String contentHashString = V4TestUtils.toHex(V4TestUtils.hash(policy));
        headers.put("x-amz-content-sha256", contentHashString);
        Map<String, String> query = new HashMap<String, String>();
        query.put("policy", "");
        String authorization = V4TestUtils.computeSignature(headers, query, contentHashString, accessKey, secretKey, 
                url, "PUT", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "PUT", headers);
        connection.connect();
        OutputStream out = connection.getOutputStream();
        out.write(policy.getBytes());
        out.flush();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        out.close();
        if (connection != null) {
            connection.disconnect();
        }
        //get
        URL url2 = new URL(OOS_DOMAIN + bucketName + "?policy");
        Map<String, String> headers2 = new HashMap<String, String>();
        headers2.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
        Map<String, String> query2 = new HashMap<String, String>();
        query2.put("policy", "");
        String authorization2 = V4TestUtils.computeSignature(headers2, query2, EMPTY_BODY_SHA256, accessKey, secretKey, 
                url2, "GET", "s3", regionName);
        headers2.put("Authorization", authorization2);
        HttpURLConnection connection2 = readyConn(url2, "GET", headers2);
        connection2.connect();
        int code2 = connection2.getResponseCode();
        String xml2 = IOUtils.toString(connection2.getInputStream());
        assertEquals(200, code2);
        System.out.println(xml2);
        assertTrue(xml2.contains("ipv4&6policy") && xml2.contains("1030::C9B4:FF12:48AA:2222") && xml2.contains(bucketName));
        if (connection2 != null) {
            connection2.disconnect();
        }
        //del
        URL url3 = new URL(OOS_DOMAIN + bucketName + "?policy");
        Map<String, String> headers3 = new HashMap<String, String>();
        headers3.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
        Map<String, String> query3 = new HashMap<String, String>();
        query3.put("policy", "");
        String authorization3 = V4TestUtils.computeSignature(headers3, query3, EMPTY_BODY_SHA256, accessKey, secretKey, 
                url3, "DELETE", "s3", regionName);
        headers3.put("Authorization", authorization3);
        HttpURLConnection connection3 = readyConn(url3, "DELETE", headers3);
        connection3.connect();
        int code3 = connection3.getResponseCode();
        String xml3 = IOUtils.toString(connection3.getInputStream());
        assertEquals(200, code3);
        System.out.println(xml3);
        if (connection3 != null) {
            connection3.disconnect();
        }
    }
    
    //put get del bucket policy, UNSIGNED_PAYLOAD方式
    @Test
    public void test07_put_get_del_bucketPolicy_no_payload_ok() throws Exception{
        String policy = IOUtils.toString(new FileInputStream(System.getProperty("user.dir")+
                File.separator+"test"+File.separator+"cn"+File.separator+"ctyun"+
                File.separator+"oos"+File.separator+"server"+File.separator+"signaturev4" + File.separator +  "ipv4&6Policy"));
        URL url = new URL(OOS_DOMAIN + bucketName + "?policy");
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", UNSIGNED_PAYLOAD);
        Map<String, String> query = new HashMap<String, String>();
        query.put("policy", "");
        String authorization = V4TestUtils.computeSignature(headers, query, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                url, "PUT", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "PUT", headers);
        connection.connect();
        OutputStream out = connection.getOutputStream();
        out.write(policy.getBytes());
        out.flush();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        out.close();        
        if (connection != null) {
            connection.disconnect();
        }
        //get
        URL url2 = new URL(OOS_DOMAIN + bucketName + "?policy");
        Map<String, String> headers2 = new HashMap<String, String>();
        headers2.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
        Map<String, String> query2 = new HashMap<String, String>();
        query2.put("policy", "");
        String authorization2 = V4TestUtils.computeSignature(headers2, query2, EMPTY_BODY_SHA256, accessKey, secretKey, 
                url2, "GET", "s3", regionName);
        headers2.put("Authorization", authorization2);
        HttpURLConnection connection2 = readyConn(url2, "GET", headers2);
        connection2.connect();
        int code2 = connection2.getResponseCode();
        String xml2 = IOUtils.toString(connection2.getInputStream());
        assertEquals(200, code2);
        System.out.println(xml2);
        assertTrue(xml2.contains("ipv4&6policy") && xml2.contains("1030::C9B4:FF12:48AA:2222") && xml2.contains(bucketName));
        if (connection2 != null) {
            connection2.disconnect();
        }
        //del
        URL url3 = new URL(OOS_DOMAIN + bucketName + "?policy");
        Map<String, String> headers3 = new HashMap<String, String>();
        headers3.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
        Map<String, String> query3 = new HashMap<String, String>();
        query3.put("policy", "");
        String authorization3 = V4TestUtils.computeSignature(headers3, query3, EMPTY_BODY_SHA256, accessKey, secretKey, 
                url3, "DELETE", "s3", regionName);
        headers3.put("Authorization", authorization3);
        HttpURLConnection connection3 = readyConn(url3, "DELETE", headers3);
        connection3.connect();
        int code3 = connection3.getResponseCode();
        String xml3 = IOUtils.toString(connection3.getInputStream());
        assertEquals(200, code3);
        System.out.println(xml3);
        if (connection3 != null) {
            connection3.disconnect();
        }
    }
    
    //put get del bucket website,payload方式
    @Test
    public void test08_put_get_del_bucketWebsite_ok() throws Exception{
        String policy = IOUtils.toString(new FileInputStream(System.getProperty("user.dir")+
                File.separator+"test"+File.separator+"cn"+File.separator+"ctyun"+
                File.separator+"oos"+File.separator+"server"+File.separator+"signaturev4" + File.separator +  "website"));
        URL url = new URL(OOS_DOMAIN + bucketName + "?website");
        Map<String, String> headers = new HashMap<String, String>();
        String contentHashString = V4TestUtils.toHex(V4TestUtils.hash(policy));
        headers.put("x-amz-content-sha256", contentHashString);
        Map<String, String> query = new HashMap<String, String>();
        query.put("website", "");
        String authorization = V4TestUtils.computeSignature(headers, query, contentHashString, accessKey, secretKey, 
                url, "PUT", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "PUT", headers);
        connection.connect();
        OutputStream out = connection.getOutputStream();
        out.write(policy.getBytes());
        out.flush();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        out.close();
        if (connection != null) {
            connection.disconnect();
        }
    }
    
    //put bucket policy, UNSIGNED_PAYLOAD方式
    @Test
    public void test09_putBucketWebsite_no_payload_ok() throws Exception{
        String policy = IOUtils.toString(new FileInputStream(System.getProperty("user.dir")+
                File.separator+"test"+File.separator+"cn"+File.separator+"ctyun"+
                File.separator+"oos"+File.separator+"server"+File.separator+"signaturev4" + File.separator +  "website"));
        URL url = new URL(OOS_DOMAIN + bucketName + "?website");
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", UNSIGNED_PAYLOAD);
        Map<String, String> query = new HashMap<String, String>();
        query.put("website", "");
        String authorization = V4TestUtils.computeSignature(headers, query, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                url, "PUT", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "PUT", headers);
        connection.connect();
        OutputStream out = connection.getOutputStream();
        out.write(policy.getBytes());
        out.flush();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        out.close();        
        if (connection != null) {
            connection.disconnect();
        }
    }
    
    // get bucket policy
    @Test
    public void test10_getBucketWebsite_ok() throws Exception{
        URL url = new URL(OOS_DOMAIN + bucketName + "?website");
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
        Map<String, String> query = new HashMap<String, String>();
        query.put("website", "");
        String authorization = V4TestUtils.computeSignature(headers, query, EMPTY_BODY_SHA256, accessKey, secretKey, 
                url, "GET", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "GET", headers);
        connection.connect();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        assertTrue(xml.contains("index.html") && xml.contains("404.html"));
        if (connection != null) {
            connection.disconnect();
        }
//        URL url2 = new URL(S3_DOMAIN + bucketNameS3 + "?website");
//        Map<String, String> headers2 = new HashMap<String, String>();
//        headers2.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
//        Map<String, String> query2 = new HashMap<String, String>();
//        query2.put("website", "");
//        String authorization2 = V4TestUtils.computeSignature(headers2, query2, EMPTY_BODY_SHA256, accessKeyS3, secretKeyS3, 
//                url2, "GET", "s3", regionNameS3);
//        headers2.put("Authorization", authorization2);
//        HttpURLConnection connection2 = readyConn(url2, "GET", headers2);
//        connection2.connect();
//        int code2 = connection2.getResponseCode();
//        String xml2 = IOUtils.toString(connection2.getInputStream());
//        System.out.println(xml2);
//        assertTrue(xml.contains("index.html") && xml.contains("404.html"));
//        assertEquals(200, code2);
//        if (connection2 != null) {
//            connection2.disconnect();
//        }
    }
    
    // delete bucket website
    @Test
    public void test11_deleteBucketWebsite_ok() throws Exception{
        URL url = new URL(OOS_DOMAIN + bucketName + "?website");
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
        Map<String, String> query = new HashMap<String, String>();
        query.put("website", "");
        String authorization = V4TestUtils.computeSignature(headers, query, EMPTY_BODY_SHA256, accessKey, secretKey, 
                url, "DELETE", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "DELETE", headers);
        connection.connect();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        if (connection != null) {
            connection.disconnect();
        }
//        URL url2 = new URL(S3_DOMAIN + bucketNameS3 + "?website");
//        Map<String, String> headers2 = new HashMap<String, String>();
//        headers2.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
//        Map<String, String> query2 = new HashMap<String, String>();
//        query2.put("website", "");
//        String authorization2 = V4TestUtils.computeSignature(headers2, query2, EMPTY_BODY_SHA256, accessKeyS3, secretKeyS3, 
//                url2, "GET", "s3", regionNameS3);
//        headers2.put("Authorization", authorization2);
//        HttpURLConnection connection2 = readyConn(url2, "GET", headers2);
//        connection2.connect();
//        int code2 = connection2.getResponseCode();
//        String xml2 = IOUtils.toString(connection2.getInputStream());
//        System.out.println(xml2);
//        assertEquals(200, code2);
//        if (connection2 != null) {
//            connection2.disconnect();
//        }
    }
    
    //put bucket logging,payload方式
    @Test
    public void test12_putBucketLogging_ok() throws Exception{
        String policy = IOUtils.toString(new FileInputStream(System.getProperty("user.dir")+
                File.separator+"test"+File.separator+"cn"+File.separator+"ctyun"+
                File.separator+"oos"+File.separator+"server"+File.separator+"signaturev4" + File.separator +  "logging"));
        URL url = new URL(OOS_DOMAIN + bucketName + "?logging");
        Map<String, String> headers = new HashMap<String, String>();
        String contentHashString = V4TestUtils.toHex(V4TestUtils.hash(policy));
        headers.put("x-amz-content-sha256", contentHashString);
        Map<String, String> query = new HashMap<String, String>();
        query.put("logging", "");
        String authorization = V4TestUtils.computeSignature(headers, query, contentHashString, accessKey, secretKey, 
                url, "PUT", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "PUT", headers);
        connection.connect();
        OutputStream out = connection.getOutputStream();
        out.write(policy.getBytes());
        out.flush();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        out.close();
        if (connection != null) {
            connection.disconnect();
        }
    }
    
    //put bucket logging, UNSIGNED_PAYLOAD方式
    @Test
    public void test13_putBucketLogging_no_payload_ok() throws Exception{
        String policy = IOUtils.toString(new FileInputStream(System.getProperty("user.dir")+
                File.separator+"test"+File.separator+"cn"+File.separator+"ctyun"+
                File.separator+"oos"+File.separator+"server"+File.separator+"signaturev4" + File.separator +  "logging"));
        URL url = new URL(OOS_DOMAIN + bucketName + "?logging");
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", UNSIGNED_PAYLOAD);
        Map<String, String> query = new HashMap<String, String>();
        query.put("logging", "");
        String authorization = V4TestUtils.computeSignature(headers, query, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                url, "PUT", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "PUT", headers);
        connection.connect();
        OutputStream out = connection.getOutputStream();
        out.write(policy.getBytes());
        out.flush();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        out.close();        
        if (connection != null) {
            connection.disconnect();
        }
    }
    
    // get bucket policy
    @Test
    public void test14_getBucketLogging_ok() throws Exception{
        URL url = new URL(OOS_DOMAIN + bucketName + "?logging");
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
        Map<String, String> query = new HashMap<String, String>();
        query.put("logging", "");
        String authorization = V4TestUtils.computeSignature(headers, query, EMPTY_BODY_SHA256, accessKey, secretKey, 
                url, "GET", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "GET", headers);
        connection.connect();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        assertTrue(xml.contains("BucketLoggingStatus") && xml.contains(bucketName));
        if (connection != null) {
            connection.disconnect();
        }
    }
    
    //List Multipart Uploads
    @Test
    public void test15_listMultipartUploads_ok() throws Exception{
        URL url = new URL(OOS_DOMAIN + bucketName + "?uploads");
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
        Map<String, String> query = new HashMap<String, String>();
        query.put("uploads", "");
        String authorization = V4TestUtils.computeSignature(headers, query, EMPTY_BODY_SHA256, accessKey, secretKey, 
                url, "GET", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "GET", headers);
        connection.connect();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        assertTrue(xml.contains("ListMultipartUploadsResult") && xml.contains(bucketName) && xml.contains("UploadIdMarker"));
        if (connection != null) {
            connection.disconnect();
        }
//        URL url = new URL(S3_DOMAIN + bucketNameS3 + "?uploads");
//        Map<String, String> headers = new HashMap<String, String>();
//        headers.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
//        Map<String, String> query = new HashMap<String, String>();
//        query.put("uploads", "");
//        String authorization = V4TestUtils.computeSignature(headers, query, EMPTY_BODY_SHA256, accessKeyS3, secretKeyS3, 
//                url, "GET", "s3", regionNameS3);
//        headers.put("Authorization", authorization);
//        HttpURLConnection connection = readyConn(url, "GET", headers);
//        connection.connect();
//        int code = connection.getResponseCode();
//        String xml = IOUtils.toString(connection.getInputStream());
//        assertEquals(200, code);
//        System.out.println(xml);
//        assertTrue(xml.contains("ListMultipartUploadsResult") && xml.contains(bucketNameS3) && xml.contains("UploadIdMarker"));
//        if (connection != null) {
//            connection.disconnect();
//        }
    }
    
    //head bucket
    @Test
    public void test16_headBucket() throws Exception{
        URL url = new URL(OOS_DOMAIN + bucketName);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
        String authorization = V4TestUtils.computeSignature(headers, null, EMPTY_BODY_SHA256, accessKey, secretKey, 
                url, "HEAD", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "HEAD", headers);
        connection.connect();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        if (connection != null) {
            connection.disconnect();
        }
//        URL url = new URL(S3_DOMAIN + bucketNameS3);
//        Map<String, String> headers = new HashMap<String, String>();
//        headers.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
//        String authorization = V4TestUtils.computeSignature(headers, null, EMPTY_BODY_SHA256, accessKeyS3, secretKeyS3, 
//                url, "HEAD", "s3", regionNameS3);
//        headers.put("Authorization", authorization);
//        HttpURLConnection connection = readyConn(url, "HEAD", headers);
//        connection.connect();
//        int code = connection.getResponseCode();
//        String xml = IOUtils.toString(connection.getInputStream());
//        assertEquals(200, code);
//        System.out.println(xml);
//        if (connection != null) {
//            connection.disconnect();
//        }
    }
    
    
    //put bucket lifecycle,payload方式
    @Test
    public void test17_putBucketLifecycle_ok() throws Exception{
        String policy = IOUtils.toString(new FileInputStream(System.getProperty("user.dir")+
                File.separator+"test"+File.separator+"cn"+File.separator+"ctyun"+
                File.separator+"oos"+File.separator+"server"+File.separator+"signaturev4" + File.separator +  "lifecycle"));
        URL url = new URL(OOS_DOMAIN + bucketName + "?lifecycle");
        Map<String, String> headers = new HashMap<String, String>();
        String contentHashString = V4TestUtils.toHex(V4TestUtils.hash(policy));
        headers.put("x-amz-content-sha256", contentHashString);
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(policy.getBytes());
        Map<String, String> query = new HashMap<String, String>();
        query.put("lifecycle", "");
        String authorization = V4TestUtils.computeSignature(headers, query, contentHashString, accessKey, secretKey, 
                url, "PUT", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "PUT", headers);
        connection.setRequestProperty("Content-MD5",BinaryUtils.toBase64(md.digest()));
        connection.connect();
        OutputStream out = connection.getOutputStream();
        out.write(policy.getBytes());
        out.flush();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        out.close();
        if (connection != null) {
            connection.disconnect();
        }
    }
    
    //put bucket lifecycle, UNSIGNED_PAYLOAD方式
    @Test
    public void test18_putBucketLifecycle_no_payload_ok() throws Exception{
        String policy = IOUtils.toString(new FileInputStream(System.getProperty("user.dir")+
                File.separator+"test"+File.separator+"cn"+File.separator+"ctyun"+
                File.separator+"oos"+File.separator+"server"+File.separator+"signaturev4" + File.separator +  "lifecycle"));
        URL url = new URL(OOS_DOMAIN + bucketName + "?lifecycle");
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", UNSIGNED_PAYLOAD);
        Map<String, String> query = new HashMap<String, String>();
        query.put("lifecycle", "");
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(policy.getBytes());
        String md5Str = BinaryUtils.toBase64(md.digest());
        headers.put("Content-MD5", md5Str);
        String authorization = V4TestUtils.computeSignature(headers, query, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                url, "PUT", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "PUT", headers);
        connection.setRequestProperty("Content-MD5",md5Str);
        connection.connect();
        OutputStream out = connection.getOutputStream();
        out.write(policy.getBytes());
        out.flush();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        out.close();        
        if (connection != null) {
            connection.disconnect();
        }
    }
    
    // get bucket lifecycle
    @Test
    public void test19_getBucketLifecycle_ok() throws Exception{
        URL url = new URL(OOS_DOMAIN + bucketName + "?lifecycle");
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
        Map<String, String> query = new HashMap<String, String>();
        query.put("lifecycle", "");
        String authorization = V4TestUtils.computeSignature(headers, query, EMPTY_BODY_SHA256, accessKey, secretKey, 
                url, "GET", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "GET", headers);
        connection.connect();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        assertTrue(xml.contains("LifecycleConfiguration"));
        if (connection != null) {
            connection.disconnect();
        }
//        URL url2 = new URL(S3_DOMAIN + bucketNameS3 + "?lifecycle");
//        Map<String, String> headers2 = new HashMap<String, String>();
//        headers2.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
//        Map<String, String> query2 = new HashMap<String, String>();
//        query2.put("lifecycle", "");
//        String authorization2 = V4TestUtils.computeSignature(headers2, query2, EMPTY_BODY_SHA256, accessKeyS3, secretKeyS3, 
//                url2, "GET", "s3", regionNameS3);
//        headers2.put("Authorization", authorization2);
//        HttpURLConnection connection2 = readyConn(url2, "GET", headers2);
//        connection2.connect();
//        int code2 = connection2.getResponseCode();
//        String xml2 = IOUtils.toString(connection2.getInputStream());
//        System.out.println(xml2);
//        assertEquals(200, code2);
//        assertTrue(xml.contains("LifecycleConfiguration"));
//        if (connection2 != null) {
//            connection2.disconnect();
//        }
    }
    
    // delete bucket policy
    @Test
    public void test20_deleteBucketLifecycle_ok() throws Exception{
        URL url = new URL(OOS_DOMAIN + bucketName + "?lifecycle");
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
        Map<String, String> query = new HashMap<String, String>();
        query.put("lifecycle", "");
        String authorization = V4TestUtils.computeSignature(headers, query, EMPTY_BODY_SHA256, accessKey, secretKey, 
                url, "DELETE", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "DELETE", headers);
        connection.connect();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(204, code);
        System.out.println(xml);
        if (connection != null) {
            connection.disconnect();
        }
    }
    
    //put bucket accelerate,payload方式
    @Test
    public void test21_putBucketAccelerate_ok() throws Exception{
        String policy = IOUtils.toString(new FileInputStream(System.getProperty("user.dir")+
                File.separator+"test"+File.separator+"cn"+File.separator+"ctyun"+
                File.separator+"oos"+File.separator+"server"+File.separator+"signaturev4" + File.separator +  "accelerate"));
        URL url = new URL(OOS_DOMAIN + bucketName + "?accelerate");
        Map<String, String> headers = new HashMap<String, String>();
        String contentHashString = V4TestUtils.toHex(V4TestUtils.hash(policy));
        headers.put("x-amz-content-sha256", contentHashString);
        Map<String, String> query = new HashMap<String, String>();
        query.put("accelerate", "");
        String authorization = V4TestUtils.computeSignature(headers, query, contentHashString, accessKey, secretKey, 
                url, "PUT", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "PUT", headers);
        connection.connect();
        OutputStream out = connection.getOutputStream();
        out.write(policy.getBytes());
        out.flush();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        out.close();
        if (connection != null) {
            connection.disconnect();
        }
    }
    
    //put bucket accelerate, UNSIGNED_PAYLOAD方式
    @Test
    public void test22_putBucketAccelerate_no_payload_ok() throws Exception{
        String policy = IOUtils.toString(new FileInputStream(System.getProperty("user.dir")+
                File.separator+"test"+File.separator+"cn"+File.separator+"ctyun"+
                File.separator+"oos"+File.separator+"server"+File.separator+"signaturev4" + File.separator +  "accelerate"));
        URL url = new URL(OOS_DOMAIN + bucketName + "?accelerate");
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", UNSIGNED_PAYLOAD);
        Map<String, String> query = new HashMap<String, String>();
        query.put("accelerate", "");
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(policy.getBytes());
        String md5Str = BinaryUtils.toBase64(md.digest());
        headers.put("Content-MD5", md5Str);
        String authorization = V4TestUtils.computeSignature(headers, query, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                url, "PUT", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "PUT", headers);
        connection.setRequestProperty("Content-MD5",md5Str);
        connection.connect();
        OutputStream out = connection.getOutputStream();
        out.write(policy.getBytes());
        out.flush();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        out.close();        
        if (connection != null) {
            connection.disconnect();
        }
    }
    
    // get bucket accelerate
    @Test
    public void test23_getBucketAccelerate_ok() throws Exception{
        URL url = new URL(OOS_DOMAIN + bucketName + "?accelerate");
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
        Map<String, String> query = new HashMap<String, String>();
        query.put("accelerate", "");
        String authorization = V4TestUtils.computeSignature(headers, query, EMPTY_BODY_SHA256, accessKey, secretKey, 
                url, "GET", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "GET", headers);
        connection.connect();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        assertTrue(xml.contains("AccelerateConfiguration"));
        if (connection != null) {
            connection.disconnect();
        }
    }
    
    //put bucket cors,payload方式
    @Test
    public void test24_putBucketCors_ok() throws Exception{
        String policy = IOUtils.toString(new FileInputStream(System.getProperty("user.dir")+
                File.separator+"test"+File.separator+"cn"+File.separator+"ctyun"+
                File.separator+"oos"+File.separator+"server"+File.separator+"signaturev4" + File.separator +  "cors"));
        URL url = new URL(OOS_DOMAIN + bucketName + "?cors");
        Map<String, String> headers = new HashMap<String, String>();
        String contentHashString = V4TestUtils.toHex(V4TestUtils.hash(policy));
        headers.put("x-amz-content-sha256", contentHashString);
        Map<String, String> query = new HashMap<String, String>();
        query.put("cors", "");
        String authorization = V4TestUtils.computeSignature(headers, query, contentHashString, accessKey, secretKey, 
                url, "PUT", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "PUT", headers);
        connection.connect();
        OutputStream out = connection.getOutputStream();
        out.write(policy.getBytes());
        out.flush();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        out.close();
        if (connection != null) {
            connection.disconnect();
        }
    }
    
    //put bucket cors, UNSIGNED_PAYLOAD方式
    @Test
    public void test25_putBucketCors_no_payload_ok() throws Exception{
        String policy = IOUtils.toString(new FileInputStream(System.getProperty("user.dir")+
                File.separator+"test"+File.separator+"cn"+File.separator+"ctyun"+
                File.separator+"oos"+File.separator+"server"+File.separator+"signaturev4" + File.separator +  "cors"));
        URL url = new URL(OOS_DOMAIN + bucketName + "?cors");
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", UNSIGNED_PAYLOAD);
        Map<String, String> query = new HashMap<String, String>();
        query.put("cors", "");
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(policy.getBytes());
        String md5Str = BinaryUtils.toBase64(md.digest());
        headers.put("Content-MD5", md5Str);
        String authorization = V4TestUtils.computeSignature(headers, query, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                url, "PUT", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "PUT", headers);
        connection.setRequestProperty("Content-MD5",md5Str);
        connection.connect();
        OutputStream out = connection.getOutputStream();
        out.write(policy.getBytes());
        out.flush();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        out.close();        
        if (connection != null) {
            connection.disconnect();
        }
    }
    
    // get bucket cors
    @Test
    public void test26_getBucketCors_ok() throws Exception{
        URL url = new URL(OOS_DOMAIN + bucketName + "?cors");
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
        Map<String, String> query = new HashMap<String, String>();
        query.put("cors", "");
        String authorization = V4TestUtils.computeSignature(headers, query, EMPTY_BODY_SHA256, accessKey, secretKey, 
                url, "GET", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "GET", headers);
        connection.connect();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        assertTrue(xml.contains("CORSConfiguration"));
        if (connection != null) {
            connection.disconnect();
        }
    }
    
    // delete bucket cors
    @Test
    public void test27_deleteBucketCors_ok() throws Exception{
        URL url = new URL(OOS_DOMAIN + bucketName + "?cors");
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
        Map<String, String> query = new HashMap<String, String>();
        query.put("cors", "");
        String authorization = V4TestUtils.computeSignature(headers, query, EMPTY_BODY_SHA256, accessKey, secretKey, 
                url, "DELETE", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "DELETE", headers);
        connection.connect();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        if (connection != null) {
            connection.disconnect();
        }
    }
    
    /** 正常 put object  payload  checksum
     * */ 
    @Test
    public void test28_put_object_payload_ok() throws Exception{
        URL url = new URL(OOS_DOMAIN + bucketName +"/" + URLEncoder.encode(objectName, "UTF-8"));
        byte[] contentHash = V4TestUtils.hash(objectContent);
        String contentHashString = V4TestUtils.toHex(contentHash);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", contentHashString);
        headers.put("content-length", objectContent.getBytes().length+"");
        headers.put("x-amz-storage-class", "REDUCED_REDUNDANCY");
        String authorization = V4TestUtils.computeSignature(headers, null, contentHashString, accessKey, secretKey, 
                new URL(OOS_DOMAIN + bucketName +"/" + objectName), "PUT", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "PUT", headers);
        connection.connect();
        OutputStream wr = connection.getOutputStream();
        wr.write(objectContent.getBytes());
        wr.flush();
        wr.close();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        System.out.println(code + ":" + xml);
        assertEquals(200, code);
        if (connection != null) {
            connection.disconnect();
        }
    }
    
    /**get object
     * @throws Exception
     */
    @Test
    public void test28_z1_get_object_ok() throws Exception{
        URL url = new URL("http://" + bucketName +"." + OOS_HOST +"/" + URLEncoder.encode(objectName, "UTF-8"));
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
        String authorization = V4TestUtils.computeSignature(headers, null, EMPTY_BODY_SHA256, accessKey, secretKey, 
                new URL("http://" + bucketName +"." + OOS_HOST +"/" + objectName), "GET", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "GET", headers);
        connection.connect();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream(),"UTF-8");
        System.out.println(code + ":" + xml);
        assertEquals(200, code);
        assertTrue(xml.equals(objectContent));
        if (connection != null) {
            connection.disconnect();
        }
    }
    
    /** 正常 put object no  checksum 
     * */ 
    @Test
    public void test29_put_object_no_checksum_ok() throws Exception{
        URL url = new URL(OOS_DOMAIN + bucketName +"/" + URLEncoder.encode(objectName, "UTF-8"));
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", UNSIGNED_PAYLOAD);
        headers.put("content-length", objectContent.getBytes().length+"");
        headers.put("x-amz-storage-class", "REDUCED_REDUNDANCY");
        String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                new URL(OOS_DOMAIN + bucketName +"/" + objectName), "PUT", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "PUT", headers);
        connection.connect();
        OutputStream wr = connection.getOutputStream();
        wr.write(objectContent.getBytes());
        wr.flush();
        wr.close();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        System.out.println(code + ":" + xml);
        assertEquals(200, code);
        if (connection != null) {
            connection.disconnect();
        }
    }
    
    /**get object
     * @throws Exception
     */
    @Test
    public void test30_get_object_ok() throws Exception{
        URL url = new URL(OOS_DOMAIN + bucketName +"/" + URLEncoder.encode(objectName, "UTF-8"));
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
        String authorization = V4TestUtils.computeSignature(headers, null, EMPTY_BODY_SHA256, accessKey, secretKey, 
                new URL(OOS_DOMAIN + bucketName +"/" + objectName), "GET", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "GET", headers);
        connection.connect();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream(),"UTF-8");
        System.out.println(code + ":" + xml);
        assertEquals(200, code);
        assertTrue(xml.equals(objectContent));
        if (connection != null) {
            connection.disconnect();
        }
    }
    
    /** 正常 delete object  
     * */ 
    @Test
    public void test31_del_object_ok() throws Exception{
        URL url = new URL(OOS_DOMAIN + bucketName +"/" + URLEncoder.encode(objectName, "UTF-8"));
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
        String authorization = V4TestUtils.computeSignature(headers, null, EMPTY_BODY_SHA256, accessKey, secretKey, 
                new URL(OOS_DOMAIN + bucketName +"/" + objectName), "DELETE", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "DELETE", headers);
        connection.connect();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        System.out.println(code + ":" + xml);
        assertEquals(204, code);
        if (connection != null) {
            connection.disconnect();
        }
    }
    
    
    /** PUT Object - Copy 
     * @throws Exception 
     * */
    @Test
    public void test31_copy_object_ok() throws Exception{
        test28_put_object_payload_ok();
        URL url = new URL(OOS_DOMAIN + bucketName +"/" + URLEncoder.encode(copyObjectName, "UTF-8"));
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
        headers.put("x-amz-copy-source","/"+bucketName+"/"+URLEncoder.encode(objectName, "UTF-8"));
        String authorization = V4TestUtils.computeSignature(headers, null, EMPTY_BODY_SHA256, accessKey, secretKey, 
                new URL(OOS_DOMAIN + bucketName +"/" + copyObjectName), "PUT", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "PUT", headers);
        connection.setRequestProperty("x-amz-copy-source", "/"+bucketName+"/"+URLEncoder.encode(objectName, "UTF-8"));
        connection.connect();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        System.out.println(code + ":" + xml);
        assertEquals(200, code);
        if (connection != null) {
            connection.disconnect();
        }
    }
    
    /** Initial Multipart Upload
     *  */
    @Test
    public void test32_initial_multipart_upload_ok() throws Exception{
        URL url = new URL(OOS_DOMAIN + bucketName +"/" + URLEncoder.encode(partObjectName, "UTF-8")+"?" + "uploads");
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
        Map<String, String> query = new HashMap<String, String>();
        query.put("uploads", "");
        String authorization = V4TestUtils.computeSignature(headers, query, EMPTY_BODY_SHA256, accessKey, secretKey, 
                new URL(OOS_DOMAIN + bucketName +"/" + partObjectName +"?uploads"), "POST", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "POST", headers);
        connection.connect();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        System.out.println(code + ":" + xml);
        assertEquals(200, code);
        assertTrue(xml.contains("InitiateMultipartUploadResult") && xml.contains(bucketName) && xml.contains("UploadId") && xml.contains(partObjectName));
        if (connection != null) {
            connection.disconnect();
        }
    }
    
    /** upload part 非 padload方式 以及 padload方式   list/complete part / copy part 
     * copy part 需要修改 copy part的大小限制为1
     * */
    @Test
    public void test33_upload_part_ok() throws Exception{
        String uploadId = getMultipartUploadId(false);
        byte[] b1= objectContent.substring(0, objectContent.length()/2).getBytes();
        byte[] b2= objectContent.substring(objectContent.length()/2).getBytes();
        URL url = new URL(OOS_DOMAIN + bucketName +"/" + URLEncoder.encode(partObjectName, "UTF-8") + "?partNumber=1" + "&uploadId=" + uploadId);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", UNSIGNED_PAYLOAD);
        Map<String, String> query = new HashMap<String, String>();
        query.put("partNumber", "1");
        query.put("uploadId", uploadId);
        String authorization = V4TestUtils.computeSignature(headers, query, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                new URL(OOS_DOMAIN + bucketName +"/" + partObjectName + "?partNumber=1" + "&uploadId=" + uploadId), "PUT", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "PUT", headers);
        connection.connect();
        
        OutputStream out = connection.getOutputStream();
        out.write(b1, 0, b1.length);
        out.flush();
        int code = connection.getResponseCode();
        assertEquals(200, code);
        String etag1 = connection.getHeaderField("ETag");
        System.out.println("etag1 =" + etag1);
        connection.disconnect();
        URL url2 = new URL(OOS_DOMAIN + bucketName +"/" + URLEncoder.encode(partObjectName, "UTF-8") + "?partNumber=2" + "&uploadId=" + uploadId);
        Map<String, String> headers2 = new HashMap<String, String>();
        String contentHashString = V4TestUtils.toHex(V4TestUtils.hash(objectContent.substring(objectContent.length()/2)));
        headers2.put("x-amz-content-sha256", contentHashString);
        Map<String, String> query2 = new HashMap<String, String>();
        query2.put("partNumber", "2");
        query2.put("uploadId", uploadId);
        String authorization2 = V4TestUtils.computeSignature(headers2, query2, contentHashString, accessKey, secretKey, 
                new URL(OOS_DOMAIN + bucketName +"/" + partObjectName + "?partNumber=2" + "&uploadId=" + uploadId), "PUT", "s3", regionName);
        headers2.put("Authorization", authorization2);
        HttpURLConnection connection2 = readyConn(url2, "PUT", headers2);
        connection2.connect();
        
        OutputStream out2 = connection2.getOutputStream();
        out2.write(b2);
        out2.flush();
        int code2 = connection2.getResponseCode();
        assertEquals(200, code2);
        String etag2 = connection2.getHeaderField("ETag");
        System.out.println("etag2 =" + etag2);
        connection2.disconnect();
        
        //Copy Part
        test29_put_object_no_checksum_ok();
        URL url5 = new URL(OOS_DOMAIN + bucketName +"/" + URLEncoder.encode(partObjectName, "UTF-8") + "?partNumber=3" + "&uploadId=" + uploadId);
        Map<String, String> headers5 = new HashMap<String, String>();
        headers5.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
        headers5.put("x-amz-copy-source", "/" + bucketName + "/" + URLEncoder.encode(objectName, "UTF-8"));
        headers5.put("x-amz-copy-source-range", "bytes=0-5");
        Map<String, String> query5 = new HashMap<String, String>();
        query5.put("partNumber", "3");
        query5.put("uploadId", uploadId);
        String authorization5 = V4TestUtils.computeSignature(headers5, query5, EMPTY_BODY_SHA256, accessKey, secretKey, 
                new URL(OOS_DOMAIN + bucketName +"/" + partObjectName + "?partNumber=3" + "&uploadId=" + uploadId), "PUT", "s3", regionName);
        headers5.put("Authorization", authorization5);
        HttpURLConnection connection5 = readyConn(url5, "PUT", headers5);
        connection5.connect();
        int code5 = connection5.getResponseCode();
        String xml5 = IOUtils.toString(connection5.getInputStream());
        System.out.println(xml5);
        assertEquals(200, code5);
        assertTrue(xml5.contains("CopyPartResult"));
        //List Part
        URL url4 = new URL(OOS_DOMAIN + bucketName +"/" + URLEncoder.encode(partObjectName, "UTF-8") + "?uploadId=" + uploadId);
        Map<String, String> headers4 = new HashMap<String, String>();
        headers4.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
        Map<String, String> query4 = new HashMap<String, String>();
        query4.put("uploadId", uploadId);
        String authorization4 = V4TestUtils.computeSignature(headers4, query4, EMPTY_BODY_SHA256, accessKey, secretKey, 
                new URL(OOS_DOMAIN + bucketName +"/" + partObjectName + "?uploadId=" + uploadId), "GET", "s3", regionName);
        headers4.put("Authorization", authorization4);
        HttpURLConnection connection4 = readyConn(url4, "GET", headers4);
        connection4.connect();
        int code4 = connection4.getResponseCode();
        assertEquals(200, code4);
        String xml4 = IOUtils.toString(connection4.getInputStream());
        assertTrue(xml4.contains("<PartNumber>1</PartNumber>")&&xml4.contains("<PartNumber>2</PartNumber>")&&xml4.contains("<PartNumber>3</PartNumber>") );
        String xml = "<CompleteMultipartUpload>"
                + "<Part><PartNumber>1</PartNumber><ETag>"+etag1 +"</ETag></Part>"
                + "<Part><PartNumber>2</PartNumber><ETag>"+ etag2 +"</ETag></Part>"
                +"</CompleteMultipartUpload>";
        
        URL url3 = new URL(OOS_DOMAIN + bucketName +"/" + URLEncoder.encode(partObjectName, "UTF-8") + "?uploadId=" + uploadId);
        Map<String, String> headers3 = new HashMap<String, String>();
        headers3.put("x-amz-content-sha256", UNSIGNED_PAYLOAD);
        headers3.put("Content-Length", xml.length()+"");
        headers3.put("content-type", "Content-Type=application/x-www-form-urlencoded");
        Map<String, String> query3 = new HashMap<String, String>();
        query3.put("uploadId", uploadId);
        String authorization3 = V4TestUtils.computeSignature(headers3, query3, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                new URL(OOS_DOMAIN + bucketName +"/" + partObjectName + "?uploadId=" + uploadId), "POST", "s3", regionName);
        headers3.put("Authorization", authorization3);
        HttpURLConnection connection3 = readyConn(url3, "POST", headers3);
        connection3.connect();
        OutputStream out3 = connection3.getOutputStream();
        out3.write(xml.getBytes());
        out3.flush();
        int code3 = connection3.getResponseCode();
        assertEquals(200, code3);
        String reqxml = IOUtils.toString(connection3.getInputStream());
        System.out.println(reqxml);
        assertTrue(reqxml.contains("CompleteMultipartUploadResult") && reqxml.contains(bucketName) && reqxml.contains(partObjectName));
        
    }
    
    /** Delete Multiple Objects 
     * @throws Exception */
    @Test
    public void test34_deleteMultipleObjects_ok() throws Exception{
        String str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + "<Delete>" + "<Quiet>false</Quiet>" 
                + "<Object><Key>" + objectName + "</Key></Object>" 
                + "<Object><Key>" + copyObjectName + "</Key></Object>"
                + "<Object><Key>" + partObjectName + "</Key></Object>"
                + "</Delete>";
        URL url = new URL(OOS_DOMAIN + bucketName + "?delete");
        Map<String, String> headers = new HashMap<String, String>();
        String contentHashString = V4TestUtils.toHex(V4TestUtils.hash(str));
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(str.getBytes());
        String md5 = BinaryUtils.toBase64(md.digest());
        headers.put("x-amz-content-sha256", contentHashString);
        headers.put("content-length", str.getBytes().length+"");
        headers.put("content-type", "Content-Type=application/x-www-form-urlencoded");
        headers.put("content-md5", md5);
        Map<String, String> query = new HashMap<String, String>();
        query.put("delete", "");
        String authorization = V4TestUtils.computeSignature(headers, query, contentHashString, accessKey, secretKey, 
                url, "POST", "s3", regionName);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "POST", headers);
        connection.setRequestProperty("Content-MD5",md5);
        connection.connect();
        OutputStream out = connection.getOutputStream();
        out.write(str.getBytes());
        out.flush();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        assertTrue(xml.contains("DeleteResult") && xml.contains(objectName)&&xml.contains(copyObjectName)&&xml.contains(partObjectName));
        out.close();
        if (connection != null) {
            connection.disconnect();
        }
    }
    
    /** 生成共享链接 
     * @throws Exception */
    @Test
    public void test35_preUrl_ok() throws Exception{
        test29_put_object_no_checksum_ok();
        URL url = new URL(OOS_DOMAIN + bucketName + "/" + URLEncoder.encode(objectName, "UTF-8"));
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-limitrate", "100");
        Map<String, String> query = new HashMap<String, String>();
        query.put("X-Amz-Expires", 24*60*60 +"");
        String preUrl = V4TestUtils.computeSignatureForQueryparameters(headers, query, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                new URL(OOS_DOMAIN + bucketName + "/" + objectName), "GET", "s3", regionName);
        System.out.println(url + "?" + preUrl);
        HttpURLConnection connection = readyConn(new URL(url + "?" +preUrl), "GET", headers);
        connection.connect();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        System.out.println(xml);
        assertEquals(200, code);
        assertTrue(xml.equals(objectContent));
        if (connection != null) {
            connection.disconnect();
        }
    }
    /** CreateAccessKey  UpdateAccessKey  DeleteAccessKey*/
    @Test
    public void test36_createAccessKey_ok() throws Exception{
        URL url = new URL(OOS_DOMAIN_IAM +"?Action=CreateAccessKey");
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", UNSIGNED_PAYLOAD);
        headers.put("host", OOS_HOST_IAM);
        Map<String, String> query = new HashMap<String, String>();
        query.put("Action", "CreateAccessKey");
        String authorization = V4TestUtils.computeSignature(headers, query, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                url, "POST", "sts", regionNameIam);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "POST", headers);
        connection.connect();
        OutputStream out = connection.getOutputStream();
        out.write("Action=CreateAccessKey".getBytes());
        out.flush();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        System.out.println(code + ":" + xml);
        assertEquals(200, code);
        if (connection != null) {
            connection.disconnect();
        }
        StringReader sr = new StringReader(xml);
        InputSource is = new InputSource(sr);
        Document doc = (new SAXBuilder()).build(is);
        Element root = doc.getRootElement(); //获取根元素
        String ak =  root.getChild("CreateAccessKeyResult",root.getNamespace()).getChild("AccessKey").getChildText("AccessKeyId");
        String sk =  root.getChild("CreateAccessKeyResult",root.getNamespace()).getChild("AccessKey").getChildText("SecretAccessKey");
        System.out.println("ak = "+ ak);
        System.out.println("sk = "+ sk);
        //UpdateAccessKey
        URL url2 = new URL(OOS_DOMAIN_IAM + "?Action=UpdateAccessKey&AccessKeyId=" + ak +"&IsPrimary=true");
        Map<String, String> headers2 = new HashMap<String, String>();
        headers2.put("x-amz-content-sha256", UNSIGNED_PAYLOAD);
        headers2.put("host", OOS_HOST_IAM);
        Map<String, String> query2 = new HashMap<String, String>();
        query2.put("Action", "UpdateAccessKey");
        query2.put("AccessKeyId", ak);
        query2.put("IsPrimary", "true");
        String authorization2 = V4TestUtils.computeSignature(headers2, query2, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                url2, "POST", "sts", regionNameIam);
        headers2.put("Authorization", authorization2);
        HttpURLConnection connection2 = readyConn(url2, "POST", headers2);
        connection2.connect();
        OutputStream out2 = connection2.getOutputStream();
        out2.write(("Action=UpdateAccessKey&AccessKeyId=" + ak +"&IsPrimary=true").getBytes());
        out2.flush();
        int code2 = connection2.getResponseCode();
        String xml2 = IOUtils.toString(connection2.getInputStream());
        System.out.println(code2 + ":" + xml2);
        assertEquals(200, code2);
        if (connection2 != null) {
            connection2.disconnect();
        }
        //DeleteAccessKey
        URL url3 = new URL(OOS_DOMAIN_IAM + "?Action=DeleteAccessKey&AccessKeyId="+ak);
        Map<String, String> headers3 = new HashMap<String, String>();
        headers3.put("x-amz-content-sha256", UNSIGNED_PAYLOAD);
        headers3.put("host", OOS_HOST_IAM);
        Map<String, String> query3 = new HashMap<String, String>();
        query3.put("Action", "DeleteAccessKey");
        query3.put("AccessKeyId", ak);
        String authorization3 = V4TestUtils.computeSignature(headers3, query3, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                url3, "POST", "sts", regionNameIam);
        headers3.put("Authorization", authorization3);
        HttpURLConnection connection3 = readyConn(url3, "POST", headers3);
        connection3.connect();
        OutputStream out3 = connection3.getOutputStream();
        out3.write(("Action=DeleteAccessKey&AccessKeyId="+ak).getBytes());
        out3.flush();
        int code3 = connection3.getResponseCode();
        String xml3 = IOUtils.toString(connection3.getInputStream());
        System.out.println(code3 + ":" + xml3);
        assertEquals(200, code3);
        if (connection3 != null) {
            connection3.disconnect();
        }
    }
    
    /** ListAccessKey*/
    @Test
    public void test37_listAccessKey_ok() throws Exception{
        URL url = new URL(OOS_DOMAIN_IAM +"?Action=ListAccessKey");
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", UNSIGNED_PAYLOAD);
        headers.put("host", OOS_HOST_IAM);
        Map<String, String> query = new HashMap<String, String>();
        query.put("Action", "ListAccessKey");
        String authorization = V4TestUtils.computeSignature(headers, query, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                url, "POST", "sts", regionNameIam);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "POST", headers);
        connection.connect();
        OutputStream out = connection.getOutputStream();
        out.write("Action=ListAccessKey".getBytes());
        out.flush();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        System.out.println(code + ":" + xml);
        assertEquals(200, code);
        assertTrue(xml.contains(accessKey));
        if (connection != null) {
            connection.disconnect();
        }
    }
    private String getMultipartUploadId(boolean s3) throws Exception{
        String bucket = bucketName;
        String ak = accessKey;
        String sk = secretKey;
        String domain = OOS_DOMAIN;
        String region = regionName;
        URL url = new URL(domain + bucket +"/" + URLEncoder.encode(partObjectName, "UTF-8")+"?" + "uploads");
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("x-amz-content-sha256", EMPTY_BODY_SHA256);
        Map<String, String> query = new HashMap<String, String>();
        query.put("uploads", "");
        String authorization = V4TestUtils.computeSignature(headers, query, EMPTY_BODY_SHA256, ak, sk, 
                new URL(domain + bucket +"/" + partObjectName+"?" + "uploads"), "POST", "s3", region);
        headers.put("Authorization", authorization);
        HttpURLConnection connection = readyConn(url, "POST", headers);
        connection.connect();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        System.out.println(code + ":" + xml);
        assertEquals(200, code);
        assertTrue(xml.contains("InitiateMultipartUploadResult") && xml.contains(bucket) && xml.contains("UploadId") && xml.contains(partObjectName));
        if (connection != null) {
            connection.disconnect();
        }
        StringReader sr = new StringReader(xml);
        InputSource is = new InputSource(sr);
        Document doc = (new SAXBuilder()).build(is);
        Element root = doc.getRootElement(); //获取根元素
        String uploadId =  root.getChild("UploadId",root.getNamespace()).getValue();
        System.out.println("uploadId = "+ uploadId);
        return uploadId;
    }
    
    public HttpURLConnection readyConn(URL url, String method, Map<String, String> headers) throws Exception{
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod(method);
        if (headers != null) {
            System.out.println("--------- Request headers ---------");
            for (String headerKey : headers.keySet()) {
                System.out.println(headerKey + ": " + headers.get(headerKey));
                connection.setRequestProperty(headerKey, headers.get(headerKey));
            }
        }
        connection.setUseCaches(false);
        connection.setDoInput(true);
        connection.setDoOutput(true);
        return connection;
    }
}
