package cn.ctyun.oos.utils.api;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.io.IOUtils;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.xml.sax.InputSource;

import cn.ctyun.oos.utils.HttpConnectionSSLRequestUtils;
import cn.ctyun.oos.utils.V4SignClient;
import common.time.TimeUtils;
import common.tuple.Pair;

public class AllAPIClassifyUtils {
    
    static String httpOrHttps=TestEndpointConst.httpOrHttps;
    static String signVersion=TestEndpointConst.signVersion;
    static String regionName=TestEndpointConst.regionName;

    static String jettyhost=TestEndpointConst.jettyhost;
    static int jettyPort=TestEndpointConst.jettyPort;  
    static String managementAPIhost=TestEndpointConst.managementAPIhost;
    static int managementAPIport=TestEndpointConst.managementAPIport; 

    static String OOS_CLOUDTRAIL_DOMAIN=TestEndpointConst.OOS_CLOUDTRAIL_DOMAIN;
    static String OOS_IAM_DOMAIN=TestEndpointConst.OOS_IAM_DOMAIN;

    static String cloudtrailBucket="cloudtrail-bucket";
    static String bucketName1="yx-bucket-3";
    static String bucketName2="yx-bucket-4";
    static String dateregion1="yxregion1";
    static String dateregion2="yxregion2";
    
    static String groupName="group10";
    static String userName="user10";
    static String accountId="3fdmxmc3pqvmp";
    

    public static void OOS_AllowActionResourceBucket(String rootAk,String rootSk,String accessKey,String secretKey,String bucketName,List<String> headers)  {
        
        // 创建bucket  
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null, null, null, null, CreateHeaders(headers));
        assertEquals(200, createbucket2.first().intValue());
        System.out.println(createbucket2.second());
//        
//        // 获取bucket的ACL信息
        Pair<Integer, String> getbucketacl=OOSAPITestUtils.Bucket_GetAcl(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, CreateHeaders(headers));
        assertEquals(200, getbucketacl.first().intValue());
        System.out.println(getbucketacl.second());
        
        // 修改bucket acl属性
        HashMap<String, String> updateaclParams=new HashMap<String, String>();
        updateaclParams.put("x-amz-acl", "public-read-write");
        Pair<Integer, String> updatebucket=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, "Local", null, null, "NotAllowed", updateaclParams);
        assertEquals(200, updatebucket.first().intValue());
        System.out.println(updatebucket.second());
        
        // 获取bucket的索引位置和数据位置 
        Pair<Integer, String> getbucketlocation=OOSAPITestUtils.Bucket_GetLocation(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, CreateHeaders(headers));
        assertEquals(200, getbucketlocation.first().intValue());
        System.out.println(getbucketlocation.second());
        
        // 创建，获取，删除bucketpolicy
        String policyString = "{" + "\"Version\": \"2012-10-17\","
                + "\"Id\": \"preventHotLinking\"," + "\"Statement\": [" + " {"
                + " \"Sid\": \"1\"," + "\"Effect\": \"Allow\","
                + "\"Principal\": {" + " \"AWS\": \"*\"" + "},"
                + "\"Action\": \"s3:GetObject\","
                + "\"Resource\": \"arn:aws:s3:::" + bucketName + "/*\","
                + "}]}";
        Pair<Integer, String> putbucketpolicy=OOSAPITestUtils.Bucket_PutPolicy(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, policyString, CreateHeaders(headers));
        assertEquals(200, putbucketpolicy.first().intValue());
        System.out.println(putbucketpolicy.second());
        
        Pair<Integer, String> getbucketpolicy=OOSAPITestUtils.Bucket_GetPolicy(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, CreateHeaders(headers));
        assertEquals(200, getbucketpolicy.first().intValue());
        System.out.println(getbucketpolicy.second());
        
        Pair<Integer, String> delbucketpolicy=OOSAPITestUtils.Bucket_DeletePolicy(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, CreateHeaders(headers));
        assertEquals(200, delbucketpolicy.first().intValue());
        System.out.println(delbucketpolicy.second());
        
        // 创建，获取，删除website
        Pair<Integer, String> putbucketwebsite=OOSAPITestUtils.Bucket_PutWebsite(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, CreateHeaders(headers));
        assertEquals(200, putbucketwebsite.first().intValue());
        System.out.println(putbucketwebsite.second());
        
        Pair<Integer, String> getbucketwebsite=OOSAPITestUtils.Bucket_GetWebsite(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, CreateHeaders(headers));
        assertEquals(200, getbucketwebsite.first().intValue());
        System.out.println(getbucketwebsite.second());
        
        Pair<Integer, String> delbucketwebsite=OOSAPITestUtils.Bucket_DeleteWebsite(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, CreateHeaders(headers));
        assertEquals(200, delbucketwebsite.first().intValue());
        System.out.println(delbucketwebsite.second());
        
        // 创建，获取logging
        Pair<Integer, String> putbucketlogging=OOSAPITestUtils.Bucket_PutLogging(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, bucketName,"logs/",CreateHeaders(headers));
        assertEquals(200, putbucketlogging.first().intValue());
        System.out.println(putbucketlogging.second());
        
        Pair<Integer, String> getbucketlogging=OOSAPITestUtils.Bucket_GetLogging(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, CreateHeaders(headers));
        assertEquals(200, getbucketlogging.first().intValue());
        System.out.println(getbucketlogging.second());
        
        // 创建，获取，删除lifecycle
        Pair<Integer, String> putbucketlifecle=OOSAPITestUtils.Bucket_PutLifecycle(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName,"logs","Enabled",30, CreateHeaders(headers));
        assertEquals(200, putbucketlifecle.first().intValue());
        System.out.println(putbucketlifecle.second());
        
        Pair<Integer, String> getbucketlifecle=OOSAPITestUtils.Bucket_GetLifecycle(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, CreateHeaders(headers));
        assertEquals(200, getbucketlifecle.first().intValue());
        System.out.println(getbucketlifecle.second());
        
        Pair<Integer, String> delbucketlifecle=OOSAPITestUtils.Bucket_DeleteLifecycle(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, CreateHeaders(headers));
        assertEquals(204, delbucketlifecle.first().intValue());
        System.out.println(delbucketlifecle.second());
        
        // 创建，获取cdn加速
        Pair<Integer, String> putbucketaccelerate=OOSAPITestUtils.Bucket_PutAccelerate(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, Arrays.asList("192.168.1.1","192.168.2.1"),CreateHeaders(headers));
        assertEquals(200, putbucketaccelerate.first().intValue());
        System.out.println(putbucketaccelerate.second());
        
        Pair<Integer, String> getbucketaccelerate=OOSAPITestUtils.Bucket_GetAccelerate(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, CreateHeaders(headers));
        assertEquals(200, getbucketaccelerate.first().intValue());
        System.out.println(getbucketaccelerate.second());
        
        // 创建，获取，删除cors 
        Pair<Integer, String> putbucketcors=OOSAPITestUtils.Bucket_PutCors(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, CreateHeaders(headers));
        assertEquals(200, putbucketcors.first().intValue());
        System.out.println(putbucketcors.second());
        
        Pair<Integer, String> getbucketcors=OOSAPITestUtils.Bucket_GetCors(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, CreateHeaders(headers));
        assertEquals(200, getbucketcors.first().intValue());
        System.out.println(getbucketcors.second());
        
        Pair<Integer, String> delbucketcors=OOSAPITestUtils.Bucket_DeleteCors(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, CreateHeaders(headers));
        assertEquals(200, delbucketcors.first().intValue());
        System.out.println(delbucketcors.second());
        
        Pair<Integer, String> listMultipartUploads=OOSAPITestUtils.Bucket_ListMultipartUploads(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, CreateHeaders(headers));
        assertEquals(200, listMultipartUploads.first().intValue());
        
        String objectName1="1.txt";
        String objectName2="2.txt";
        
        Pair<Integer, String> putobject=OOSAPITestUtils.Object_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, objectName1, "first", CreateHeaders(headers));
        assertEquals(200, putobject.first().intValue());
        
        Pair<Integer, String> putobject2=OOSAPITestUtils.Object_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, objectName2,"second", CreateHeaders(headers));
        assertEquals(200, putobject2.first().intValue());
        
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, CreateHeaders(headers));
        assertEquals(200, listobjects.first().intValue());
                
        Pair<Integer, String> delobjects=OOSAPITestUtils.Object_DeleteMulit(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, Arrays.asList(objectName1,objectName2), CreateHeaders(headers));
        assertEquals(200, delobjects.first().intValue());
        System.out.println(delobjects.second());
        
        // delete bucket
        Pair<Integer, String> delbucket=OOSAPITestUtils.Bucket_Delete(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, CreateHeaders(headers));
        assertEquals(204, delbucket.first().intValue());
        System.out.println(delbucket.second());
    }
    
    public static void OOS_DenyActionResourceBucket(String rootAk,String rootSk,String accessKey,String secretKey,String bucketName,List<String> headers) {
        
        // 创建bucket  
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, "Local", null, null, null, CreateHeaders(headers));
        assertEquals(403, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, "Local", null, null, null, CreateHeaders(headers));
        assertEquals(200, createbucket2.first().intValue());
        System.out.println(createbucket2.second());
//        
//        // 获取bucket的ACL信息
        Pair<Integer, String> getbucketacl=OOSAPITestUtils.Bucket_GetAcl(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, getbucketacl.first().intValue());
        System.out.println(getbucketacl.second());
        
        // 修改bucket acl属性
        HashMap<String, String> updateaclParams=new HashMap<String, String>();
        updateaclParams.put("x-amz-acl", "public-read-write");
        Pair<Integer, String> updatebucket=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, "Local", null, null, "NotAllowed", updateaclParams);
        assertEquals(403, updatebucket.first().intValue());
        System.out.println(updatebucket.second());
        
        // 获取bucket的索引位置和数据位置 
        Pair<Integer, String> getbucketlocation=OOSAPITestUtils.Bucket_GetLocation(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, getbucketlocation.first().intValue());
        System.out.println(getbucketlocation.second());
        
        // 创建，获取，删除bucketpolicy
        String policyString = "{" + "\"Version\": \"2012-10-17\","
                + "\"Id\": \"preventHotLinking\"," + "\"Statement\": [" + " {"
                + " \"Sid\": \"1\"," + "\"Effect\": \"Allow\","
                + "\"Principal\": {" + " \"AWS\": \"*\"" + "},"
                + "\"Action\": \"s3:GetObject\","
                + "\"Resource\": \"arn:aws:s3:::" + bucketName + "/*\","
                + "}]}";
        Pair<Integer, String> putbucketpolicy=OOSAPITestUtils.Bucket_PutPolicy(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, policyString, null);
        assertEquals(403, putbucketpolicy.first().intValue());
        System.out.println(putbucketpolicy.second());
        
        Pair<Integer, String> putbucketpolicy2=OOSAPITestUtils.Bucket_PutPolicy(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, policyString, null);
        assertEquals(200, putbucketpolicy2.first().intValue());
        System.out.println(putbucketpolicy2.second());
        
        Pair<Integer, String> getbucketpolicy=OOSAPITestUtils.Bucket_GetPolicy(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, getbucketpolicy.first().intValue());
        System.out.println(getbucketpolicy.second());
        
        Pair<Integer, String> delbucketpolicy=OOSAPITestUtils.Bucket_DeletePolicy(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, delbucketpolicy.first().intValue());
        System.out.println(delbucketpolicy.second());
        
        // 创建，获取，删除website
        Pair<Integer, String> putbucketwebsite=OOSAPITestUtils.Bucket_PutWebsite(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, putbucketwebsite.first().intValue());
        System.out.println(putbucketwebsite.second());
        
        Pair<Integer, String> putbucketwebsite2=OOSAPITestUtils.Bucket_PutWebsite(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, null);
        assertEquals(200, putbucketwebsite2.first().intValue());
        System.out.println(putbucketwebsite2.second());
        
        Pair<Integer, String> getbucketwebsite=OOSAPITestUtils.Bucket_GetWebsite(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, getbucketwebsite.first().intValue());
        System.out.println(getbucketwebsite.second());
        
        Pair<Integer, String> delbucketwebsite=OOSAPITestUtils.Bucket_DeleteWebsite(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, delbucketwebsite.first().intValue());
        System.out.println(delbucketwebsite.second());
        
        // 创建，获取logging
        Pair<Integer, String> putbucketlogging=OOSAPITestUtils.Bucket_PutLogging(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, bucketName,"logs/",null);
        assertEquals(403, putbucketlogging.first().intValue());
        System.out.println(putbucketlogging.second());
        
        Pair<Integer, String> putbucketlogging2=OOSAPITestUtils.Bucket_PutLogging(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, bucketName,"logs/",null);
        assertEquals(200, putbucketlogging2.first().intValue());
        System.out.println(putbucketlogging2.second());
        
        Pair<Integer, String> getbucketlogging=OOSAPITestUtils.Bucket_GetLogging(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, getbucketlogging.first().intValue());
        System.out.println(getbucketlogging.second());
        
        // 创建，获取，删除lifecycle
        Pair<Integer, String> putbucketlifecle=OOSAPITestUtils.Bucket_PutLifecycle(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName,"logs","Enabled",30, null);
        assertEquals(403, putbucketlifecle.first().intValue());
        System.out.println(putbucketlifecle.second());
        
        Pair<Integer, String> putbucketlifecle2=OOSAPITestUtils.Bucket_PutLifecycle(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName,"logs","Enabled",30, null);
        assertEquals(200, putbucketlifecle2.first().intValue());
        System.out.println(putbucketlifecle2.second());
        
        Pair<Integer, String> getbucketlifecle=OOSAPITestUtils.Bucket_GetLifecycle(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, getbucketlifecle.first().intValue());
        System.out.println(getbucketlifecle.second());
        
        Pair<Integer, String> delbucketlifecle=OOSAPITestUtils.Bucket_DeleteLifecycle(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, delbucketlifecle.first().intValue());
        System.out.println(delbucketlifecle.second());
        
        // 创建，获取cdn加速
        Pair<Integer, String> putbucketaccelerate=OOSAPITestUtils.Bucket_PutAccelerate(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, Arrays.asList("192.168.1.1","192.168.2.1"),null);
        assertEquals(403, putbucketaccelerate.first().intValue());
        System.out.println(putbucketaccelerate.second());
        
        Pair<Integer, String> putbucketaccelerate2=OOSAPITestUtils.Bucket_PutAccelerate(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, Arrays.asList("192.168.1.1","192.168.2.1"),null);
        assertEquals(200, putbucketaccelerate2.first().intValue());
        System.out.println(putbucketaccelerate2.second());
        
        Pair<Integer, String> getbucketaccelerate=OOSAPITestUtils.Bucket_GetAccelerate(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, getbucketaccelerate.first().intValue());
        System.out.println(getbucketaccelerate.second());
        
        // 创建，获取，删除cors 
        Pair<Integer, String> putbucketcors=OOSAPITestUtils.Bucket_PutCors(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, putbucketcors.first().intValue());
        System.out.println(putbucketcors.second());
        
        Pair<Integer, String> putbucketcors2=OOSAPITestUtils.Bucket_PutCors(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, null);
        assertEquals(200, putbucketcors2.first().intValue());
        System.out.println(putbucketcors2.second());
        
        Pair<Integer, String> getbucketcors=OOSAPITestUtils.Bucket_GetCors(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, getbucketcors.first().intValue());
        System.out.println(getbucketcors.second());
        
        Pair<Integer, String> delbucketcors=OOSAPITestUtils.Bucket_DeleteCors(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, delbucketcors.first().intValue());
        System.out.println(delbucketcors.second());
        
        Pair<Integer, String> listMultipartUploads=OOSAPITestUtils.Bucket_ListMultipartUploads(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, listMultipartUploads.first().intValue());
        
        String objectName1="1.txt";
        String objectName2="2.txt";
        
        Pair<Integer, String> putobject=OOSAPITestUtils.Object_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, objectName1, "first", null);
        assertEquals(200, putobject.first().intValue());
        
        Pair<Integer, String> putobject2=OOSAPITestUtils.Object_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, objectName2, "second", null);
        assertEquals(200, putobject2.first().intValue());
        
        Pair<Integer, String> delobjects=OOSAPITestUtils.Object_DeleteMulit(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, Arrays.asList(objectName1,objectName2), null);
        assertEquals(403, delobjects.first().intValue());
        System.out.println(delobjects.second());
        
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, CreateHeaders(headers));
        assertEquals(403, listobjects.first().intValue());
        
        Pair<Integer, String> delobjects2=OOSAPITestUtils.Object_DeleteMulit(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, Arrays.asList(objectName1,objectName2), null);
        assertEquals(200, delobjects2.first().intValue());
        System.out.println(delobjects2.second());
        
        // delete bucket
        Pair<Integer, String> delbucket=OOSAPITestUtils.Bucket_Delete(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, delbucket.first().intValue());
        System.out.println(delbucket.second());
        
        Pair<Integer, String> delbucket2=OOSAPITestUtils.Bucket_Delete(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, null);
        assertEquals(204, delbucket2.first().intValue());
        System.out.println(delbucket2.second());
    }
    
    public static void OOS_AllowActionResourceObject(String rootAk,String rootSk,String  accessKey,String secretKey,String bucketName,String prefix,List<String> headers){
        
         //put get head delete object
        String objectName="src.txt";
        if (prefix!=null) {
            objectName=prefix+objectName;
        }
        Pair<Integer, String> putobject=OOSAPITestUtils.Object_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName, true), "first", CreateHeaders(headers));
        assertEquals(200, putobject.first().intValue());
        System.out.println(putobject.second());
        
        Pair<Integer, String> getobject=OOSAPITestUtils.Object_Get(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName, true), CreateHeaders(headers));
        assertEquals(200, getobject.first().intValue());
        System.out.println(getobject.second());
        
        int headobject=OOSAPITestUtils.Object_Head(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName, true), CreateHeaders(headers));
        assertEquals(200, headobject);
        
        Pair<Integer, String> delobject=OOSAPITestUtils.Object_Delete(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName, true), CreateHeaders(headers));
        assertEquals(204, delobject.first().intValue());
        System.out.println(delobject.second());
        
        // post object
        Pair<Integer, String> postobject=OOSAPITestUtils.Object_Post(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, objectName, "post.txt", CreateHeaders(headers));
        assertEquals(204, postobject.first().intValue());
        System.out.println(postobject.second());
        
        // copy object
        String objectName2="desc.txt";
        if (prefix!=null) {
            objectName2=prefix+objectName2;
        }
        Pair<Integer, String> copyobject=OOSAPITestUtils.Object_Copy(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName, true), V4SignClient.urlEncode(objectName2, true), CreateHeaders(headers));
        assertEquals(200, copyobject.first().intValue());
        System.out.println(copyobject.second());
        
        
        // 分段上传，1.init 2.uploadpart,3.copy part,4.List Multipart Uploads,5.list part 6.Complete Multipart Upload,7.Abort Multipart Upload
        String objectName3="muli.txt";
        if (prefix!=null) {
            objectName3=prefix+objectName3;
        }
        Pair<Integer, String> initmuli=OOSAPITestUtils.Object_InitialMultipartUpload(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName3, true), CreateHeaders(headers));
        assertEquals(200, initmuli.first().intValue());
        String uploadId=OOSAPITestUtils.getMultipartUploadId(initmuli.second());
        
        Pair<Integer, String> uploadpart=OOSAPITestUtils.Object_UploadPart(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName3, true), uploadId, 1, "123", CreateHeaders(headers));
        assertEquals(200, uploadpart.first().intValue());
        String etag1=uploadpart.second();
        Pair<Integer, String> copypart=OOSAPITestUtils.Object_CopyPart(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName3, true), uploadId, 2, V4SignClient.urlEncode(objectName, true), CreateHeaders(headers));
        assertEquals(200, copypart.first().intValue());
        String etag2=OOSAPITestUtils.getCopyPartEtag(copypart.second());
       
        Pair<Integer, String> listpart=OOSAPITestUtils.Object_ListPart(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName3, true), uploadId, CreateHeaders(headers));
        assertEquals(200, listpart.first().intValue());
        System.out.println(listpart.second());
        
        Map<String, String> partEtagMap = new HashMap<String, String>();
        partEtagMap.put("1", etag1);
        partEtagMap.put("2", etag2);

        Pair<Integer, String> completemultipart=OOSAPITestUtils.Object_CompleteMultipartUpload(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName,V4SignClient.urlEncode(objectName3, true), uploadId, partEtagMap, CreateHeaders(headers));
        assertEquals(200, completemultipart.first().intValue());
        System.out.println(completemultipart.second());
        
        String objectName4="muli2.txt";
        if (prefix!=null) {
            objectName4=prefix+objectName4;
        }
        Pair<Integer, String> initmuli2=OOSAPITestUtils.Object_InitialMultipartUpload(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName4, true), CreateHeaders(headers));
        assertEquals(200, initmuli2.first().intValue());
        String uploadId2=OOSAPITestUtils.getMultipartUploadId(initmuli2.second());
        
        Pair<Integer, String> uploadpart2=OOSAPITestUtils.Object_UploadPart(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName4, true), uploadId2, 1, "123", CreateHeaders(headers));
        assertEquals(200, uploadpart2.first().intValue());
        String etag3=uploadpart2.second();
        Pair<Integer, String> copypart2=OOSAPITestUtils.Object_CopyPart(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName4, true), uploadId2, 2, V4SignClient.urlEncode(objectName, true), CreateHeaders(headers));
        assertEquals(200, copypart2.first().intValue());
        String etag4=OOSAPITestUtils.getCopyPartEtag(copypart2.second());

        Pair<Integer, String> aboutmultipart=OOSAPITestUtils.object_AbortMultipartUpload(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName4, true), uploadId2, CreateHeaders(headers));
        assertEquals(204, aboutmultipart.first().intValue());
        System.out.println(aboutmultipart.second());
        
        Pair<Integer, String> delobjects2=OOSAPITestUtils.Object_DeleteMulit(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, Arrays.asList(objectName,objectName2,objectName3,objectName4), CreateHeaders(headers));
        assertEquals(200, delobjects2.first().intValue());
        System.out.println(delobjects2.second());

    }
    
    public static void OOS_DenyActionResourceObject(String rootAk,String rootSk,String  accessKey,String secretKey,String bucketName,String prefix,List<String> headers ){
        
         //put get head delete object
        String objectName="src.txt";
        if (prefix!=null) {
            objectName=prefix+objectName;
        }
        Pair<Integer, String> putobject=OOSAPITestUtils.Object_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName, true), "first", CreateHeaders(headers));
        assertEquals(403, putobject.first().intValue());
        System.out.println(putobject.second());
        
        Pair<Integer, String> putobject1=OOSAPITestUtils.Object_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, V4SignClient.urlEncode(objectName, true), "first", CreateHeaders(headers));
        assertEquals(200, putobject1.first().intValue());
        System.out.println(putobject1.second());
        
        Pair<Integer, String> getobject=OOSAPITestUtils.Object_Get(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName, true), CreateHeaders(headers));
        assertEquals(403, getobject.first().intValue());
        System.out.println(getobject.second());
        
        int headobject=OOSAPITestUtils.Object_Head(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName, true), CreateHeaders(headers));
        assertEquals(403, headobject);
        
        Pair<Integer, String> delobject=OOSAPITestUtils.Object_Delete(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName, true), CreateHeaders(headers));
        assertEquals(403, delobject.first().intValue());
        System.out.println(delobject.second());
        
        
        // post object
        Pair<Integer, String> postobject=OOSAPITestUtils.Object_Post(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, objectName,"post.txt", CreateHeaders(headers));
        assertEquals(403, postobject.first().intValue());
        System.out.println(postobject.second());
        
        // copy object
        String objectName2="desc.txt";
        if (prefix!=null) {
            objectName2=prefix+objectName2;
        }
        Pair<Integer, String> copyobject=OOSAPITestUtils.Object_Copy(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName, true), V4SignClient.urlEncode(objectName2, true), CreateHeaders(headers));
        assertEquals(403, copyobject.first().intValue());
        System.out.println(copyobject.second());
          
        // 分段上传，1.init 2.uploadpart,3.copy part,4.List Multipart Uploads,5.list part 6.Complete Multipart Upload,7.Abort Multipart Upload
        String objectName3="muli.txt";
        if (prefix!=null) {
            objectName3=prefix+objectName3;
        }
        Pair<Integer, String> initmuli=OOSAPITestUtils.Object_InitialMultipartUpload(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName3, true), CreateHeaders(headers));
        assertEquals(403, initmuli.first().intValue());
 
        Pair<Integer, String> initmuliroot=OOSAPITestUtils.Object_InitialMultipartUpload(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, V4SignClient.urlEncode(objectName3, true), CreateHeaders(headers));
        assertEquals(200, initmuliroot.first().intValue());
        String uploadId=OOSAPITestUtils.getMultipartUploadId(initmuliroot.second());
        
        Pair<Integer, String> uploadpart=OOSAPITestUtils.Object_UploadPart(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName3, true), uploadId, 1, "123", CreateHeaders(headers));
        assertEquals(403, uploadpart.first().intValue());
        Pair<Integer, String> copypart=OOSAPITestUtils.Object_CopyPart(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName3, true), uploadId, 2, V4SignClient.urlEncode(objectName,true), CreateHeaders(headers));
        assertEquals(403, copypart.first().intValue());
        
        Pair<Integer, String> uploadpartroot=OOSAPITestUtils.Object_UploadPart(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, V4SignClient.urlEncode(objectName3, true), uploadId, 1, "123", CreateHeaders(headers));
        assertEquals(200, uploadpartroot.first().intValue());
        String etag1=uploadpartroot.second();
        Pair<Integer, String> copypartroot=OOSAPITestUtils.Object_CopyPart(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, V4SignClient.urlEncode(objectName3, true), uploadId, 2, V4SignClient.urlEncode(objectName,true), CreateHeaders(headers));
        assertEquals(200, copypartroot.first().intValue());
        String etag2=OOSAPITestUtils.getCopyPartEtag(copypartroot.second());
        
        Pair<Integer, String> listpart=OOSAPITestUtils.Object_ListPart(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName3, true), uploadId, CreateHeaders(headers));
        assertEquals(403, listpart.first().intValue());
        System.out.println(listpart.second());
        
        Map<String, String> partEtagMap = new HashMap<String, String>();
        partEtagMap.put("1", etag1);
        partEtagMap.put("2", etag2);

        Pair<Integer, String> completemultipart=OOSAPITestUtils.Object_CompleteMultipartUpload(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName,V4SignClient.urlEncode(objectName3, true), uploadId, partEtagMap, CreateHeaders(headers));
        assertEquals(403, completemultipart.first().intValue());
        System.out.println(completemultipart.second());
        
        Pair<Integer, String> aboutmultipart=OOSAPITestUtils.object_AbortMultipartUpload(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName3, true), uploadId, CreateHeaders(headers));
        assertEquals(403, aboutmultipart.first().intValue());
        System.out.println(aboutmultipart.second());
        
        Pair<Integer, String> aboutmultipartroot=OOSAPITestUtils.object_AbortMultipartUpload(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, V4SignClient.urlEncode(objectName3, true), uploadId, CreateHeaders(headers));
        assertEquals(204, aboutmultipartroot.first().intValue());
        System.out.println(aboutmultipartroot.second());
        
        Pair<Integer, String> delobjects2=OOSAPITestUtils.Object_DeleteMulit(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, Arrays.asList(objectName, objectName3), CreateHeaders(headers));
        assertEquals(200, delobjects2.first().intValue());
        System.out.println(delobjects2.second());
        
        
    }
    
    
    public static void CloudTrail_AllowActionResourceTrail(String accessKey,String secretKey,String trailName,List<String> headers) {
 
        Pair<Integer, String> createtrail=CloudTrailAPITestUtils.CreateTrail(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, cloudtrailBucket, true, CreateHeaders(headers));
        assertEquals(200, createtrail.first().intValue());
        System.out.println(createtrail.second());

        Pair<Integer, String> updateTrail=CloudTrailAPITestUtils.UpdateTrail(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, cloudtrailBucket, null, true, CreateHeaders(headers));
        assertEquals(200, updateTrail.first().intValue());
        System.out.println(updateTrail.second());
        
        Pair<Integer, String> putEventSelectors=CloudTrailAPITestUtils.PutEventSelectors(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, "All", true, CreateHeaders(headers));
        assertEquals(200, putEventSelectors.first().intValue());
        System.out.println(putEventSelectors.second());
        
        Pair<Integer, String> getEventSelectors=CloudTrailAPITestUtils.GetEventSelectors(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, true, CreateHeaders(headers));
        assertEquals(200, getEventSelectors.first().intValue());
        System.out.println(getEventSelectors.second());

        Pair<Integer, String> startLogging=CloudTrailAPITestUtils.StartLogging(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, true, CreateHeaders(headers));
        assertEquals(200, startLogging.first().intValue());
        System.out.println(startLogging.second());
        
        Pair<Integer, String> getTrailStatus=CloudTrailAPITestUtils.GetTrailStatus(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, true, CreateHeaders(headers));
        assertEquals(200, getTrailStatus.first().intValue());
        System.out.println(getTrailStatus.second());
        
        Pair<Integer, String> stopLogging=CloudTrailAPITestUtils.StopLogging(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, true, CreateHeaders(headers));
        assertEquals(200, stopLogging.first().intValue());
        System.out.println(stopLogging.second());
 
        Pair<Integer, String> deleteTrail=CloudTrailAPITestUtils.DeleteTrail(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, true, CreateHeaders(headers));
        assertEquals(200, deleteTrail.first().intValue());
        System.out.println(deleteTrail.second());
    }
    
    public static void CloudTrail_DenyActionResourceTrail(String rootAk,String rootSk,String accessKey,String secretKey,String trailName,List<String> headers) {
        Pair<Integer, String> createtrail=CloudTrailAPITestUtils.CreateTrail(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, cloudtrailBucket, true, CreateHeaders(headers));
        assertEquals(403, createtrail.first().intValue());
        System.out.println(createtrail.second());
        
        Pair<Integer, String> createtrail2=CloudTrailAPITestUtils.CreateTrail(OOS_CLOUDTRAIL_DOMAIN, regionName, rootAk, rootSk, trailName, cloudtrailBucket, true, CreateHeaders(headers));
        assertEquals(200, createtrail2.first().intValue());
        System.out.println(createtrail2.second());

        Pair<Integer, String> updateTrail=CloudTrailAPITestUtils.UpdateTrail(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, cloudtrailBucket, null, true, CreateHeaders(headers));
        assertEquals(403, updateTrail.first().intValue());
        System.out.println(updateTrail.second());
        
        Pair<Integer, String> putEventSelectors=CloudTrailAPITestUtils.PutEventSelectors(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, "All", true, CreateHeaders(headers));
        assertEquals(403, putEventSelectors.first().intValue());
        System.out.println(putEventSelectors.second());
        
        Pair<Integer, String> getEventSelectors=CloudTrailAPITestUtils.GetEventSelectors(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, true, CreateHeaders(headers));
        assertEquals(403, getEventSelectors.first().intValue());
        System.out.println(getEventSelectors.second());

        Pair<Integer, String> startLogging=CloudTrailAPITestUtils.StartLogging(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, true, CreateHeaders(headers));
        assertEquals(403, startLogging.first().intValue());
        System.out.println(startLogging.second());
        
        Pair<Integer, String> getTrailStatus=CloudTrailAPITestUtils.GetTrailStatus(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, true, CreateHeaders(headers));
        assertEquals(403, getTrailStatus.first().intValue());
        System.out.println(getTrailStatus.second());
        
        Pair<Integer, String> stopLogging=CloudTrailAPITestUtils.StopLogging(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, true, CreateHeaders(headers));
        assertEquals(403, stopLogging.first().intValue());
        System.out.println(stopLogging.second());
 
        Pair<Integer, String> deleteTrail=CloudTrailAPITestUtils.DeleteTrail(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, true, CreateHeaders(headers));
        assertEquals(403, deleteTrail.first().intValue());
        System.out.println(deleteTrail.second());
        
        Pair<Integer, String> deleteTrail2=CloudTrailAPITestUtils.DeleteTrail(OOS_CLOUDTRAIL_DOMAIN, regionName, rootAk, rootSk, trailName, true, CreateHeaders(headers));
        assertEquals(200, deleteTrail2.first().intValue());
        System.out.println(deleteTrail2.second());
    }
    
    public static void IAM_APIALLAllow(String ak,String sk,List<String> headers) {

        IAMAPITestUtils.CreateGroup(OOS_IAM_DOMAIN,regionName,ak, sk, groupName, CreateHeaders(headers),200);
        IAMAPITestUtils.CreateUser(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),200);
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag1=new Pair<String, String>();
        tag1.first("team");
        tag1.second("test");
        tags.add(tag1);
        IAMAPITestUtils.TagUser(OOS_IAM_DOMAIN,regionName,ak, sk, userName, tags, CreateHeaders(headers),200);
        String createAk=IAMAPITestUtils.CreateAccessKey(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),200);
        String akId=getCreateAccessKey(createAk);
        IAMAPITestUtils.UpdateAccessKey(OOS_IAM_DOMAIN,regionName,ak, sk, akId, userName, "Inactive", CreateHeaders(headers),200);
        IAMAPITestUtils.AddUserToGroup(OOS_IAM_DOMAIN,regionName,ak, sk, groupName, userName,CreateHeaders(headers), 200);
        
        
        IAMAPITestUtils.CreateLoginProfile(OOS_IAM_DOMAIN,regionName,ak, sk, userName, "a12345678", CreateHeaders(headers),200);
        IAMAPITestUtils.UpdateLoginProfile(OOS_IAM_DOMAIN,regionName,ak, sk, userName, "b12345678", CreateHeaders(headers),200);
//        IAMAPITestUtils.ChangePassword(ak, sk, userName, "b12345678", "c12345678", 200);
        
        IAMAPITestUtils.UpdateAccountPasswordPolicy(OOS_IAM_DOMAIN,regionName,ak, sk, CreateHeaders(headers),200);

        String virtualMFADeviceName="mfa2";
        String mfaString=IAMAPITestUtils.CreateVirtualMFADevice(OOS_IAM_DOMAIN,regionName,ak, sk, virtualMFADeviceName, CreateHeaders(headers),200);
        Pair<String, String> devicePair=getcreateVirtualMFADevice(mfaString);
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        IAMAPITestUtils.EnableMFADevice(OOS_IAM_DOMAIN,regionName,ak, sk, userName, accountId, virtualMFADeviceName, codesPair.first(), codesPair.second(), CreateHeaders(headers),200);
        
        String policyName="oosall";
        String policyString="{\n" + 
                "    \"Version\": \"2012-10-17\",\n" + 
                "    \"Statement\": [\n" + 
                "        {\n" + 
                "            \"Effect\": \"Allow\",\n" + 
                "            \"Action\": \"oos:*\",\n" + 
                "            \"Resource\": \"*\"\n" + 
                "        }\n" + 
                "    ]\n" + 
                "}\n" + 
                "";
        IAMAPITestUtils.CreatePolicy(OOS_IAM_DOMAIN,regionName,ak, sk, policyName, policyString, CreateHeaders(headers),200);
        IAMAPITestUtils.AttachGroupPolicy(OOS_IAM_DOMAIN,regionName,ak, sk, accountId, groupName, policyName, CreateHeaders(headers),200);
        IAMAPITestUtils.AttachUserPolicy(OOS_IAM_DOMAIN,regionName,ak, sk, accountId, userName, policyName, CreateHeaders(headers),200);
        
        
        IAMAPITestUtils.GetGroup(OOS_IAM_DOMAIN,regionName,ak, sk, groupName, CreateHeaders(headers),200);
        IAMAPITestUtils.ListGroups(OOS_IAM_DOMAIN,regionName,ak, sk, CreateHeaders(headers),200);
        IAMAPITestUtils.GetUser(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.ListUsers(OOS_IAM_DOMAIN,regionName,ak, sk, CreateHeaders(headers),200);
        IAMAPITestUtils.ListUserTags(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.ListAccessKeys(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.ListGroupsForUser(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.GetLoginProfile(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.ListVirtualMFADevices(OOS_IAM_DOMAIN,regionName,ak, sk, CreateHeaders(headers),200);
        IAMAPITestUtils.ListMFADevices(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.GetAccountPasswordPolicy(OOS_IAM_DOMAIN,regionName,ak, sk, CreateHeaders(headers),200);
        IAMAPITestUtils.GetPolicy(OOS_IAM_DOMAIN,regionName,ak, sk, accountId, policyName, CreateHeaders(headers),200);
        IAMAPITestUtils.ListPolicies(OOS_IAM_DOMAIN,regionName,ak, sk, CreateHeaders(headers),200);
        IAMAPITestUtils.ListAttachedGroupPolicies(OOS_IAM_DOMAIN,regionName,ak, sk, groupName, CreateHeaders(headers),200);
        IAMAPITestUtils.ListAttachedUserPolicies(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.ListEntitiesForPolicy(OOS_IAM_DOMAIN,regionName,ak, sk, accountId, policyName, CreateHeaders(headers),200);
        
        IAMAPITestUtils.DetachUserPolicy(OOS_IAM_DOMAIN,regionName,ak, sk, accountId, userName, policyName, CreateHeaders(headers),200);
        IAMAPITestUtils.DetachGroupPolicy(OOS_IAM_DOMAIN,regionName,ak, sk, accountId, groupName, policyName, CreateHeaders(headers),200);
        IAMAPITestUtils.DeletePolicy(OOS_IAM_DOMAIN,regionName,ak, sk, accountId, policyName, CreateHeaders(headers),200);
        IAMAPITestUtils.DeactivateMFADevice(OOS_IAM_DOMAIN,regionName,ak, sk, userName, accountId,virtualMFADeviceName , CreateHeaders(headers),200);
        IAMAPITestUtils.DeleteVirtualMFADevice(OOS_IAM_DOMAIN,regionName,ak, sk, accountId, virtualMFADeviceName, CreateHeaders(headers),200);
        IAMAPITestUtils.DeleteAccountPasswordPolicy(OOS_IAM_DOMAIN,regionName,ak, sk, CreateHeaders(headers),200);
        IAMAPITestUtils.DeleteLoginProfile(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.UntagUser(OOS_IAM_DOMAIN,regionName,ak, sk, userName, Arrays.asList("team"), CreateHeaders(headers),200);
        IAMAPITestUtils.DeleteAccessKey(OOS_IAM_DOMAIN,regionName,ak, sk, akId, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.RemoveUserFromGroup(OOS_IAM_DOMAIN,regionName,ak, sk, groupName, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.DeleteUser(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.DeleteGroup(OOS_IAM_DOMAIN,regionName,ak, sk, groupName, CreateHeaders(headers),200);
    }
    
    public static void IAM_APIALLDeny(String rootak,String rootsk,String ak,String sk,List<String> headers) {

        IAMAPITestUtils.CreateGroup(OOS_IAM_DOMAIN,regionName,ak, sk, groupName, CreateHeaders(headers),403);
        IAMAPITestUtils.CreateUser(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),403);
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag1=new Pair<String, String>();
        tag1.first("team");
        tag1.second("test");
        tags.add(tag1);
        IAMAPITestUtils.TagUser(OOS_IAM_DOMAIN,regionName,ak, sk, userName, tags, CreateHeaders(headers),403);
        IAMAPITestUtils.CreateAccessKey(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),403);

        IAMAPITestUtils.CreateGroup(OOS_IAM_DOMAIN,regionName,rootak, rootsk, groupName, CreateHeaders(headers),200);
        IAMAPITestUtils.CreateUser(OOS_IAM_DOMAIN,regionName,rootak, rootsk, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.TagUser(OOS_IAM_DOMAIN,regionName,rootak, rootsk, userName, tags, CreateHeaders(headers),200);
        String createAk=IAMAPITestUtils.CreateAccessKey(OOS_IAM_DOMAIN,regionName,rootak, rootsk, userName, CreateHeaders(headers),200);
        String akId=getCreateAccessKey(createAk);
        
        IAMAPITestUtils.UpdateAccessKey(OOS_IAM_DOMAIN,regionName,ak, sk, akId, userName, "Inactive", CreateHeaders(headers),403);
        IAMAPITestUtils.AddUserToGroup(OOS_IAM_DOMAIN,regionName,ak, sk, groupName, userName, CreateHeaders(headers),403);
        
        IAMAPITestUtils.CreateLoginProfile(OOS_IAM_DOMAIN,regionName,ak, sk, userName, "a12345678", CreateHeaders(headers),403);
        IAMAPITestUtils.CreateLoginProfile(OOS_IAM_DOMAIN,regionName,rootak, rootsk, userName, "a12345678", CreateHeaders(headers),200);
        
        IAMAPITestUtils.UpdateLoginProfile(OOS_IAM_DOMAIN,regionName,ak, sk, userName, "b12345678", CreateHeaders(headers),403);
        IAMAPITestUtils.UpdateLoginProfile(OOS_IAM_DOMAIN,regionName,rootak, rootsk, userName, "b12345678", CreateHeaders(headers),200);
//        IAMAPITestUtils.ChangePassword(ak, sk, userName, "b12345678", "c12345678", 200);
        
        IAMAPITestUtils.UpdateAccountPasswordPolicy(OOS_IAM_DOMAIN,regionName,ak, sk, CreateHeaders(headers),403);
        IAMAPITestUtils.UpdateAccountPasswordPolicy(OOS_IAM_DOMAIN,regionName,rootak, rootsk, CreateHeaders(headers),200);

        String virtualMFADeviceName="mfa2";
        IAMAPITestUtils.CreateVirtualMFADevice(OOS_IAM_DOMAIN,regionName,ak, sk, virtualMFADeviceName, CreateHeaders(headers),403);
                
        String mfaString=IAMAPITestUtils.CreateVirtualMFADevice(OOS_IAM_DOMAIN,regionName,rootak, rootsk, virtualMFADeviceName, CreateHeaders(headers),200);
        Pair<String, String> devicePair=getcreateVirtualMFADevice(mfaString);
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        IAMAPITestUtils.EnableMFADevice(OOS_IAM_DOMAIN,regionName,ak, sk, userName, accountId, virtualMFADeviceName, codesPair.first(), codesPair.second(), CreateHeaders(headers),403);
        IAMAPITestUtils.EnableMFADevice(OOS_IAM_DOMAIN,regionName,rootak, rootsk, userName, accountId, virtualMFADeviceName, codesPair.first(), codesPair.second(), CreateHeaders(headers),200);
        
        String policyName="oosall";
        String policyString="{\n" + 
                "    \"Version\": \"2012-10-17\",\n" + 
                "    \"Statement\": [\n" + 
                "        {\n" + 
                "            \"Effect\": \"Allow\",\n" + 
                "            \"Action\": \"oos:*\",\n" + 
                "            \"Resource\": \"*\"\n" + 
                "        }\n" + 
                "    ]\n" + 
                "}\n" + 
                "";
        IAMAPITestUtils.CreatePolicy(OOS_IAM_DOMAIN,regionName,ak, sk, policyName, policyString, CreateHeaders(headers),403);
        IAMAPITestUtils.CreatePolicy(OOS_IAM_DOMAIN,regionName,rootak, rootsk, policyName, policyString, CreateHeaders(headers),200);
        IAMAPITestUtils.AttachGroupPolicy(OOS_IAM_DOMAIN,regionName,ak, sk, accountId, groupName, policyName, CreateHeaders(headers),403);
        IAMAPITestUtils.AttachUserPolicy(OOS_IAM_DOMAIN,regionName,ak, sk, accountId, userName, policyName, CreateHeaders(headers),403);
        
        
        IAMAPITestUtils.GetGroup(OOS_IAM_DOMAIN,regionName,ak, sk, groupName, CreateHeaders(headers),403);
        IAMAPITestUtils.ListGroups(OOS_IAM_DOMAIN,regionName,ak, sk, CreateHeaders(headers),403);
        IAMAPITestUtils.GetUser(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),403);
        IAMAPITestUtils.ListUsers(OOS_IAM_DOMAIN,regionName,ak, sk, CreateHeaders(headers),403);
        IAMAPITestUtils.ListUserTags(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),403);
        IAMAPITestUtils.ListAccessKeys(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),403);
        IAMAPITestUtils.ListGroupsForUser(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),403);
        IAMAPITestUtils.GetLoginProfile(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),403);
        IAMAPITestUtils.ListVirtualMFADevices(OOS_IAM_DOMAIN,regionName,ak, sk, CreateHeaders(headers),403);
        IAMAPITestUtils.ListMFADevices(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),403);
        IAMAPITestUtils.GetAccountPasswordPolicy(OOS_IAM_DOMAIN,regionName,ak, sk, CreateHeaders(headers),403);
        IAMAPITestUtils.GetPolicy(OOS_IAM_DOMAIN,regionName,ak, sk, accountId, policyName, CreateHeaders(headers),403);
        IAMAPITestUtils.ListPolicies(OOS_IAM_DOMAIN,regionName,ak, sk, CreateHeaders(headers),403);
        IAMAPITestUtils.ListAttachedGroupPolicies(OOS_IAM_DOMAIN,regionName,ak, sk, groupName, CreateHeaders(headers),403);
        IAMAPITestUtils.ListAttachedUserPolicies(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),403);
        IAMAPITestUtils.ListEntitiesForPolicy(OOS_IAM_DOMAIN,regionName,ak, sk, accountId, policyName, CreateHeaders(headers),403);
        
        IAMAPITestUtils.DetachUserPolicy(OOS_IAM_DOMAIN,regionName,ak, sk, accountId, userName, policyName, CreateHeaders(headers),403);
        IAMAPITestUtils.DetachGroupPolicy(OOS_IAM_DOMAIN,regionName,ak, sk, accountId, groupName, policyName, CreateHeaders(headers),403);
        IAMAPITestUtils.DeletePolicy(OOS_IAM_DOMAIN,regionName,ak, sk, accountId, policyName, CreateHeaders(headers),403);
        IAMAPITestUtils.DeactivateMFADevice(OOS_IAM_DOMAIN,regionName,ak, sk, userName, accountId,virtualMFADeviceName , CreateHeaders(headers),403);
        IAMAPITestUtils.DeleteVirtualMFADevice(OOS_IAM_DOMAIN,regionName,ak, sk, accountId, virtualMFADeviceName, CreateHeaders(headers),403);
        IAMAPITestUtils.DeleteAccountPasswordPolicy(OOS_IAM_DOMAIN,regionName,ak, sk, CreateHeaders(headers),403);
        IAMAPITestUtils.DeleteLoginProfile(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),403);
        IAMAPITestUtils.UntagUser(OOS_IAM_DOMAIN,regionName,ak, sk, userName, Arrays.asList("team"), CreateHeaders(headers),403);
        IAMAPITestUtils.DeleteAccessKey(OOS_IAM_DOMAIN,regionName,ak, sk, akId, userName, CreateHeaders(headers),403);
        IAMAPITestUtils.DeleteUser(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),403);
        IAMAPITestUtils.RemoveUserFromGroup(OOS_IAM_DOMAIN,regionName,ak, sk, groupName, userName, CreateHeaders(headers),403);
        IAMAPITestUtils.DeleteGroup(OOS_IAM_DOMAIN,regionName,ak, sk, groupName, CreateHeaders(headers),403);
        
        IAMAPITestUtils.DeletePolicy(OOS_IAM_DOMAIN,regionName,rootak, rootsk, accountId, policyName, CreateHeaders(headers),200);
        IAMAPITestUtils.DeactivateMFADevice(OOS_IAM_DOMAIN,regionName,rootak, rootsk, userName, accountId,virtualMFADeviceName , CreateHeaders(headers),200);
        IAMAPITestUtils.DeleteVirtualMFADevice(OOS_IAM_DOMAIN,regionName,rootak, rootsk, accountId, virtualMFADeviceName, CreateHeaders(headers),200);
        IAMAPITestUtils.DeleteAccountPasswordPolicy(OOS_IAM_DOMAIN,regionName,rootak, rootsk, CreateHeaders(headers),200);
        IAMAPITestUtils.DeleteLoginProfile(OOS_IAM_DOMAIN,regionName,rootak, rootsk, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.UntagUser(OOS_IAM_DOMAIN,regionName,rootak, rootsk, userName, Arrays.asList("team"), CreateHeaders(headers),200);
        IAMAPITestUtils.DeleteAccessKey(OOS_IAM_DOMAIN,regionName,rootak, rootsk, akId, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.RemoveUserFromGroup(OOS_IAM_DOMAIN,regionName,rootak, rootsk, groupName, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.DeleteUser(OOS_IAM_DOMAIN,regionName,rootak, rootsk, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.DeleteGroup(OOS_IAM_DOMAIN,regionName,rootak, rootsk, groupName, CreateHeaders(headers),200);
    }
    
    public static void IAM_APIALLReadOnly(String rootak,String rootsk,String ak,String sk,List<String> headers) {
        
        IAMAPITestUtils.CreateGroup(OOS_IAM_DOMAIN,regionName,ak, sk, groupName, CreateHeaders(headers),403);
        IAMAPITestUtils.CreateUser(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),403);
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag1=new Pair<String, String>();
        tag1.first("team");
        tag1.second("test");
        tags.add(tag1);
        IAMAPITestUtils.TagUser(OOS_IAM_DOMAIN,regionName,ak, sk, userName, tags, CreateHeaders(headers),403);
        IAMAPITestUtils.CreateAccessKey(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),403);

        IAMAPITestUtils.CreateGroup(OOS_IAM_DOMAIN,regionName,rootak, rootsk, groupName, CreateHeaders(headers),200);
        IAMAPITestUtils.CreateUser(OOS_IAM_DOMAIN,regionName,rootak, rootsk, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.TagUser(OOS_IAM_DOMAIN,regionName,rootak, rootsk, userName, tags, CreateHeaders(headers),200);
        String createAk=IAMAPITestUtils.CreateAccessKey(OOS_IAM_DOMAIN,regionName,rootak, rootsk, userName, CreateHeaders(headers),200);
        String akId=getCreateAccessKey(createAk);
        
        IAMAPITestUtils.UpdateAccessKey(OOS_IAM_DOMAIN,regionName,ak, sk, akId, userName, "Inactive", CreateHeaders(headers),403);
        IAMAPITestUtils.AddUserToGroup(OOS_IAM_DOMAIN,regionName,ak, sk, groupName, userName, CreateHeaders(headers),403);
        
        IAMAPITestUtils.CreateLoginProfile(OOS_IAM_DOMAIN,regionName,ak, sk, userName, "a12345678", CreateHeaders(headers),403);
        IAMAPITestUtils.CreateLoginProfile(OOS_IAM_DOMAIN,regionName,rootak, rootsk, userName, "a12345678", CreateHeaders(headers),200);
        
        IAMAPITestUtils.UpdateLoginProfile(OOS_IAM_DOMAIN,regionName,ak, sk, userName, "b12345678", CreateHeaders(headers),403);
        IAMAPITestUtils.UpdateLoginProfile(OOS_IAM_DOMAIN,regionName,rootak, rootsk, userName, "b12345678", CreateHeaders(headers),200);
//        IAMAPITestUtils.ChangePassword(ak, sk, userName, "b12345678", "c12345678", 200);
        
        IAMAPITestUtils.UpdateAccountPasswordPolicy(OOS_IAM_DOMAIN,regionName,ak, sk, CreateHeaders(headers),403);
        IAMAPITestUtils.UpdateAccountPasswordPolicy(OOS_IAM_DOMAIN,regionName,rootak, rootsk, CreateHeaders(headers),200);

        String virtualMFADeviceName="mfa2";
        IAMAPITestUtils.CreateVirtualMFADevice(OOS_IAM_DOMAIN,regionName,ak, sk, virtualMFADeviceName, CreateHeaders(headers),403);
                
        String mfaString=IAMAPITestUtils.CreateVirtualMFADevice(OOS_IAM_DOMAIN,regionName,rootak, rootsk, virtualMFADeviceName, CreateHeaders(headers),200);
        Pair<String, String> devicePair=getcreateVirtualMFADevice(mfaString);
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        IAMAPITestUtils.EnableMFADevice(OOS_IAM_DOMAIN,regionName,ak, sk, userName, accountId, virtualMFADeviceName, codesPair.first(), codesPair.second(), CreateHeaders(headers),403);
        IAMAPITestUtils.EnableMFADevice(OOS_IAM_DOMAIN,regionName,rootak, rootsk, userName, accountId, virtualMFADeviceName, codesPair.first(), codesPair.second(), CreateHeaders(headers),200);
        
        String policyName="oosall";
        String policyString="{\n" + 
                "    \"Version\": \"2012-10-17\",\n" + 
                "    \"Statement\": [\n" + 
                "        {\n" + 
                "            \"Effect\": \"Allow\",\n" + 
                "            \"Action\": \"oos:*\",\n" + 
                "            \"Resource\": \"*\"\n" + 
                "        }\n" + 
                "    ]\n" + 
                "}\n" + 
                "";
        IAMAPITestUtils.CreatePolicy(OOS_IAM_DOMAIN,regionName,ak, sk, policyName, policyString, CreateHeaders(headers),403);
        IAMAPITestUtils.CreatePolicy(OOS_IAM_DOMAIN,regionName,rootak, rootsk, policyName, policyString, CreateHeaders(headers),200);
        IAMAPITestUtils.AttachGroupPolicy(OOS_IAM_DOMAIN,regionName,ak, sk, accountId, groupName, policyName, CreateHeaders(headers),403);
        IAMAPITestUtils.AttachUserPolicy(OOS_IAM_DOMAIN,regionName,ak, sk, accountId, userName, policyName, CreateHeaders(headers),403);
        
        
        IAMAPITestUtils.GetGroup(OOS_IAM_DOMAIN,regionName,ak, sk, groupName, CreateHeaders(headers),200);
        IAMAPITestUtils.ListGroups(OOS_IAM_DOMAIN,regionName,ak, sk,CreateHeaders(headers),200);
        IAMAPITestUtils.GetUser(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.ListUsers(OOS_IAM_DOMAIN,regionName,ak, sk, CreateHeaders(headers),200);
        IAMAPITestUtils.ListUserTags(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.ListAccessKeys(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.ListGroupsForUser(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.GetLoginProfile(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.ListVirtualMFADevices(OOS_IAM_DOMAIN,regionName,ak, sk, CreateHeaders(headers),200);
        IAMAPITestUtils.ListMFADevices(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.GetAccountPasswordPolicy(OOS_IAM_DOMAIN,regionName,ak, sk, CreateHeaders(headers),200);
        IAMAPITestUtils.GetPolicy(OOS_IAM_DOMAIN,regionName,ak, sk, accountId, policyName, CreateHeaders(headers),200);
        IAMAPITestUtils.ListPolicies(OOS_IAM_DOMAIN,regionName,ak, sk, CreateHeaders(headers),200);
        IAMAPITestUtils.ListAttachedGroupPolicies(OOS_IAM_DOMAIN,regionName,ak, sk, groupName, CreateHeaders(headers),200);
        IAMAPITestUtils.ListAttachedUserPolicies(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.ListEntitiesForPolicy(OOS_IAM_DOMAIN,regionName,ak, sk, accountId, policyName, CreateHeaders(headers),200);
        
        IAMAPITestUtils.DetachUserPolicy(OOS_IAM_DOMAIN,regionName,ak, sk, accountId, userName, policyName, CreateHeaders(headers),403);
        IAMAPITestUtils.DetachGroupPolicy(OOS_IAM_DOMAIN,regionName,ak, sk, accountId, groupName, policyName, CreateHeaders(headers),403);
        IAMAPITestUtils.DeletePolicy(OOS_IAM_DOMAIN,regionName,ak, sk, accountId, policyName, CreateHeaders(headers),403);
        IAMAPITestUtils.DeactivateMFADevice(OOS_IAM_DOMAIN,regionName,ak, sk, userName, accountId,virtualMFADeviceName , CreateHeaders(headers),403);
        IAMAPITestUtils.DeleteVirtualMFADevice(OOS_IAM_DOMAIN,regionName,ak, sk, accountId, virtualMFADeviceName, CreateHeaders(headers),403);
        IAMAPITestUtils.DeleteAccountPasswordPolicy(OOS_IAM_DOMAIN,regionName,ak, sk, CreateHeaders(headers),403);
        IAMAPITestUtils.DeleteLoginProfile(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),403);
        IAMAPITestUtils.UntagUser(OOS_IAM_DOMAIN,regionName,ak, sk, userName, Arrays.asList("team"), CreateHeaders(headers),403);
        IAMAPITestUtils.DeleteAccessKey(OOS_IAM_DOMAIN,regionName,ak, sk, akId, userName, CreateHeaders(headers),403);
        IAMAPITestUtils.DeleteUser(OOS_IAM_DOMAIN,regionName,ak, sk, userName, CreateHeaders(headers),403);
        IAMAPITestUtils.RemoveUserFromGroup(OOS_IAM_DOMAIN,regionName,ak, sk, groupName, userName, CreateHeaders(headers),403);
        IAMAPITestUtils.DeleteGroup(OOS_IAM_DOMAIN,regionName,ak, sk, groupName, CreateHeaders(headers),403);
        
        IAMAPITestUtils.DeletePolicy(OOS_IAM_DOMAIN,regionName,rootak, rootsk, accountId, policyName, CreateHeaders(headers),200);
        IAMAPITestUtils.DeactivateMFADevice(OOS_IAM_DOMAIN,regionName,rootak, rootsk, userName, accountId,virtualMFADeviceName , CreateHeaders(headers),200);
        IAMAPITestUtils.DeleteVirtualMFADevice(OOS_IAM_DOMAIN,regionName,rootak, rootsk, accountId, virtualMFADeviceName, CreateHeaders(headers),200);
        IAMAPITestUtils.DeleteAccountPasswordPolicy(OOS_IAM_DOMAIN,regionName,rootak, rootsk, CreateHeaders(headers),200);
        IAMAPITestUtils.DeleteLoginProfile(OOS_IAM_DOMAIN,regionName,rootak, rootsk, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.UntagUser(OOS_IAM_DOMAIN,regionName,rootak, rootsk, userName, Arrays.asList("team"), CreateHeaders(headers),200);
        IAMAPITestUtils.DeleteAccessKey(OOS_IAM_DOMAIN,regionName,rootak, rootsk, akId, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.RemoveUserFromGroup(OOS_IAM_DOMAIN,regionName,rootak, rootsk, groupName, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.DeleteUser(OOS_IAM_DOMAIN,regionName,rootak, rootsk, userName, CreateHeaders(headers),200);
        IAMAPITestUtils.DeleteGroup(OOS_IAM_DOMAIN,regionName,rootak, rootsk, groupName, CreateHeaders(headers),200);
    }
    
   
    
    public static void OOS_APIALLAllow(String accessKey,String secretKey,List<String> headers) {
        
        
     // 获取所有bucket列表
        Pair<Integer, String> listallmybucket=OOSAPITestUtils.Service_Get(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, CreateHeaders(headers));
        assertEquals(200, listallmybucket.first().intValue());
        System.out.println(listallmybucket.second());
        
        // 获取资源池中的索引位置和数据位置列表
        Pair<Integer, String> getregion=OOSAPITestUtils.Region_Get(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, CreateHeaders(headers));
        assertEquals(200, getregion.first().intValue());
        System.out.println(getregion.second());
        
        // 创建bucket
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, null, null, null, null, CreateHeaders(headers));
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, "Specified", null, Arrays.asList(dateregion1), "NotAllowed", CreateHeaders(headers));
        assertEquals(200, createbucket2.first().intValue());
        System.out.println(createbucket2.second());
//        
//        // 获取bucket的ACL信息
        Pair<Integer, String> getbucketacl=OOSAPITestUtils.Bucket_GetAcl(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, CreateHeaders(headers));
        assertEquals(200, getbucketacl.first().intValue());
        System.out.println(getbucketacl.second());
        
        // 获取bucket的索引位置和数据位置 
        Pair<Integer, String> getbucketlocation=OOSAPITestUtils.Bucket_GetLocation(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, CreateHeaders(headers));
        assertEquals(200, getbucketlocation.first().intValue());
        System.out.println(getbucketlocation.second());
        
        // 创建，获取，删除bucketpolicy
        String policyString = "{" + "\"Version\": \"2012-10-17\","
                + "\"Id\": \"preventHotLinking\"," + "\"Statement\": [" + " {"
                + " \"Sid\": \"1\"," + "\"Effect\": \"Allow\","
                + "\"Principal\": {" + " \"AWS\": \"*\"" + "},"
                + "\"Action\": \"s3:ListBucket\","
                + "\"Resource\": \"arn:aws:s3:::" + bucketName2 + "\","
                + "}]}";
        Pair<Integer, String> putbucketpolicy=OOSAPITestUtils.Bucket_PutPolicy(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, policyString, CreateHeaders(headers));
        assertEquals(200, putbucketpolicy.first().intValue());
        System.out.println(putbucketpolicy.second());
        
        Pair<Integer, String> getbucketpolicy=OOSAPITestUtils.Bucket_GetPolicy(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, CreateHeaders(headers));
        assertEquals(200, getbucketpolicy.first().intValue());
        System.out.println(getbucketpolicy.second());
        
        Pair<Integer, String> delbucketpolicy=OOSAPITestUtils.Bucket_DeletePolicy(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, CreateHeaders(headers));
        assertEquals(200, delbucketpolicy.first().intValue());
        System.out.println(delbucketpolicy.second());
        
        // 创建，获取，删除website
        Pair<Integer, String> putbucketwebsite=OOSAPITestUtils.Bucket_PutWebsite(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, CreateHeaders(headers));
        assertEquals(200, putbucketwebsite.first().intValue());
        System.out.println(putbucketwebsite.second());
        
        Pair<Integer, String> getbucketwebsite=OOSAPITestUtils.Bucket_GetWebsite(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, CreateHeaders(headers));
        assertEquals(200, getbucketwebsite.first().intValue());
        System.out.println(getbucketwebsite.second());
        
        Pair<Integer, String> delbucketwebsite=OOSAPITestUtils.Bucket_DeleteWebsite(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, CreateHeaders(headers));
        assertEquals(200, delbucketwebsite.first().intValue());
        System.out.println(delbucketwebsite.second());
        
        // 创建，获取logging
        Pair<Integer, String> putbucketlogging=OOSAPITestUtils.Bucket_PutLogging(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, bucketName2,"logs/",CreateHeaders(headers));
        assertEquals(200, putbucketlogging.first().intValue());
        System.out.println(putbucketlogging.second());
        
        Pair<Integer, String> getbucketlogging=OOSAPITestUtils.Bucket_GetLogging(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, CreateHeaders(headers));
        assertEquals(200, getbucketlogging.first().intValue());
        System.out.println(getbucketlogging.second());
        
        // 创建，获取，删除lifecycle
        Pair<Integer, String> putbucketlifecle=OOSAPITestUtils.Bucket_PutLifecycle(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2,"logs","Enabled",30, CreateHeaders(headers));
        assertEquals(200, putbucketlifecle.first().intValue());
        System.out.println(putbucketlifecle.second());
        
        Pair<Integer, String> getbucketlifecle=OOSAPITestUtils.Bucket_GetLifecycle(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, CreateHeaders(headers));
        assertEquals(200, getbucketlifecle.first().intValue());
        System.out.println(getbucketlifecle.second());
        
        Pair<Integer, String> delbucketlifecle=OOSAPITestUtils.Bucket_DeleteLifecycle(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, CreateHeaders(headers));
        assertEquals(204, delbucketlifecle.first().intValue());
        System.out.println(delbucketlifecle.second());
        
        // 创建，获取cdn加速
        Pair<Integer, String> putbucketaccelerate=OOSAPITestUtils.Bucket_PutAccelerate(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, Arrays.asList("192.168.1.1","192.168.2.1"),CreateHeaders(headers));
        assertEquals(200, putbucketaccelerate.first().intValue());
        System.out.println(putbucketaccelerate.second());
        
        Pair<Integer, String> getbucketaccelerate=OOSAPITestUtils.Bucket_GetAccelerate(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, CreateHeaders(headers));
        assertEquals(200, getbucketaccelerate.first().intValue());
        System.out.println(getbucketaccelerate.second());
        
        // 创建，获取，删除cors 
        Pair<Integer, String> putbucketcors=OOSAPITestUtils.Bucket_PutCors(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, CreateHeaders(headers));
        assertEquals(200, putbucketcors.first().intValue());
        System.out.println(putbucketcors.second());
        
        Pair<Integer, String> getbucketcors=OOSAPITestUtils.Bucket_GetCors(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, CreateHeaders(headers));
        assertEquals(200, getbucketcors.first().intValue());
        System.out.println(getbucketcors.second());
        
        Pair<Integer, String> delbucketcors=OOSAPITestUtils.Bucket_DeleteCors(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, CreateHeaders(headers));
        assertEquals(200, delbucketcors.first().intValue());
        System.out.println(delbucketcors.second());
        
        // delete bucket
        Pair<Integer, String> delbucket=OOSAPITestUtils.Bucket_Delete(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, CreateHeaders(headers));
        assertEquals(204, delbucket.first().intValue());
        System.out.println(delbucket.second());
        
        // put get head delete object
        String objectName="src.txt";
        Pair<Integer, String> putobject=OOSAPITestUtils.Object_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, "first", CreateHeaders(headers));
        assertEquals(200, putobject.first().intValue());
        System.out.println(putobject.second());
        
        Pair<Integer, String> getobject=OOSAPITestUtils.Object_Get(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, CreateHeaders(headers));
        assertEquals(200, getobject.first().intValue());
        System.out.println(getobject.second());
        
        int headobject=OOSAPITestUtils.Object_Head(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, CreateHeaders(headers));
        assertEquals(200, headobject);
        
        Pair<Integer, String> delobject=OOSAPITestUtils.Object_Delete(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, CreateHeaders(headers));
        assertEquals(204, delobject.first().intValue());
        System.out.println(delobject.second());
        
        // post object
        Pair<Integer, String> postobject=OOSAPITestUtils.Object_Post(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, "post.txt", CreateHeaders(headers));
        assertEquals(204, postobject.first().intValue());
        System.out.println(postobject.second());
        
        // copy object
        String objectName2="desc.txt";
        Pair<Integer, String> copyobject=OOSAPITestUtils.Object_Copy(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, objectName2, CreateHeaders(headers));
        assertEquals(200, copyobject.first().intValue());
        System.out.println(copyobject.second());
        
        // bucket中的object信息
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, CreateHeaders(headers));
        assertEquals(200, listobjects.first().intValue());
        System.out.println(listobjects.second());
        
        // 分段上传，1.init 2.uploadpart,3.copy part,4.List Multipart Uploads,5.list part 6.Complete Multipart Upload,7.Abort Multipart Upload
        String objectName3="muli.txt";
        Pair<Integer, String> initmuli=OOSAPITestUtils.Object_InitialMultipartUpload(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, CreateHeaders(headers));
        assertEquals(200, initmuli.first().intValue());
        String uploadId=OOSAPITestUtils.getMultipartUploadId(initmuli.second());
        
        Pair<Integer, String> uploadpart=OOSAPITestUtils.Object_UploadPart(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, uploadId, 1, "123", CreateHeaders(headers));
        assertEquals(200, uploadpart.first().intValue());
        String etag1=uploadpart.second();
        Pair<Integer, String> copypart=OOSAPITestUtils.Object_CopyPart(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, uploadId, 2, objectName, CreateHeaders(headers));
        assertEquals(200, copypart.first().intValue());
        String etag2=OOSAPITestUtils.getCopyPartEtag(copypart.second());
        
        Pair<Integer, String> listMultipartUploads=OOSAPITestUtils.Bucket_ListMultipartUploads(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, CreateHeaders(headers));
        assertEquals(200, listMultipartUploads.first().intValue());
        
        Pair<Integer, String> listpart=OOSAPITestUtils.Object_ListPart(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, uploadId, CreateHeaders(headers));
        assertEquals(200, listpart.first().intValue());
        System.out.println(listpart.second());
        
        Map<String, String> partEtagMap = new HashMap<String, String>();
        partEtagMap.put("1", etag1);
        partEtagMap.put("2", etag2);

        Pair<Integer, String> completemultipart=OOSAPITestUtils.Object_CompleteMultipartUpload(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1,objectName3, uploadId, partEtagMap, CreateHeaders(headers));
        assertEquals(200, completemultipart.first().intValue());
        System.out.println(completemultipart.second());
        
        String objectName4="muli2.txt";
        Pair<Integer, String> initmuli2=OOSAPITestUtils.Object_InitialMultipartUpload(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName4, CreateHeaders(headers));
        assertEquals(200, initmuli2.first().intValue());
        String uploadId2=OOSAPITestUtils.getMultipartUploadId(initmuli2.second());
        
        Pair<Integer, String> uploadpart2=OOSAPITestUtils.Object_UploadPart(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName4, uploadId2, 1, "123", CreateHeaders(headers));
        assertEquals(200, uploadpart2.first().intValue());
        String etag3=uploadpart2.second();
        Pair<Integer, String> copypart2=OOSAPITestUtils.Object_CopyPart(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName4, uploadId2, 2, objectName, CreateHeaders(headers));
        assertEquals(200, copypart2.first().intValue());
        String etag4=OOSAPITestUtils.getCopyPartEtag(copypart2.second());

        Pair<Integer, String> aboutmultipart=OOSAPITestUtils.object_AbortMultipartUpload(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName4, uploadId2, CreateHeaders(headers));
        assertEquals(204, aboutmultipart.first().intValue());
        System.out.println(aboutmultipart.second());
        
        // delete mulit 
        Pair<Integer, String> delobjects=OOSAPITestUtils.Object_DeleteMulit(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, Arrays.asList(objectName,objectName2,objectName3,objectName4), CreateHeaders(headers));
        assertEquals(200, delobjects.first().intValue());
        System.out.println(delobjects.second());
        
        // delete bucket
        Pair<Integer, String> delbucket2=OOSAPITestUtils.Bucket_Delete(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, CreateHeaders(headers));
        assertEquals(204, delbucket2.first().intValue());
        System.out.println(delbucket2.second());
    }
    
    public static void OOS_APIALLDeny(String rootak,String rootsk,String accessKey,String secretKey) {
     // 获取所有bucket列表
        Pair<Integer, String> listallmybucket=OOSAPITestUtils.Service_Get(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, null);
        assertEquals(403, listallmybucket.first().intValue());
        System.out.println(listallmybucket.second());
        
        // 获取资源池中的索引位置和数据位置列表
        Pair<Integer, String> getregion=OOSAPITestUtils.Region_Get(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, null);
        assertEquals(403, getregion.first().intValue());
        System.out.println(getregion.second());
        
        // 创建bucket
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, null, null, null, null, null);
        assertEquals(403, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> createbucket1root=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, null, null, null, null, null);
        assertEquals(200, createbucket1root.first().intValue());
        System.out.println(createbucket1root.second());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, "Specified", null, Arrays.asList(dateregion1), "NotAllowed", null);
        assertEquals(403, createbucket2.first().intValue());
        System.out.println(createbucket2.second());
        
        Pair<Integer, String> createbucket2root=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, "Specified", null, Arrays.asList(dateregion1), "NotAllowed", null);
        assertEquals(200, createbucket2root.first().intValue());
        System.out.println(createbucket2root.second());
//        
//        // 获取bucket的ACL信息
        Pair<Integer, String> getbucketacl=OOSAPITestUtils.Bucket_GetAcl(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, getbucketacl.first().intValue());
        System.out.println(getbucketacl.second());
        
        // 修改bucket acl属性
        HashMap<String, String> updateaclParams=new HashMap<String, String>();
        updateaclParams.put("x-amz-acl", "public-read-write");
        Pair<Integer, String> updatebucket=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, "Specified", null, Arrays.asList(dateregion1), "NotAllowed", updateaclParams);
        assertEquals(403, updatebucket.first().intValue());
        System.out.println(updatebucket.second());
        
        // 获取bucket的索引位置和数据位置 
        Pair<Integer, String> getbucketlocation=OOSAPITestUtils.Bucket_GetLocation(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, getbucketlocation.first().intValue());
        System.out.println(getbucketlocation.second());
        
        // 创建，获取，删除bucketpolicy
        String policyString = "{" + "\"Version\": \"2012-10-17\","
                + "\"Id\": \"preventHotLinking\"," + "\"Statement\": [" + " {"
                + " \"Sid\": \"1\"," + "\"Effect\": \"Allow\","
                + "\"Principal\": {" + " \"AWS\": \"*\"" + "},"
                + "\"Action\": \"s3:ListBucket\","
                + "\"Resource\": \"arn:aws:s3:::" + bucketName2 + "\","
                + "}]}";
        Pair<Integer, String> putbucketpolicy=OOSAPITestUtils.Bucket_PutPolicy(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, policyString, null);
        assertEquals(403, putbucketpolicy.first().intValue());
        System.out.println(putbucketpolicy.second());
        
        Pair<Integer, String> putbucketpolicyroot=OOSAPITestUtils.Bucket_PutPolicy(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, policyString, null);
        assertEquals(200, putbucketpolicyroot.first().intValue());
        System.out.println(putbucketpolicyroot.second());
        
        Pair<Integer, String> getbucketpolicy=OOSAPITestUtils.Bucket_GetPolicy(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, getbucketpolicy.first().intValue());
        System.out.println(getbucketpolicy.second());
        
        Pair<Integer, String> delbucketpolicy=OOSAPITestUtils.Bucket_DeletePolicy(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, delbucketpolicy.first().intValue());
        System.out.println(delbucketpolicy.second());
        
        // 创建，获取，删除website
        Pair<Integer, String> putbucketwebsite=OOSAPITestUtils.Bucket_PutWebsite(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, putbucketwebsite.first().intValue());
        System.out.println(putbucketwebsite.second());
        
        Pair<Integer, String> putbucketwebsiteroot=OOSAPITestUtils.Bucket_PutWebsite(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, null);
        assertEquals(200, putbucketwebsiteroot.first().intValue());
        System.out.println(putbucketwebsiteroot.second());
        
        Pair<Integer, String> getbucketwebsite=OOSAPITestUtils.Bucket_GetWebsite(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, getbucketwebsite.first().intValue());
        System.out.println(getbucketwebsite.second());
        
        Pair<Integer, String> delbucketwebsite=OOSAPITestUtils.Bucket_DeleteWebsite(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, delbucketwebsite.first().intValue());
        System.out.println(delbucketwebsite.second());
        
        // 创建，获取logging
        Pair<Integer, String> putbucketlogging=OOSAPITestUtils.Bucket_PutLogging(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, bucketName2,"logs/",null);
        assertEquals(403, putbucketlogging.first().intValue());
        System.out.println(putbucketlogging.second());
        
        Pair<Integer, String> putbucketloggingroot=OOSAPITestUtils.Bucket_PutLogging(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, bucketName2,"logs/",null);
        assertEquals(200, putbucketloggingroot.first().intValue());
        System.out.println(putbucketloggingroot.second());
        
        Pair<Integer, String> getbucketlogging=OOSAPITestUtils.Bucket_GetLogging(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, getbucketlogging.first().intValue());
        System.out.println(getbucketlogging.second());
        
        // 创建，获取，删除lifecycle
        Pair<Integer, String> putbucketlifecle=OOSAPITestUtils.Bucket_PutLifecycle(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2,"logs","Enabled",30, null);
        assertEquals(403, putbucketlifecle.first().intValue());
        System.out.println(putbucketlifecle.second());
        
        Pair<Integer, String> putbucketlifecleroot=OOSAPITestUtils.Bucket_PutLifecycle(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2,"logs","Enabled",30, null);
        assertEquals(200, putbucketlifecleroot.first().intValue());
        System.out.println(putbucketlifecleroot.second());
        
        Pair<Integer, String> getbucketlifecle=OOSAPITestUtils.Bucket_GetLifecycle(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, getbucketlifecle.first().intValue());
        System.out.println(getbucketlifecle.second());
        
        Pair<Integer, String> delbucketlifecle=OOSAPITestUtils.Bucket_DeleteLifecycle(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, delbucketlifecle.first().intValue());
        System.out.println(delbucketlifecle.second());
        
        // 创建，获取cdn加速
        Pair<Integer, String> putbucketaccelerate=OOSAPITestUtils.Bucket_PutAccelerate(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, Arrays.asList("192.168.1.1","192.168.2.1"),null);
        assertEquals(403, putbucketaccelerate.first().intValue());
        System.out.println(putbucketaccelerate.second());
        
        Pair<Integer, String> putbucketaccelerateroot=OOSAPITestUtils.Bucket_PutAccelerate(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, Arrays.asList("192.168.1.1","192.168.2.1"),null);
        assertEquals(200, putbucketaccelerateroot.first().intValue());
        System.out.println(putbucketaccelerateroot.second());
        
        Pair<Integer, String> getbucketaccelerate=OOSAPITestUtils.Bucket_GetAccelerate(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, getbucketaccelerate.first().intValue());
        System.out.println(getbucketaccelerate.second());
        
        // 创建，获取，删除cors 
        Pair<Integer, String> putbucketcors=OOSAPITestUtils.Bucket_PutCors(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, putbucketcors.first().intValue());
        System.out.println(putbucketcors.second());
        
        Pair<Integer, String> putbucketcorsroot=OOSAPITestUtils.Bucket_PutCors(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, null);
        assertEquals(200, putbucketcorsroot.first().intValue());
        System.out.println(putbucketcorsroot.second());
        
        Pair<Integer, String> getbucketcors=OOSAPITestUtils.Bucket_GetCors(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, getbucketcors.first().intValue());
        System.out.println(getbucketcors.second());
        
        Pair<Integer, String> delbucketcors=OOSAPITestUtils.Bucket_DeleteCors(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, delbucketcors.first().intValue());
        System.out.println(delbucketcors.second());
         
        // delete bucket
        Pair<Integer, String> delbucket=OOSAPITestUtils.Bucket_Delete(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, delbucket.first().intValue());
        System.out.println(delbucket.second());
        
        Pair<Integer, String> delbucketroot=OOSAPITestUtils.Bucket_Delete(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, null);
        assertEquals(204, delbucketroot.first().intValue());
        System.out.println(delbucketroot.second());
        
        // put get head delete object
        String objectName="src.txt";
        Pair<Integer, String> putobject=OOSAPITestUtils.Object_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, "first", null);
        assertEquals(403, putobject.first().intValue());
        System.out.println(putobject.second());
        
        Pair<Integer, String> putobjectroot=OOSAPITestUtils.Object_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName, "first", null);
        assertEquals(200, putobjectroot.first().intValue());
        System.out.println(putobjectroot.second());
        
        Pair<Integer, String> getobject=OOSAPITestUtils.Object_Get(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, null);
        assertEquals(403, getobject.first().intValue());
        System.out.println(getobject.second());
        
        int headobject=OOSAPITestUtils.Object_Head(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, null);
        assertEquals(403, headobject);
        
        Pair<Integer, String> delobject=OOSAPITestUtils.Object_Delete(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, null);
        assertEquals(403, delobject.first().intValue());
        System.out.println(delobject.second());
        
        Pair<Integer, String> delobjectroot=OOSAPITestUtils.Object_Delete(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName, null);
        assertEquals(204, delobjectroot.first().intValue());
        System.out.println(delobjectroot.second());
        
        // post object
        Pair<Integer, String> postobject=OOSAPITestUtils.Object_Post(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, "post.txt", null);
        assertEquals(403, postobject.first().intValue());
        System.out.println(postobject.second());
        
        Pair<Integer, String> postobjectroot=OOSAPITestUtils.Object_Post(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName, "post.txt", null);
        assertEquals(204, postobjectroot.first().intValue());
        System.out.println(postobjectroot.second());
        
        // copy object
        String objectName2="desc.txt";
        Pair<Integer, String> copyobject=OOSAPITestUtils.Object_Copy(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, objectName2, null);
        assertEquals(403, copyobject.first().intValue());
        System.out.println(copyobject.second());
        
        Pair<Integer, String> copyobjectroot=OOSAPITestUtils.Object_Copy(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName, objectName2, null);
        assertEquals(200, copyobjectroot.first().intValue());
        System.out.println(copyobjectroot.second());
        
        // bucket中的object信息
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, null);
        assertEquals(403, listobjects.first().intValue());
        System.out.println(listobjects.second());
        
        // 分段上传，1.init 2.uploadpart,3.copy part,4.List Multipart Uploads,5.list part 6.Complete Multipart Upload,7.Abort Multipart Upload
        String objectName3="muli.txt";
        Pair<Integer, String> initmuli=OOSAPITestUtils.Object_InitialMultipartUpload(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, null);
        assertEquals(403, initmuli.first().intValue());
 
        Pair<Integer, String> initmuliroot=OOSAPITestUtils.Object_InitialMultipartUpload(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName3, null);
        assertEquals(200, initmuliroot.first().intValue());
        String uploadId=OOSAPITestUtils.getMultipartUploadId(initmuliroot.second());
        
        Pair<Integer, String> uploadpart=OOSAPITestUtils.Object_UploadPart(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, uploadId, 1, "123", null);
        assertEquals(403, uploadpart.first().intValue());
        Pair<Integer, String> copypart=OOSAPITestUtils.Object_CopyPart(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, uploadId, 2, objectName, null);
        assertEquals(403, copypart.first().intValue());
        
        Pair<Integer, String> uploadpartroot=OOSAPITestUtils.Object_UploadPart(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName3, uploadId, 1, "123", null);
        assertEquals(200, uploadpartroot.first().intValue());
        String etag1=uploadpartroot.second();
        Pair<Integer, String> copypartroot=OOSAPITestUtils.Object_CopyPart(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName3, uploadId, 2, objectName, null);
        assertEquals(200, copypartroot.first().intValue());
        String etag2=OOSAPITestUtils.getCopyPartEtag(copypartroot.second());
        
        Pair<Integer, String> listMultipartUploads=OOSAPITestUtils.Bucket_ListMultipartUploads(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, null);
        assertEquals(403, listMultipartUploads.first().intValue());
        
        Pair<Integer, String> listpart=OOSAPITestUtils.Object_ListPart(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, uploadId, null);
        assertEquals(403, listpart.first().intValue());
        System.out.println(listpart.second());
        
        Map<String, String> partEtagMap = new HashMap<String, String>();
        partEtagMap.put("1", etag1);
        partEtagMap.put("2", etag2);

        Pair<Integer, String> completemultipart=OOSAPITestUtils.Object_CompleteMultipartUpload(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1,objectName3, uploadId, partEtagMap, null);
        assertEquals(403, completemultipart.first().intValue());
        System.out.println(completemultipart.second());
        
        Pair<Integer, String> aboutmultipart=OOSAPITestUtils.object_AbortMultipartUpload(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, uploadId, null);
        assertEquals(403, aboutmultipart.first().intValue());
        System.out.println(aboutmultipart.second());
        
        Pair<Integer, String> aboutmultipartroot=OOSAPITestUtils.object_AbortMultipartUpload(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName3, uploadId, null);
        assertEquals(204, aboutmultipartroot.first().intValue());
        System.out.println(aboutmultipartroot.second());
        
        // delete mulit 
        Pair<Integer, String> delobjects=OOSAPITestUtils.Object_DeleteMulit(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, Arrays.asList(objectName,objectName2,objectName3), null);
        assertEquals(403, delobjects.first().intValue());
        System.out.println(delobjects.second());
        
        Pair<Integer, String> delobjectsroot=OOSAPITestUtils.Object_DeleteMulit(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, Arrays.asList(objectName,objectName2,objectName3), null);
        assertEquals(200, delobjectsroot.first().intValue());
        System.out.println(delobjectsroot.second());
        
        // delete bucket
        Pair<Integer, String> delbucket2=OOSAPITestUtils.Bucket_Delete(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, null);
        assertEquals(403, delbucket2.first().intValue());
        System.out.println(delbucket2.second());
        
        Pair<Integer, String> delbucket2root=OOSAPITestUtils.Bucket_Delete(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, null);
        assertEquals(204, delbucket2root.first().intValue());
        System.out.println(delbucket2root.second());
    }
    
    public static void OOS_APIReadOnly(String rootak,String rootsk,String accessKey,String secretKey) {

     // 获取所有bucket列表
        Pair<Integer, String> listallmybucket=OOSAPITestUtils.Service_Get(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, null);
        assertEquals(200, listallmybucket.first().intValue());
        System.out.println(listallmybucket.second());
        
        // 获取资源池中的索引位置和数据位置列表
        Pair<Integer, String> getregion=OOSAPITestUtils.Region_Get(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, null);
        assertEquals(200, getregion.first().intValue());
        System.out.println(getregion.second());
        
        // 创建bucket
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, null, null, null, null, null);
        assertEquals(403, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> createbucket1root=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, null, null, null, null, null);
        assertEquals(200, createbucket1root.first().intValue());
        System.out.println(createbucket1root.second());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, "Specified", null, Arrays.asList(dateregion1), "NotAllowed", null);
        assertEquals(403, createbucket2.first().intValue());
        System.out.println(createbucket2.second());
        
        Pair<Integer, String> createbucket2root=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, "Specified", null, Arrays.asList(dateregion1), "NotAllowed", null);
        assertEquals(200, createbucket2root.first().intValue());
        System.out.println(createbucket2root.second());
//        
//        // 获取bucket的ACL信息
        Pair<Integer, String> getbucketacl=OOSAPITestUtils.Bucket_GetAcl(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketacl.first().intValue());
        System.out.println(getbucketacl.second());
        
        // 修改bucket acl属性
        HashMap<String, String> updateaclParams=new HashMap<String, String>();
        updateaclParams.put("x-amz-acl", "public-read-write");
        Pair<Integer, String> updatebucket=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, "Specified", null, Arrays.asList(dateregion1), "NotAllowed", updateaclParams);
        assertEquals(403, updatebucket.first().intValue());
        System.out.println(updatebucket.second());
        
        // 获取bucket的索引位置和数据位置 
        Pair<Integer, String> getbucketlocation=OOSAPITestUtils.Bucket_GetLocation(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketlocation.first().intValue());
        System.out.println(getbucketlocation.second());
        
        // 创建，获取，删除bucketpolicy
        String policyString = "{" + "\"Version\": \"2012-10-17\","
                + "\"Id\": \"preventHotLinking\"," + "\"Statement\": [" + " {"
                + " \"Sid\": \"1\"," + "\"Effect\": \"Allow\","
                + "\"Principal\": {" + " \"AWS\": \"*\"" + "},"
                + "\"Action\": \"s3:ListBucket\","
                + "\"Resource\": \"arn:aws:s3:::" + bucketName2 + "\","
                + "}]}";
        Pair<Integer, String> putbucketpolicy=OOSAPITestUtils.Bucket_PutPolicy(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, policyString, null);
        assertEquals(403, putbucketpolicy.first().intValue());
        System.out.println(putbucketpolicy.second());
        
        Pair<Integer, String> putbucketpolicyroot=OOSAPITestUtils.Bucket_PutPolicy(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, policyString, null);
        assertEquals(200, putbucketpolicyroot.first().intValue());
        System.out.println(putbucketpolicyroot.second());
        
        Pair<Integer, String> getbucketpolicy=OOSAPITestUtils.Bucket_GetPolicy(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketpolicy.first().intValue());
        System.out.println(getbucketpolicy.second());
        
        Pair<Integer, String> delbucketpolicy=OOSAPITestUtils.Bucket_DeletePolicy(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, delbucketpolicy.first().intValue());
        System.out.println(delbucketpolicy.second());
        
        // 创建，获取，删除website
        Pair<Integer, String> putbucketwebsite=OOSAPITestUtils.Bucket_PutWebsite(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, putbucketwebsite.first().intValue());
        System.out.println(putbucketwebsite.second());
        
        Pair<Integer, String> putbucketwebsiteroot=OOSAPITestUtils.Bucket_PutWebsite(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, null);
        assertEquals(200, putbucketwebsiteroot.first().intValue());
        System.out.println(putbucketwebsiteroot.second());
        
        Pair<Integer, String> getbucketwebsite=OOSAPITestUtils.Bucket_GetWebsite(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketwebsite.first().intValue());
        System.out.println(getbucketwebsite.second());
        
        Pair<Integer, String> delbucketwebsite=OOSAPITestUtils.Bucket_DeleteWebsite(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, delbucketwebsite.first().intValue());
        System.out.println(delbucketwebsite.second());
        
        // 创建，获取logging
        Pair<Integer, String> putbucketlogging=OOSAPITestUtils.Bucket_PutLogging(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, bucketName2,"logs/",null);
        assertEquals(403, putbucketlogging.first().intValue());
        System.out.println(putbucketlogging.second());
        
        Pair<Integer, String> putbucketloggingroot=OOSAPITestUtils.Bucket_PutLogging(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, bucketName2,"logs/",null);
        assertEquals(200, putbucketloggingroot.first().intValue());
        System.out.println(putbucketloggingroot.second());
        
        Pair<Integer, String> getbucketlogging=OOSAPITestUtils.Bucket_GetLogging(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketlogging.first().intValue());
        System.out.println(getbucketlogging.second());
        
        // 创建，获取，删除lifecycle
        Pair<Integer, String> putbucketlifecle=OOSAPITestUtils.Bucket_PutLifecycle(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2,"logs","Enabled",30, null);
        assertEquals(403, putbucketlifecle.first().intValue());
        System.out.println(putbucketlifecle.second());
        
        Pair<Integer, String> putbucketlifecleroot=OOSAPITestUtils.Bucket_PutLifecycle(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2,"logs","Enabled",30, null);
        assertEquals(200, putbucketlifecleroot.first().intValue());
        System.out.println(putbucketlifecleroot.second());
        
        Pair<Integer, String> getbucketlifecle=OOSAPITestUtils.Bucket_GetLifecycle(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketlifecle.first().intValue());
        System.out.println(getbucketlifecle.second());
        
        Pair<Integer, String> delbucketlifecle=OOSAPITestUtils.Bucket_DeleteLifecycle(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, delbucketlifecle.first().intValue());
        System.out.println(delbucketlifecle.second());
        
        // 创建，获取cdn加速
        Pair<Integer, String> putbucketaccelerate=OOSAPITestUtils.Bucket_PutAccelerate(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, Arrays.asList("192.168.1.1","192.168.2.1"),null);
        assertEquals(403, putbucketaccelerate.first().intValue());
        System.out.println(putbucketaccelerate.second());
        
        Pair<Integer, String> putbucketaccelerateroot=OOSAPITestUtils.Bucket_PutAccelerate(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, Arrays.asList("192.168.1.1","192.168.2.1"),null);
        assertEquals(200, putbucketaccelerateroot.first().intValue());
        System.out.println(putbucketaccelerateroot.second());
        
        Pair<Integer, String> getbucketaccelerate=OOSAPITestUtils.Bucket_GetAccelerate(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketaccelerate.first().intValue());
        System.out.println(getbucketaccelerate.second());
        
        // 创建，获取，删除cors 
        Pair<Integer, String> putbucketcors=OOSAPITestUtils.Bucket_PutCors(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, putbucketcors.first().intValue());
        System.out.println(putbucketcors.second());
        
        Pair<Integer, String> putbucketcorsroot=OOSAPITestUtils.Bucket_PutCors(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, null);
        assertEquals(200, putbucketcorsroot.first().intValue());
        System.out.println(putbucketcorsroot.second());
        
        Pair<Integer, String> getbucketcors=OOSAPITestUtils.Bucket_GetCors(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketcors.first().intValue());
        System.out.println(getbucketcors.second());
        
        Pair<Integer, String> delbucketcors=OOSAPITestUtils.Bucket_DeleteCors(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, delbucketcors.first().intValue());
        System.out.println(delbucketcors.second());
         
        // delete bucket
        Pair<Integer, String> delbucket=OOSAPITestUtils.Bucket_Delete(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, delbucket.first().intValue());
        System.out.println(delbucket.second());
        
        Pair<Integer, String> delbucketroot=OOSAPITestUtils.Bucket_Delete(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, null);
        assertEquals(204, delbucketroot.first().intValue());
        System.out.println(delbucketroot.second());
        
        // put get head delete object
        String objectName="src.txt";
        Pair<Integer, String> putobject=OOSAPITestUtils.Object_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, "first", null);
        assertEquals(403, putobject.first().intValue());
        System.out.println(putobject.second());
        
        Pair<Integer, String> putobjectroot=OOSAPITestUtils.Object_Put(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName, "first", null);
        assertEquals(200, putobjectroot.first().intValue());
        System.out.println(putobjectroot.second());
        
        Pair<Integer, String> getobject=OOSAPITestUtils.Object_Get(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, null);
        assertEquals(200, getobject.first().intValue());
        System.out.println(getobject.second());
        
        int headobject=OOSAPITestUtils.Object_Head(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, null);
        assertEquals(200, headobject);
        
        Pair<Integer, String> delobject=OOSAPITestUtils.Object_Delete(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, null);
        assertEquals(403, delobject.first().intValue());
        System.out.println(delobject.second());
        
        Pair<Integer, String> delobjectroot=OOSAPITestUtils.Object_Delete(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName, null);
        assertEquals(204, delobjectroot.first().intValue());
        System.out.println(delobjectroot.second());
        
        // post object
        Pair<Integer, String> postobject=OOSAPITestUtils.Object_Post(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, "post.txt", null);
        assertEquals(403, postobject.first().intValue());
        System.out.println(postobject.second());
        
        Pair<Integer, String> postobjectroot=OOSAPITestUtils.Object_Post(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName, "post.txt", null);
        assertEquals(204, postobjectroot.first().intValue());
        System.out.println(postobjectroot.second());
        
        // copy object
        String objectName2="desc.txt";
        Pair<Integer, String> copyobject=OOSAPITestUtils.Object_Copy(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, objectName2, null);
        assertEquals(403, copyobject.first().intValue());
        System.out.println(copyobject.second());
        
        Pair<Integer, String> copyobjectroot=OOSAPITestUtils.Object_Copy(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName, objectName2, null);
        assertEquals(200, copyobjectroot.first().intValue());
        System.out.println(copyobjectroot.second());
        
        // bucket中的object信息
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, null);
        assertEquals(200, listobjects.first().intValue());
        System.out.println(listobjects.second());
        
        // 分段上传，1.init 2.uploadpart,3.copy part,4.List Multipart Uploads,5.list part 6.Complete Multipart Upload,7.Abort Multipart Upload
        String objectName3="muli.txt";
        Pair<Integer, String> initmuli=OOSAPITestUtils.Object_InitialMultipartUpload(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, null);
        assertEquals(403, initmuli.first().intValue());
 
        Pair<Integer, String> initmuliroot=OOSAPITestUtils.Object_InitialMultipartUpload(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName3, null);
        assertEquals(200, initmuliroot.first().intValue());
        String uploadId=OOSAPITestUtils.getMultipartUploadId(initmuliroot.second());
        
        Pair<Integer, String> uploadpart=OOSAPITestUtils.Object_UploadPart(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, uploadId, 1, "123", null);
        assertEquals(403, uploadpart.first().intValue());
        Pair<Integer, String> copypart=OOSAPITestUtils.Object_CopyPart(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, uploadId, 2, objectName, null);
        assertEquals(403, copypart.first().intValue());
        
        Pair<Integer, String> uploadpartroot=OOSAPITestUtils.Object_UploadPart(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName3, uploadId, 1, "123", null);
        assertEquals(200, uploadpartroot.first().intValue());
        String etag1=uploadpartroot.second();
        Pair<Integer, String> copypartroot=OOSAPITestUtils.Object_CopyPart(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName3, uploadId, 2, objectName, null);
        assertEquals(200, copypartroot.first().intValue());
        String etag2=OOSAPITestUtils.getCopyPartEtag(copypartroot.second());
        
        Pair<Integer, String> listMultipartUploads=OOSAPITestUtils.Bucket_ListMultipartUploads(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, null);
        assertEquals(200, listMultipartUploads.first().intValue());
        
        Pair<Integer, String> listpart=OOSAPITestUtils.Object_ListPart(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, uploadId, null);
        assertEquals(200, listpart.first().intValue());
        System.out.println(listpart.second());
        
        Map<String, String> partEtagMap = new HashMap<String, String>();
        partEtagMap.put("1", etag1);
        partEtagMap.put("2", etag2);

        Pair<Integer, String> completemultipart=OOSAPITestUtils.Object_CompleteMultipartUpload(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1,objectName3, uploadId, partEtagMap, null);
        assertEquals(403, completemultipart.first().intValue());
        System.out.println(completemultipart.second());
        
        Pair<Integer, String> aboutmultipart=OOSAPITestUtils.object_AbortMultipartUpload(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, uploadId, null);
        assertEquals(403, aboutmultipart.first().intValue());
        System.out.println(aboutmultipart.second());
        
        Pair<Integer, String> aboutmultipartroot=OOSAPITestUtils.object_AbortMultipartUpload(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName3, uploadId, null);
        assertEquals(204, aboutmultipartroot.first().intValue());
        System.out.println(aboutmultipartroot.second());
        
        // delete mulit 
        Pair<Integer, String> delobjects=OOSAPITestUtils.Object_DeleteMulit(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, Arrays.asList(objectName,objectName2,objectName3), null);
        assertEquals(403, delobjects.first().intValue());
        System.out.println(delobjects.second());
        
        Pair<Integer, String> delobjectsroot=OOSAPITestUtils.Object_DeleteMulit(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, Arrays.asList(objectName,objectName2,objectName3), null);
        assertEquals(200, delobjectsroot.first().intValue());
        System.out.println(delobjectsroot.second());
        
        // delete bucket
        Pair<Integer, String> delbucket2=OOSAPITestUtils.Bucket_Delete(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, null);
        assertEquals(403, delbucket2.first().intValue());
        System.out.println(delbucket2.second());
        
        Pair<Integer, String> delbucket2root=OOSAPITestUtils.Bucket_Delete(httpOrHttps, jettyhost, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, null);
        assertEquals(204, delbucket2root.first().intValue());
        System.out.println(delbucket2root.second());
    }
    
    public static void OOS_PreSignAllAllow(String accessKey,String secretKey,String bucketName,List<String> headers,List<String> querys) {
        String objectName="object1.txt";
        String objectName2="mulit1.txt";
        String objectName3="mulit2.txt";
        String objectName4="mulit3.txt";
        String objectContent="first";
        
        String putobjectv4url=OOSAPIPresignedUrlUtils.Object_Put_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName, objectContent, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn=creatConn(putobjectv4url, "PUT", CreateHeaders(headers));
        try {
            OutputStream wr = conn.getOutputStream();
            wr.write(objectContent.getBytes());
            wr.flush();
            wr.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        Pair<Integer, String> putobjectv4result=OOSAPITestUtils.GetResult(conn);
        assertEquals(200, putobjectv4result.first().intValue());
        
        // get head v4
        String getobjectv4url=OOSAPIPresignedUrlUtils.Object_Get_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName,CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn1=creatConn(getobjectv4url, "GET", CreateHeaders(headers));
        Pair<Integer, String> getobjectv4result=OOSAPITestUtils.GetResult(conn1);
        assertEquals(200, getobjectv4result.first().intValue());
        
        String headobjectv4url=OOSAPIPresignedUrlUtils.Object_Head_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName,CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn2=creatConn(headobjectv4url, "HEAD", CreateHeaders(headers));
        try {
            conn2.connect();
            int code = conn2.getResponseCode();
            assertEquals(200, code);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // get v2
        String getobjectv2url=OOSAPIPresignedUrlUtils.Object_get_V2_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName,CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn3=creatConn(getobjectv2url, "GET", CreateHeaders(headers));
        Pair<Integer, String> getobjectv2result=OOSAPITestUtils.GetResult(conn3);
        assertEquals(200, getobjectv2result.first().intValue());
        
        // delete v4
        String delobjectv4url=OOSAPIPresignedUrlUtils.Object_Delete_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName,CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn4=creatConn(delobjectv4url, "DELETE", CreateHeaders(headers));
        Pair<Integer, String> delobjectv4result=OOSAPITestUtils.GetResult(conn4);
        assertEquals(204, delobjectv4result.first().intValue());
        
//         initial v4
        String initialobjectv4url=OOSAPIPresignedUrlUtils.Object_InitialMultipartUpload_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName2,CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn5=creatConn(initialobjectv4url, "POST", CreateHeaders(headers));
        Pair<Integer, String> initialobjectv4result=OOSAPITestUtils.GetResult(conn5);
        assertEquals(200, initialobjectv4result.first().intValue());
        String uploadId1=OOSAPITestUtils.getMultipartUploadId(initialobjectv4result.second());
        
        // upload v4
        String partContent1="123";
        String partContent2="456";
        String etag1="";
        String etag2="";
        String uploadobjectv4url1=OOSAPIPresignedUrlUtils.Object_UploadPart_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName2,uploadId1, 1, partContent1, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn6=creatConn(uploadobjectv4url1, "PUT", CreateHeaders(headers));
        try {
            
            OutputStream wr = conn6.getOutputStream();
            wr.write(partContent1.getBytes());
            wr.flush();
            wr.close();
            
            conn6.connect();
            
            int code = conn6.getResponseCode();
            assertEquals(200, code);
            String etag = conn6.getHeaderField("ETag");
            etag1=etag;
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        String uploadobjectv4url2=OOSAPIPresignedUrlUtils.Object_UploadPart_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName2,uploadId1, 2, partContent2, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn7=creatConn(uploadobjectv4url2, "PUT", CreateHeaders(headers));
        try {
            
            OutputStream wr = conn7.getOutputStream();
            wr.write(partContent2.getBytes());
            wr.flush();
            wr.close();
            
            conn7.connect();
            
            int code = conn7.getResponseCode();
            assertEquals(200, code);
            String etag = conn7.getHeaderField("ETag");
            etag2=etag;
            
        } catch (Exception e) {
            e.printStackTrace();
        }

        // list part v4 v2
        String listpartv4url=OOSAPIPresignedUrlUtils.Object_ListPart_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName2,uploadId1, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn8=creatConn(listpartv4url, "GET", CreateHeaders(headers));
        Pair<Integer, String> listpartv4result=OOSAPITestUtils.GetResult(conn8);
        assertEquals(200, listpartv4result.first().intValue());
        
        String listpartv2url=OOSAPIPresignedUrlUtils.Object_ListPart_V2_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName2,uploadId1, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn9=creatConn(listpartv2url, "GET", CreateHeaders(headers));
        Pair<Integer, String> listpartv2result=OOSAPITestUtils.GetResult(conn9);
        assertEquals(200, listpartv2result.first().intValue());
        
        // complete v4
       
        Map<String, String> partEtagMap = new HashMap<String, String>();
        partEtagMap.put("1", etag1);
        partEtagMap.put("2", etag2);
        String completeString=OOSAPIPresignedUrlUtils.createCompleteMultipartUploadBody(partEtagMap);
        System.out.println("completeString="+completeString);
        String completev4url=OOSAPIPresignedUrlUtils.Object_CompleteMultipartUpload_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName2,uploadId1, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn10=creatConn(completev4url, "POST", CreateHeaders(headers));
        try {
            OutputStream wr = conn10.getOutputStream();
            wr.write(completeString.getBytes());
            wr.flush();
            wr.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        Pair<Integer, String> completev4result=OOSAPITestUtils.GetResult(conn10);
        assertEquals(200, completev4result.first().intValue());

        // initial v2
        String initialobjectv2url=OOSAPIPresignedUrlUtils.Object_InitialMultipartUpload_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName3,CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn11=creatConn(initialobjectv2url, "POST", CreateHeaders(headers));
        Pair<Integer, String> initialobjectv2result=OOSAPITestUtils.GetResult(conn11);
        assertEquals(200, initialobjectv2result.first().intValue());
        String uploadId2=OOSAPITestUtils.getMultipartUploadId(initialobjectv2result.second());
        
        // upload v4
        String etag3="";
        String etag4="";
        String uploadobjectv4url3=OOSAPIPresignedUrlUtils.Object_UploadPart_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName3,uploadId2, 1, partContent1, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn12=creatConn(uploadobjectv4url3, "PUT", CreateHeaders(headers));
        try {
            
            OutputStream wr = conn12.getOutputStream();
            wr.write(partContent1.getBytes());
            wr.flush();
            wr.close();
            
            conn12.connect();
            int code = conn12.getResponseCode();
            assertEquals(200, code);
            String etag = conn12.getHeaderField("ETag");
            etag3=etag;
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        String uploadobjectv4url4=OOSAPIPresignedUrlUtils.Object_UploadPart_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName3,uploadId2, 2, partContent2, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn13=creatConn(uploadobjectv4url4, "PUT", CreateHeaders(headers));
        try {
            
            OutputStream wr = conn13.getOutputStream();
            wr.write(partContent2.getBytes());
            wr.flush();
            wr.close();
            
            conn13.connect();
            
            int code = conn13.getResponseCode();
            assertEquals(200, code);
            String etag = conn13.getHeaderField("ETag");
            etag4=etag;
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        // complete v2
        Map<String, String> partEtagMap2 = new HashMap<String, String>();
        partEtagMap2.put("1", etag3);
        partEtagMap2.put("2", etag4);
        String completeString2=OOSAPIPresignedUrlUtils.createCompleteMultipartUploadBody(partEtagMap2);
        String completev2url=OOSAPIPresignedUrlUtils.Object_CompleteMultipartUpload_V2_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName3,uploadId2, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn14=creatConn(completev2url, "POST", CreateHeaders(headers));
        try {
            OutputStream wr = conn14.getOutputStream();
            wr.write(completeString2.getBytes());
            wr.flush();
            wr.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        Pair<Integer, String> completev2result=OOSAPITestUtils.GetResult(conn14);
        assertEquals(200, completev2result.first().intValue());
        
        // initial upload v4
        String initialobjectv4url3=OOSAPIPresignedUrlUtils.Object_InitialMultipartUpload_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName4,CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn15=creatConn(initialobjectv4url3, "POST", CreateHeaders(headers));
        Pair<Integer, String> initialobjectv4result3=OOSAPITestUtils.GetResult(conn15);
        assertEquals(200, initialobjectv4result3.first().intValue());
        String uploadId3=OOSAPITestUtils.getMultipartUploadId(initialobjectv4result3.second());
        
        // upload v4
        String uploadobjectv4url5=OOSAPIPresignedUrlUtils.Object_UploadPart_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName4,uploadId3, 1, partContent1, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn16=creatConn(uploadobjectv4url5, "PUT", CreateHeaders(headers));
        try {
            
            OutputStream wr = conn16.getOutputStream();
            wr.write(partContent1.getBytes());
            wr.flush();
            wr.close();
            
            conn16.connect();
            
            int code = conn16.getResponseCode();
            assertEquals(200, code);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        String uploadobjectv4url6=OOSAPIPresignedUrlUtils.Object_UploadPart_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName4,uploadId3, 2, partContent2, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn17=creatConn(uploadobjectv4url6, "PUT", CreateHeaders(headers));
        try {
            
            OutputStream wr = conn17.getOutputStream();
            wr.write(partContent2.getBytes());
            wr.flush();
            wr.close();
            
            conn17.connect();
            
            int code = conn17.getResponseCode();
            assertEquals(200, code);
            
        } catch (Exception e) {
            e.printStackTrace();
        }

        // abort v4
        String abortv4url=OOSAPIPresignedUrlUtils.Object_AboutMultipartUpload_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName4,uploadId3, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn18=creatConn(abortv4url, "DELETE", CreateHeaders(headers));
        Pair<Integer, String> abortv4result=OOSAPITestUtils.GetResult(conn18);
        assertEquals(204, abortv4result.first().intValue());
        
        // deletemuli v2
        String delbodyString=OOSAPIPresignedUrlUtils.createDeleteMulitBody(Arrays.asList(objectName2,objectName3,objectName4), false);
        
        HashMap<String, String> mulidelheaders=CreateHeaders(headers);
        mulidelheaders.put("content-type", "application/x-www-form-urlencoded");
        mulidelheaders.put("Content-MD5", OOSAPIPresignedUrlUtils.getMD5(delbodyString));
        mulidelheaders.put("Content-Length",String.valueOf(delbodyString.length()));
        String deletemuliv2url=OOSAPIPresignedUrlUtils.Object_DeleteMulit_V2_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName,delbodyString, mulidelheaders, CreateHeaders(querys));
         
        HttpURLConnection conn19=creatConn(deletemuliv2url, "POST", mulidelheaders);
        try {
            OutputStream wr = conn19.getOutputStream();
            wr.write(delbodyString.getBytes());
            wr.flush();
            wr.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        Pair<Integer, String> deletemuliv2result=OOSAPITestUtils.GetResult(conn19);
        assertEquals(200, deletemuliv2result.first().intValue());
    }
    
    public static void OOS_PreSignAllDeny(String rootAk,String rootSk,String accessKey,String secretKey,String bucketName,List<String> headers,List<String> querys) {
        String objectName="object1.txt";
        String objectName2="mulit1.txt";
        String objectName3="mulit2.txt";
        String objectName4="mulit3.txt";
        String objectContent="first";
        
        String putobjectv4url=OOSAPIPresignedUrlUtils.Object_Put_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName, objectContent, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn=creatConn(putobjectv4url, "PUT", CreateHeaders(headers));
        try {
            OutputStream wr = conn.getOutputStream();
            wr.write(objectContent.getBytes());
            wr.flush();
            wr.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        Pair<Integer, String> putobjectv4result=OOSAPITestUtils.GetResult(conn);
        assertEquals(403, putobjectv4result.first().intValue());
        
        String putobjectv4urlroot=OOSAPIPresignedUrlUtils.Object_Put_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, rootAk, rootSk, bucketName, objectName, objectContent, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection connroot=creatConn(putobjectv4urlroot, "PUT", CreateHeaders(headers));
        try {
            OutputStream wr = connroot.getOutputStream();
            wr.write(objectContent.getBytes());
            wr.flush();
            wr.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        Pair<Integer, String> putobjectv4resultroot=OOSAPITestUtils.GetResult(connroot);
        assertEquals(200, putobjectv4resultroot.first().intValue());
        
        // get head v4
        String getobjectv4url=OOSAPIPresignedUrlUtils.Object_Get_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName,CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn1=creatConn(getobjectv4url, "GET", CreateHeaders(headers));
        Pair<Integer, String> getobjectv4result=OOSAPITestUtils.GetResult(conn1);
        assertEquals(403, getobjectv4result.first().intValue());
        
        String headobjectv4url=OOSAPIPresignedUrlUtils.Object_Head_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName,CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn2=creatConn(headobjectv4url, "HEAD", CreateHeaders(headers));
        try {
            conn2.connect();
            int code = conn2.getResponseCode();
            assertEquals(403, code);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // get v2
        String getobjectv2url=OOSAPIPresignedUrlUtils.Object_get_V2_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName,CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn3=creatConn(getobjectv2url, "GET", CreateHeaders(headers));
        Pair<Integer, String> getobjectv2result=OOSAPITestUtils.GetResult(conn3);
        assertEquals(403, getobjectv2result.first().intValue());
        
        // delete v4
        String delobjectv4url=OOSAPIPresignedUrlUtils.Object_Delete_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName,CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn4=creatConn(delobjectv4url, "DELETE", CreateHeaders(headers));
        Pair<Integer, String> delobjectv4result=OOSAPITestUtils.GetResult(conn4);
        assertEquals(403, delobjectv4result.first().intValue());
        
//         initial v4
        String initialobjectv4url=OOSAPIPresignedUrlUtils.Object_InitialMultipartUpload_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName2,CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn5=creatConn(initialobjectv4url, "POST", CreateHeaders(headers));
        Pair<Integer, String> initialobjectv4result=OOSAPITestUtils.GetResult(conn5);
        assertEquals(403, initialobjectv4result.first().intValue());
       
        
        String initialobjectv4urlroot=OOSAPIPresignedUrlUtils.Object_InitialMultipartUpload_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, rootAk, rootSk, bucketName, objectName2,CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn5root=creatConn(initialobjectv4urlroot, "POST", CreateHeaders(headers));
        Pair<Integer, String> initialobjectv4resultroot=OOSAPITestUtils.GetResult(conn5root);
        assertEquals(200, initialobjectv4resultroot.first().intValue());
        String uploadId1=OOSAPITestUtils.getMultipartUploadId(initialobjectv4resultroot.second());
        
        // upload v4
        String partContent1="123";
        String partContent2="456";
        String etag1="";
        String etag2="";
        String uploadobjectv4url1=OOSAPIPresignedUrlUtils.Object_UploadPart_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName2,uploadId1, 1, partContent1, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn6=creatConn(uploadobjectv4url1, "PUT", CreateHeaders(headers));
        try {
            
            OutputStream wr = conn6.getOutputStream();
            wr.write(partContent1.getBytes());
            wr.flush();
            wr.close();
            
            conn6.connect();
            
            int code = conn6.getResponseCode();
            assertEquals(403, code);

            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        String uploadobjectv4url2=OOSAPIPresignedUrlUtils.Object_UploadPart_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName2,uploadId1, 2, partContent2, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn7=creatConn(uploadobjectv4url2, "PUT", CreateHeaders(headers));
        try {
            
            OutputStream wr = conn7.getOutputStream();
            wr.write(partContent2.getBytes());
            wr.flush();
            wr.close();
            
            conn7.connect();
            
            int code = conn7.getResponseCode();
            assertEquals(403, code);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        String uploadobjectv4url1root=OOSAPIPresignedUrlUtils.Object_UploadPart_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, rootAk, rootSk, bucketName, objectName2,uploadId1, 1, partContent1, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn6root=creatConn(uploadobjectv4url1root, "PUT", CreateHeaders(headers));
        try {
            
            OutputStream wr = conn6root.getOutputStream();
            wr.write(partContent1.getBytes());
            wr.flush();
            wr.close();
            
            conn6root.connect();
            
            int code = conn6root.getResponseCode();
            assertEquals(200, code);
            String etag = conn6root.getHeaderField("ETag");
            etag1=etag;
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        String uploadobjectv4url2root=OOSAPIPresignedUrlUtils.Object_UploadPart_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, rootAk, rootSk, bucketName, objectName2,uploadId1, 2, partContent2, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn7root=creatConn(uploadobjectv4url2root, "PUT", CreateHeaders(headers));
        try {
            
            OutputStream wr = conn7root.getOutputStream();
            wr.write(partContent2.getBytes());
            wr.flush();
            wr.close();
            
            conn7root.connect();
            
            int code = conn7root.getResponseCode();
            assertEquals(200, code);
            String etag = conn7root.getHeaderField("ETag");
            etag2=etag;
            
        } catch (Exception e) {
            e.printStackTrace();
        }

        // list part v4 v2
        String listpartv4url=OOSAPIPresignedUrlUtils.Object_ListPart_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName2,uploadId1, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn8=creatConn(listpartv4url, "GET", CreateHeaders(headers));
        Pair<Integer, String> listpartv4result=OOSAPITestUtils.GetResult(conn8);
        assertEquals(403, listpartv4result.first().intValue());
        
        String listpartv2url=OOSAPIPresignedUrlUtils.Object_ListPart_V2_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName2,uploadId1, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn9=creatConn(listpartv2url, "GET", CreateHeaders(headers));
        Pair<Integer, String> listpartv2result=OOSAPITestUtils.GetResult(conn9);
        assertEquals(403, listpartv2result.first().intValue());
        
        // complete v4
       
        Map<String, String> partEtagMap = new HashMap<String, String>();
        partEtagMap.put("1", etag1);
        partEtagMap.put("2", etag2);
        String completeString=OOSAPIPresignedUrlUtils.createCompleteMultipartUploadBody(partEtagMap);
        System.out.println("completeString="+completeString);
        String completev4url=OOSAPIPresignedUrlUtils.Object_CompleteMultipartUpload_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName2,uploadId1, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn10=creatConn(completev4url, "POST", CreateHeaders(headers));
        try {
            OutputStream wr = conn10.getOutputStream();
            wr.write(completeString.getBytes());
            wr.flush();
            wr.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        Pair<Integer, String> completev4result=OOSAPITestUtils.GetResult(conn10);
        assertEquals(403, completev4result.first().intValue());

        
        // complete v2
        Map<String, String> partEtagMap2 = new HashMap<String, String>();
        partEtagMap2.put("1", etag1);
        partEtagMap2.put("2", etag2);
        String completeString2=OOSAPIPresignedUrlUtils.createCompleteMultipartUploadBody(partEtagMap2);
        String completev2url=OOSAPIPresignedUrlUtils.Object_CompleteMultipartUpload_V2_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName3,uploadId1, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn14=creatConn(completev2url, "POST", CreateHeaders(headers));
        try {
            OutputStream wr = conn14.getOutputStream();
            wr.write(completeString2.getBytes());
            wr.flush();
            wr.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        Pair<Integer, String> completev2result=OOSAPITestUtils.GetResult(conn14);
        assertEquals(403, completev2result.first().intValue());
        
        
        // abort v4
        String abortv4url=OOSAPIPresignedUrlUtils.Object_AboutMultipartUpload_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName4,uploadId1, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn18=creatConn(abortv4url, "DELETE", CreateHeaders(headers));
        Pair<Integer, String> abortv4result=OOSAPITestUtils.GetResult(conn18);
        assertEquals(403, abortv4result.first().intValue());
        
        // deletemuli v2
        String delbodyString=OOSAPIPresignedUrlUtils.createDeleteMulitBody(Arrays.asList(objectName,objectName2), false);
        
        HashMap<String, String> mulidelheaders=CreateHeaders(headers);
        mulidelheaders.put("content-type", "application/x-www-form-urlencoded");
        mulidelheaders.put("Content-MD5", OOSAPIPresignedUrlUtils.getMD5(delbodyString));
        mulidelheaders.put("Content-Length",String.valueOf(delbodyString.length()));
        
//        String deletemuliv2url=OOSAPIPresignedUrlUtils.Object_DeleteMulit_V2_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName,delbodyString, mulidelheaders, CreateHeaders(querys));
//         
//        HttpURLConnection conn19=creatConn(deletemuliv2url, "POST", mulidelheaders);
//        try {
//            OutputStream wr = conn19.getOutputStream();
//            wr.write(delbodyString.getBytes());
//            wr.flush();
//            wr.close();
//            
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//        
//        Pair<Integer, String> deletemuliv2result=OOSAPITestUtils.GetResult(conn19);
//        assertEquals(403, deletemuliv2result.first().intValue());
        
        String deletemuliv2urlroot=OOSAPIPresignedUrlUtils.Object_DeleteMulit_V2_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, rootAk, rootSk, bucketName,delbodyString, mulidelheaders, CreateHeaders(querys));
        
        HttpURLConnection conn19root=creatConn(deletemuliv2urlroot, "POST", mulidelheaders);
        try {
            OutputStream wr = conn19root.getOutputStream();
            wr.write(delbodyString.getBytes());
            wr.flush();
            wr.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        Pair<Integer, String> deletemuliv2resultroot=OOSAPITestUtils.GetResult(conn19root);
        assertEquals(200, deletemuliv2resultroot.first().intValue());
    }
    
    public static void CloudTrail_APIReadOnly(String rootak,String rootsk,String accessKey,String secretKey, String trailName,String bucketName,boolean isTarget, int code) {

        Pair<Integer, String> createtrail=CloudTrailAPITestUtils.CreateTrail(OOS_CLOUDTRAIL_DOMAIN , regionName, rootak, rootsk, trailName, bucketName, isTarget, null);
        assertEquals(200, createtrail.first().intValue());
        System.out.println(createtrail.second());
        
        Pair<Integer, String> describeTrails=CloudTrailAPITestUtils.DescribeTrails(OOS_CLOUDTRAIL_DOMAIN , regionName, accessKey, secretKey, Arrays.asList(trailName), isTarget, null);
        assertEquals(code, describeTrails.first().intValue());
        System.out.println(describeTrails.second());
        
        Pair<Integer, String> getEventSelectors=CloudTrailAPITestUtils.GetEventSelectors(OOS_CLOUDTRAIL_DOMAIN , regionName, accessKey, secretKey, trailName, isTarget, null);
        assertEquals(code, getEventSelectors.first().intValue());
        System.out.println(getEventSelectors.second());
        
        Pair<Integer, String> getTrailStatus=CloudTrailAPITestUtils.GetTrailStatus(OOS_CLOUDTRAIL_DOMAIN , regionName, accessKey, secretKey, trailName, isTarget, null);
        assertEquals(code, getTrailStatus.first().intValue());
        System.out.println(getTrailStatus.second());
        
        Pair<Integer, String> lookupEvents=CloudTrailAPITestUtils.LookupEvents(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey,"EventSource","oos-cn-cloudtrail.ctyunapi.cn", isTarget, null);
        assertEquals(code, lookupEvents.first().intValue());
        System.out.println(lookupEvents.second());
        
        Pair<Integer, String> deleteTrail=CloudTrailAPITestUtils.DeleteTrail(OOS_CLOUDTRAIL_DOMAIN , regionName, rootak, rootsk, trailName, isTarget, null);
        assertEquals(200, deleteTrail.first().intValue());
        System.out.println(deleteTrail.second());
    }
    
    
    
    public static void CloudTrail_APIALLAllow(String accessKey,String secretKey, String trailName,String bucketName,boolean isTarget,List<String> headers) {
        
        Pair<Integer, String> createtrail=CloudTrailAPITestUtils.CreateTrail(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, bucketName, isTarget, CreateHeaders(headers));
        assertEquals(200, createtrail.first().intValue());
        System.out.println(createtrail.second());
        
        Pair<Integer, String> describeTrails=CloudTrailAPITestUtils.DescribeTrails(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, Arrays.asList(trailName), isTarget, CreateHeaders(headers));
        assertEquals(200, describeTrails.first().intValue());
        System.out.println(describeTrails.second());
        
        Pair<Integer, String> updateTrail=CloudTrailAPITestUtils.UpdateTrail(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, bucketName, null, isTarget, CreateHeaders(headers));
        assertEquals(200, updateTrail.first().intValue());
        System.out.println(updateTrail.second());
        
        Pair<Integer, String> putEventSelectors=CloudTrailAPITestUtils.PutEventSelectors(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, "All", isTarget, CreateHeaders(headers));
        assertEquals(200, putEventSelectors.first().intValue());
        System.out.println(putEventSelectors.second());
        
        Pair<Integer, String> getEventSelectors=CloudTrailAPITestUtils.GetEventSelectors(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, isTarget, CreateHeaders(headers));
        assertEquals(200, getEventSelectors.first().intValue());
        System.out.println(getEventSelectors.second());

        Pair<Integer, String> startLogging=CloudTrailAPITestUtils.StartLogging(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, isTarget, CreateHeaders(headers));
        assertEquals(200, startLogging.first().intValue());
        System.out.println(startLogging.second());
        
        Pair<Integer, String> getTrailStatus=CloudTrailAPITestUtils.GetTrailStatus(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, isTarget, CreateHeaders(headers));
        assertEquals(200, getTrailStatus.first().intValue());
        System.out.println(getTrailStatus.second());
        
        Pair<Integer, String> stopLogging=CloudTrailAPITestUtils.StopLogging(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, isTarget, CreateHeaders(headers));
        assertEquals(200, stopLogging.first().intValue());
        System.out.println(stopLogging.second());
        
        Pair<Integer, String> lookupEvents=CloudTrailAPITestUtils.LookupEvents(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey,"EventSource","oos-cn-cloudtrail.ctyunapi.cn", isTarget, CreateHeaders(headers));
        assertEquals(200, lookupEvents.first().intValue());
        System.out.println(lookupEvents.second());
        
        Pair<Integer, String> deleteTrail=CloudTrailAPITestUtils.DeleteTrail(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, isTarget, CreateHeaders(headers));
        assertEquals(200, deleteTrail.first().intValue());
        System.out.println(deleteTrail.second());
    }
    
    public static void CloudTrail_APIALLDeny(String rootak,String rootsk,String accessKey,String secretKey, String trailName,String bucketName,boolean isTarget) {
        
        Pair<Integer, String> createtrail=CloudTrailAPITestUtils.CreateTrail(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, bucketName, isTarget, null);
        assertEquals(403, createtrail.first().intValue());
        System.out.println(createtrail.second());
        
        Pair<Integer, String> createtrail2=CloudTrailAPITestUtils.CreateTrail(OOS_CLOUDTRAIL_DOMAIN, regionName, rootak, rootsk, trailName, bucketName, isTarget, null);
        assertEquals(200, createtrail2.first().intValue());
        System.out.println(createtrail2.second());
        
        Pair<Integer, String> describeTrails=CloudTrailAPITestUtils.DescribeTrails(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, Arrays.asList(trailName), isTarget, null);
        assertEquals(403, describeTrails.first().intValue());
        System.out.println(describeTrails.second());
        
        Pair<Integer, String> updateTrail=CloudTrailAPITestUtils.UpdateTrail(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, bucketName, null, isTarget, null);
        assertEquals(403, updateTrail.first().intValue());
        System.out.println(updateTrail.second());
        
        Pair<Integer, String> putEventSelectors=CloudTrailAPITestUtils.PutEventSelectors(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, "All", isTarget, null);
        assertEquals(403, putEventSelectors.first().intValue());
        System.out.println(putEventSelectors.second());
        
        Pair<Integer, String> getEventSelectors=CloudTrailAPITestUtils.GetEventSelectors(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, isTarget, null);
        assertEquals(403, getEventSelectors.first().intValue());
        System.out.println(getEventSelectors.second());

        Pair<Integer, String> startLogging=CloudTrailAPITestUtils.StartLogging(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, isTarget, null);
        assertEquals(403, startLogging.first().intValue());
        System.out.println(startLogging.second());
        
        Pair<Integer, String> getTrailStatus=CloudTrailAPITestUtils.GetTrailStatus(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, isTarget, null);
        assertEquals(403, getTrailStatus.first().intValue());
        System.out.println(getTrailStatus.second());
        
        Pair<Integer, String> stopLogging=CloudTrailAPITestUtils.StopLogging(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, isTarget, null);
        assertEquals(403, stopLogging.first().intValue());
        System.out.println(stopLogging.second());
        
        Pair<Integer, String> lookupEvents=CloudTrailAPITestUtils.LookupEvents(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey,"EventSource","oos-cn-cloudtrail.ctyunapi.cn", isTarget, null);
        assertEquals(403, lookupEvents.first().intValue());
        System.out.println(lookupEvents.second());
        
        Pair<Integer, String> deleteTrail=CloudTrailAPITestUtils.DeleteTrail(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, isTarget, null);
        assertEquals(403, deleteTrail.first().intValue());
        System.out.println(deleteTrail.second());
        
        Pair<Integer, String> deleteTrail2=CloudTrailAPITestUtils.DeleteTrail(OOS_CLOUDTRAIL_DOMAIN, regionName, rootak, rootsk, trailName, isTarget, null);
        assertEquals(200, deleteTrail2.first().intValue());
        System.out.println(deleteTrail2.second());
    }
    
    public static void Management_APIALL(String ak,String sk,List<String> headers,int code) {

        String regionNamemg=regionName+"-mg";
        String today = TimeUtils.toYYYY_MM_dd(new Date());
        String dateRegion1=TestEndpointConst.dataRegion1;
        
        Pair<Integer, String> getUsage=ManagementAPITestUtils.GetUsage(httpOrHttps, managementAPIhost, managementAPIport, signVersion, regionNamemg,ak, sk, today, today, null, "byDay", CreateHeaders(headers));
        assertEquals(code, getUsage.first().intValue());
        
        Pair<Integer, String> getAvailBW=ManagementAPITestUtils.GetAvailBW(httpOrHttps, managementAPIhost, managementAPIport, signVersion, regionNamemg,ak, sk, today+"-00-05", today+"-08-05", dateRegion1, CreateHeaders(headers));
        assertEquals(code, getAvailBW.first().intValue());
        
        Pair<Integer, String> getBandwidth=ManagementAPITestUtils.GetBandwidth(httpOrHttps, managementAPIhost, managementAPIport, signVersion, regionNamemg,ak, sk, today+"-00-05", today+"-00-10", null, CreateHeaders(headers));
        assertEquals(code, getBandwidth.first().intValue());
        
        Pair<Integer, String> getConnection=ManagementAPITestUtils.GetConnection(httpOrHttps, managementAPIhost, managementAPIport, signVersion, regionNamemg,ak, sk, today+"-00-05", today+"-00-10", null, CreateHeaders(headers));
        assertEquals(code, getConnection.first().intValue());
        
        Pair<Integer, String> getCapacity=ManagementAPITestUtils.GetCapacity(httpOrHttps, managementAPIhost, managementAPIport, signVersion,regionNamemg, ak, sk, today, today, null, "byHour", dateRegion1, CreateHeaders(headers));
        assertEquals(code, getCapacity.first().intValue());
        
        Pair<Integer, String> getDeleteCapacity=ManagementAPITestUtils.GetDeleteCapacity(httpOrHttps, managementAPIhost, managementAPIport, signVersion, regionNamemg,ak, sk, today, today, null, "byDay", dateRegion1, CreateHeaders(headers));
        assertEquals(code, getDeleteCapacity.first().intValue());
        
        Pair<Integer, String> getTraffics=ManagementAPITestUtils.GetTraffics(httpOrHttps, managementAPIhost, managementAPIport, signVersion, regionNamemg,ak, sk,today, today, null, "by5min", dateRegion1, "all", "internet", "direct", CreateHeaders(headers));
        assertEquals(code, getTraffics.first().intValue());
        
        Pair<Integer, String> getAvailableBandwidth=ManagementAPITestUtils.GetAvailableBandwidth(httpOrHttps, managementAPIhost, managementAPIport, signVersion, regionNamemg,ak, sk,today, today, "by5min", dateRegion1, "inbound", "noninternet", CreateHeaders(headers));
        assertEquals(code, getAvailableBandwidth.first().intValue());
        
        Pair<Integer, String> getRequests=ManagementAPITestUtils.GetRequests(httpOrHttps, managementAPIhost, managementAPIport, signVersion, regionNamemg,ak, sk,today, today, null, "byDay", dateRegion1, "all", "put", CreateHeaders(headers));
        assertEquals(code, getRequests.first().intValue());
        
        Pair<Integer, String> getReturnCode=ManagementAPITestUtils.GetReturnCode(httpOrHttps, managementAPIhost, managementAPIport, signVersion, regionNamemg,ak, sk,today, today, null, "byDay", dateRegion1, "all", "get", "Response500", CreateHeaders(headers));
        assertEquals(code, getReturnCode.first().intValue());
        
        Pair<Integer, String> getConcurrentConnection=ManagementAPITestUtils.GetConcurrentConnection(httpOrHttps, managementAPIhost, managementAPIport, signVersion, regionNamemg,ak, sk,today, today, null, "by5min", dateRegion1, "all", CreateHeaders(headers));
        assertEquals(code, getConcurrentConnection.first().intValue());
    }

    private static HashMap<String, String> CreateHeaders(List<String> propertys) {
        HashMap<String, String> headers = new HashMap<String, String>();
        if (propertys!=null&&propertys.size()%2==0) {
            int i=0;
            while (i<propertys.size()) {
                headers.put(propertys.get(i), propertys.get(i+1));
                i+=2;
                
            }
        }
        return headers;
    }
    
    public static String getCreateAccessKey(String xml) {
        try {
            StringReader sr = new StringReader(xml);
            InputSource is = new InputSource(sr);
            Document doc = (new SAXBuilder()).build(is);
            Element root = doc.getRootElement();
            
            Element createAKResultElement=root.getChild("CreateAccessKeyResult");
            Element AkElement=createAKResultElement.getChild("AccessKey");
            String ak=AkElement.getChild("AccessKeyId").getValue();
            System.out.println(ak);
            System.out.println(AkElement.getChild("SecretAccessKey").getValue());
            System.out.println(AkElement.getChild("CreateDate").getValue());
            
            return ak;
            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        }
        
        public static Pair<String, String> getcreateVirtualMFADevice(String xml) {
            try {
                StringReader sr = new StringReader(xml);
                InputSource is = new InputSource(sr);
                Document doc = (new SAXBuilder()).build(is);
                Element root = doc.getRootElement();
                
                Element resultElement=root.getChild("CreateVirtualMFADeviceResult");
                Element virtualMFADevice=resultElement.getChild("VirtualMFADevice");
                String SerialNumber=virtualMFADevice.getChild("SerialNumber").getValue();
                String Base32StringSeed=virtualMFADevice.getChild("Base32StringSeed").getValue();
                String QRCodePNG=virtualMFADevice.getChild("QRCodePNG").getValue();
                System.out.println("QRCodePNG="+QRCodePNG);
                Pair<String, String> pair = new Pair<String, String>();
                pair.first(SerialNumber);
                pair.second(Base32StringSeed);
                return pair;
            } catch (Exception e) {
                e.printStackTrace();
            }
            
            return null;
        }
        
        public static Pair<String, String> CreateIdentifyingCode(String secret) {
            Pair<String, String> codePair = new Pair<String, String>();
            int WINDOW_SIZE = 3;
            Base32 codec = new Base32();
            byte[] decodedKey = codec.decode(secret);
            long t = System.currentTimeMillis() / 1000L / 30L;
            for (int i = -WINDOW_SIZE; i <= WINDOW_SIZE; ++i) {
                long hash1 = generateCode(decodedKey, t + i);
                long hash2 = generateCode(decodedKey, t + i + 1);
                String code1=String.valueOf(hash1);
                String code2=String.valueOf(hash2);
                if (code1.length()<6) {
                    String prefix="";
                    for (int j = 0; j < 6-code1.length(); j++) {
                        prefix+="0";
                    }
                    code1=prefix+code1;
                }
                if (code2.length()<6) {
                    String prefix="";
                    for (int j = 0; j < 6-code2.length(); j++) {
                        prefix+="0";
                    }
                    code2=prefix+code2;
                }
                codePair.first(code1);
                codePair.second(code2);
            }
            return codePair;
        }
        
         private static int generateCode(byte[] key, long t)  {
                byte[] data = new byte[8];
                long value = t;
                for (int i = 8; i-- > 0; value >>>= 8) {
                    data[i] = (byte) value;
                }
                SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
                Mac mac;
                try {
                    mac = Mac.getInstance("HmacSHA1");
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
                try {
                    mac.init(signKey);
                } catch (InvalidKeyException e) {
                    throw new RuntimeException(e);
                }
                byte[] hash = mac.doFinal(data);
                int offset = hash[20 - 1] & 0xF;
                // We're using a long because Java hasn't got unsigned int.
                long truncatedHash = 0;
                for (int i = 0; i < 4; ++i) {
                    truncatedHash <<= 8;
                    // We are dealing with signed bytes:
                    // we just keep the first byte.
                    truncatedHash |= (hash[offset + i] & 0xFF);
                }
                truncatedHash &= 0x7FFFFFFF;
                truncatedHash %= 1000000;
                return (int) truncatedHash;
            }
        
        public String longToUTC(long time) {
            SimpleDateFormat sf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
            sf.setTimeZone(TimeZone.getTimeZone("UTC"));
            String utctime=sf.format(time);
            return utctime;
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
//                    System.out.println("--------- Request headers ---------");
                    for (String headerKey : headers.keySet()) {
//                        System.out.println(headerKey + ": " + headers.get(headerKey));
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
}
