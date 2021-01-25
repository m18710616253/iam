package cn.ctyun.oos.accesscontroller;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.io.IOUtils;
import org.jdom.JDOMException;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.AccessKeyResultUtilsDev;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.server.result.AccessKeyResult;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.iam.test.iamaccesscontrol.IAMInterfaceTestUtils;
import cn.ctyun.oos.iam.test.oosaccesscontrol.OOSInterfaceTestUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;
import common.tuple.Pair;

public class OOSAccessTestDev {

    private static MetaClient metaClient = MetaClient.getGlobalClient();
    
    private static final OwnerMeta owner = new OwnerMeta("wangduo@ctyun.cn");
    private static final String accountId = owner.getAccountId();
    private static final String accessKey="ak-wangduo";
    private static final String secretKey="sk-wangduo";
    
    // 用户名
    String policyName = "policyaa112w23423";
    String userName = "test1234aas12w3ee1";
    
    AccessKeyResult accessKeyResult;
    
    
    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        
      IAMTestUtils.TrancateTable("iam-user");
      IAMTestUtils.TrancateTable("iam-group");
      IAMTestUtils.TrancateTable("iam-policy");
        
        // 创建owner
        owner.verify = null;
        owner.currentAKNum = 0;
        owner.maxAKNum = 2;
        metaClient.ownerInsertForTest(owner);
        metaClient.ownerSelect(owner);
        
        AkSkMeta asKey = new AkSkMeta(owner.getId());
        asKey.accessKey = accessKey;
        asKey.setSecretKey(secretKey);
        asKey.status = 1;
        asKey.isPrimary = 1;
        metaClient.akskInsert(asKey);

    }
    
    @Before
    public void setUp() throws JDOMException, IOException {
        
        
        String body;
        Pair<Integer, String> resultPair;
        // 创建一个用户
        body = "Action=CreateUser&Version=2010-05-08&UserName=" + userName;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        
        // 给用户创建一个ak
        body="Action=CreateAccessKey&UserName=" + userName;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(resultPair.second());
    }
    
    @After
    public void after() {
        
        String body;
        Pair<Integer, String> resultPair;
        
        // 删除AK
        body="Action=DeleteAccessKey&AccessKeyId=" + accessKeyResult.accessKeyId + "&UserName=" + userName;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
        // 删除用户
        body = "Action=DeleteUser&Version=2010-05-08&UserName=" + userName ;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
    }
    
    @Test
    public void testGetService() throws Exception{
        
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListAllMyBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
        
        URL url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN);
        HttpURLConnection connection = OOSTestUtilsDev.invokeHttpsRequest(url, "GET", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        connection.connect();
        int code = connection.getResponseCode();
        assertEquals(200, code);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
        IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);

    }
    
    @Test
    public void testGetServiceHasNoPolicy() throws Exception{
        
        URL url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN);
        HttpURLConnection connection = OOSTestUtilsDev.invokeHttpsRequest(url, "GET", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        connection.connect();
        int code = connection.getResponseCode();
        assertEquals(403, code);

    }
    
    @Test
    public void testPutBucket() throws Exception{

        URL url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN + "test-bucket1");
        HttpURLConnection connection = OOSTestUtilsDev.invokeHttpsRequest(url, "PUT", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        connection.connect();
        assertEquals(403, connection.getResponseCode());
        System.out.println(IOUtils.toString(connection.getErrorStream()));
        
        
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:CreateBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
        
        connection = OOSTestUtilsDev.invokeHttpsRequest(url, "PUT", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        connection.connect();
        assertEquals(200, connection.getResponseCode());
        System.out.println(IOUtils.toString(connection.getInputStream()));
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
        IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
    }
    
    @Test
    public void testDeleteBucket() throws Exception{

        URL url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN + "test-bucket");
        HttpURLConnection connection = OOSTestUtilsDev.invokeHttpsRequest(url, "DELETE", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        connection.connect();
        assertEquals(403, connection.getResponseCode());
        System.out.println(IOUtils.toString(connection.getErrorStream()));
        
        
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:DeleteBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":test-bucket1"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
        
        connection = OOSTestUtilsDev.invokeHttpsRequest(url, "DELETE", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        connection.connect();
        assertEquals(403, connection.getResponseCode());
        System.out.println(IOUtils.toString(connection.getErrorStream()));
        
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:DeleteBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":test-bucket"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        connection = OOSTestUtilsDev.invokeHttpsRequest(url, "DELETE", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        connection.connect();
        assertEquals(200, connection.getResponseCode());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
        IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
    }
    
    @Test
    public void testGetBucket() throws Exception{

        URL url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN + "test-bucket");
        HttpURLConnection connection = OOSTestUtilsDev.invokeHttpsRequest(url, "GET", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        connection.connect();
        assertEquals(403, connection.getResponseCode());
        System.out.println(IOUtils.toString(connection.getErrorStream()));
        
        
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
        
        connection = OOSTestUtilsDev.invokeHttpsRequest(url, "GET", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        connection.connect();
        assertEquals(200, connection.getResponseCode());
        System.out.println(IOUtils.toString(connection.getInputStream()));
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
        IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
    }
    
    
    @Test
    public void testHeadBucket() throws Exception{

        URL url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN + "test-bucket2");
        HttpURLConnection connection = OOSTestUtilsDev.invokeHttpsRequest(url, "HEAD", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        connection.connect();
        assertEquals(404, connection.getResponseCode());
        System.out.println(IOUtils.toString(connection.getErrorStream()));
        
        
//        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
//        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
//        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
//        
//        connection = OOSTestUtilsDev.invokeHttpsRequest(url, "HEAD", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
//        connection.connect();
//        assertEquals(200, connection.getResponseCode());
//        System.out.println(IOUtils.toString(connection.getInputStream()));
//        
//        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
//        IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
    }
    
    @Test
    public void testPutBucketPolicy() throws Exception{
        URL url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN + "test-bucket1?policy");
        String policy = "{\"Version\": \"2012-10-17\",\"Id\": \"S3PolicyId3\",\"Statement\": [{\"Sid\": \"ipv4&6policy\",\"Effect\": \"Allow\",\"Principal\": {\"AWS\": \"*\"},\"Action\": \"s3:*\",\"Resource\": \"arn:aws:s3:::test-bucket1/*\"}]}";
        Map<String, String> query = new HashMap<String, String>();
        query.put("policy", "");
        HttpURLConnection connection = OOSTestUtilsDev.invokeHttpsRequest(url, "PUT", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey, query);
        connection.connect();
        OutputStream out = connection.getOutputStream();
        out.write(policy.getBytes());
        out.flush();
        assertEquals(403, connection.getResponseCode());
        System.out.println(IOUtils.toString(connection.getErrorStream()));
        
        
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucketPolicy"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
        
        connection = OOSTestUtilsDev.invokeHttpsRequest(url, "PUT", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey, query);
        connection.connect();
        out = connection.getOutputStream();
        out.write(policy.getBytes());
        out.flush();
        assertEquals(200, connection.getResponseCode());
        System.out.println(IOUtils.toString(connection.getInputStream()));
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
        IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
    }
    
    @Test
    public void testListMultipartUploads() throws Exception{
        URL url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN + "test-bucket1?uploads");
        Map<String, String> query = new HashMap<String, String>();
        query.put("uploads", "");
        HttpURLConnection connection = OOSTestUtilsDev.invokeHttpsRequest(url, "GET", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey, query);
        connection.connect();
        assertEquals(403, connection.getResponseCode());
        System.out.println(IOUtils.toString(connection.getErrorStream()));
        
        url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN + "test-bucket?uploads");
        connection = OOSTestUtilsDev.invokeHttpsRequest(url, "GET", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey, query);
        connection.connect();
        assertEquals(200, connection.getResponseCode());
        System.out.println(IOUtils.toString(connection.getInputStream()));
        
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":test-bucket1"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
        
        url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN + "test-bucket1?uploads");
        connection = OOSTestUtilsDev.invokeHttpsRequest(url, "GET", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey, query);
        connection.connect();
        assertEquals(200, connection.getResponseCode());
        System.out.println(IOUtils.toString(connection.getInputStream()));
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
        IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
    }
    
    
    @Test
    public void testPutObject() throws Exception{
        String objectName = "test-object";
        String objectContent = "hello world!12345!@#$%^&*()_+\":[]\\?>,.adsf中文繁體";
        URL url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN + "test-bucket1/" + URLEncoder.encode(objectName, "UTF-8"));
        
        HttpURLConnection connection = OOSTestUtilsDev.invokeHttpsRequest(url, "PUT", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        connection.connect();
        OutputStream wr = connection.getOutputStream();
        wr.write(objectContent.getBytes());
        wr.flush();
        wr.close();
        int code = connection.getResponseCode();
         IOUtils.toString(connection.getErrorStream());
        //assertEquals(403, code);
        
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":test-bucket/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
        
        connection = OOSTestUtilsDev.invokeHttpsRequest(url, "PUT", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        connection.connect();
        wr = connection.getOutputStream();
        wr.write(objectContent.getBytes());
        wr.flush();
        wr.close();
        connection.getResponseCode();
    }
    
    
    @Test
    public void test_BucketACLPublic() {
        String bucketName="yx-bucket-1";
        String objectName="publicbucket1.txt";
//        HashMap<String, String> params=new HashMap<String, String>();
//        params.put("x-amz-acl", "public-read-write");
//        OOSInterfaceTestUtils.Bucket_Put("http", "V4", 8080, accessKey, secretKey, bucketName, null, null, null, null, params);
        
//        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,"123", null);
//        assertEquals(200, putresult1.first().intValue());
//        
//        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Object_Get(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
//        assertEquals(200, getresult1.first().intValue());
//        
//        Pair<Integer, String> delresult1=OOSInterfaceTestUtils.Object_Delete(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
//        assertEquals(204, delresult1.first().intValue());
        
//        Pair<Integer, String> postresult1=OOSInterfaceTestUtils.Object_Post(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,"123", null);
//        assertEquals(204, postresult1.first().intValue());
//        
//        String objectName3="des.txt";
//        Pair<Integer, String> copyresult1=OOSInterfaceTestUtils.Object_Copy(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,objectName3,null);
//        assertEquals(200, copyresult1.first().intValue()); 
        
        Pair<Integer, String> uploadPartResult2=OOSInterfaceTestUtils.Object_CopyPart("http", "V4", 8080, accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey, bucketName, "1111" ,"1111",1,objectName,null);
        assertEquals(200, uploadPartResult2.first().intValue()); 
        
        
//        String objectName2="mulit";
//        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName2,null);
//        assertEquals(200, initresult1.first().intValue()); 
//        String uploadId=getMultipartUploadId(initresult1.second());
//        System.err.println("uploadId="+uploadId);
//        Map<String, String> partEtagMap = new HashMap<String, String>();
//        
//        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName2,uploadId,1,"uploadpart1",null);
//        assertEquals(200, uploadPartResult1.first().intValue()); 
//        partEtagMap.put("1", uploadPartResult1.second());
//        

//        
//        Pair<Integer, String> uploadPartResult2=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName2,uploadId,2,"uploadpart2",null);
//        assertEquals(200, uploadPartResult2.first().intValue()); 
//        partEtagMap.put("2", uploadPartResult2.second());
//        
//        Pair<Integer, String> ListPartResult=OOSInterfaceTestUtils.Object_ListPart(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName2, uploadId,null);
//        assertEquals(200, ListPartResult.first().intValue());   
//        assertTrue(ListPartResult.second().contains("ListPartsResult"));
//         
//        Pair<Integer, String> completeResult=OOSInterfaceTestUtils.Object_CompleteMultipartUpload(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName2, uploadId, partEtagMap,null);
//        assertEquals(200, completeResult.first().intValue()); 
//        
//        int headresult1=OOSInterfaceTestUtils.Object_Head(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName2,null);
//        assertEquals(200, headresult1);
//        
//        
//        
//        Pair<Integer, String> aborteResult=OOSInterfaceTestUtils.object_AbortMultipartUpload(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName2, uploadId, null);
//        assertEquals(204, aborteResult.first().intValue());  
        
    }
}
