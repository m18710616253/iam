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

public class OOSCondtionKeyAccessTestDev {

    private static MetaClient metaClient = MetaClient.getGlobalClient();
    
    private static final OwnerMeta owner = new OwnerMeta("wangduo@ctyun.cn");
    private static final String accountId = owner.getAccountId();
    private static final String accessKey="ak-wangduo";
    private static final String secretKey="sk-wangduo";
    
    // 用户名
    String policyName = "policyaa112w23423";
    String userName = "test1234aas12w3ee1";
    String userName1 = "testAAAuser1";
    
    AccessKeyResult accessKeyResult;
    AccessKeyResult accessKeyResult1;
    
    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        
      IAMTestUtils.TrancateTable("iam-user");
      IAMTestUtils.TrancateTable("iam-group");
      IAMTestUtils.TrancateTable("iam-policy");
      //IAMTestUtils.TrancateTable("iam-accountSummary");
        
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
        
        
        body = "Action=CreateUser&Version=2010-05-08&UserName=" + userName1;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        
        // 给用户创建一个ak
        body="Action=CreateAccessKey&UserName=" + userName1;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        accessKeyResult1 = AccessKeyResultUtilsDev.convertToAccessKeyResult(resultPair.second());
    }
    
    @After
    public void after() {
        
//        String body;
//        Pair<Integer, String> resultPair;
//        
//        // 删除AK
//        body="Action=DeleteAccessKey&AccessKeyId=" + accessKeyResult.accessKeyId + "&UserName=" + userName;
//        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
//        assertEquals(200, resultPair.first().intValue());
//        // 删除用户
//        body = "Action=DeleteUser&Version=2010-05-08&UserName=" + userName ;
//        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
//        assertEquals(200, resultPair.first().intValue());
    }
    
    @Test
    public void testPutBucket() throws Exception{

        URL url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN + "test-bucket1");
        HttpURLConnection connection = OOSTestUtilsDev.invokeHttpsRequest(url, "PUT", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        connection.connect();
        assertEquals(403, connection.getResponseCode());
        System.out.println(IOUtils.toString(connection.getErrorStream()));
        
        
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
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
    public void testListBucketPrefix() throws Exception{

        URL url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN + "test-bucket1/?prefix=" + userName + "/");
        HttpURLConnection connection = OOSTestUtilsDev.invokeHttpsRequest(url, "GET", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        connection.connect();
        assertEquals(403, connection.getResponseCode());
        System.out.println(IOUtils.toString(connection.getErrorStream()));
        
        
        String policyString="{\r\n" + 
                "\"Version\": \"2012-10-17\",\r\n" + 
                "\"Statement\": [\r\n" + 
                "{\r\n" + 
                "\"Action\": [\"oos:ListBucket\"],\r\n" + 
                "\"Effect\": \"Allow\",\r\n" + 
                "\"Resource\": [\"arn:ctyun:oos::" + accountId + ":test-bucket1\"],\r\n" + 
                "\"Condition\": {\"StringLike\": {\"oos:prefix\": [\"${ctyun:username}/*\"]}}\r\n" + 
                "}\r\n" + 
                "]\r\n" + 
                "}";
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
    public void testListBucketPrefixTwoUser() throws Exception{

        URL url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN + "test-bucket1/?prefix=" + userName + "/");
        HttpURLConnection connection = OOSTestUtilsDev.invokeHttpsRequest(url, "GET", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        connection.connect();
        assertEquals(403, connection.getResponseCode());
        System.out.println(IOUtils.toString(connection.getErrorStream()));
        
        
        String policyString="{\r\n" + 
                "\"Version\": \"2012-10-17\",\r\n" + 
                "\"Statement\": [\r\n" + 
                "{\r\n" + 
                "\"Action\": [\"oos:ListBucket\"],\r\n" + 
                "\"Effect\": \"Allow\",\r\n" + 
                "\"Resource\": [\"arn:ctyun:oos::" + accountId + ":test-bucket1\"],\r\n" + 
                "\"Condition\": {\"StringLike\": {\"oos:prefix\": [\"${ctyun:username}/*\"]}}\r\n" + 
                "}\r\n" + 
                "]\r\n" + 
                "}";
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
        
        sleep(2000);
        
        connection = OOSTestUtilsDev.invokeHttpsRequest(url, "GET", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        connection.connect();
        assertEquals(200, connection.getResponseCode());
        System.out.println(IOUtils.toString(connection.getInputStream()));
        
        // user 访问 user1 拒绝
        url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN + "test-bucket1/?prefix=" + userName1 + "/");
        connection = OOSTestUtilsDev.invokeHttpsRequest(url, "GET", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        connection.connect();
        assertEquals(403, connection.getResponseCode());
        System.out.println(IOUtils.toString(connection.getErrorStream()));
        
        // user1 访问 user1 拒绝
        url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN + "test-bucket1/?prefix=" + userName1 + "/");
        connection = OOSTestUtilsDev.invokeHttpsRequest(url, "GET", accessKeyResult1.accessKeyId, accessKeyResult1.secretAccessKey);
        connection.connect();
        assertEquals(403, connection.getResponseCode());
        System.out.println(IOUtils.toString(connection.getErrorStream()));
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        sleep(2000);
        
        // user1 访问 user1 允许
        url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN + "test-bucket1/?prefix=" + userName1 + "/");
        connection = OOSTestUtilsDev.invokeHttpsRequest(url, "GET", accessKeyResult1.accessKeyId, accessKeyResult1.secretAccessKey);
        connection.connect();
        assertEquals(200, connection.getResponseCode());
        System.out.println(IOUtils.toString(connection.getInputStream()));
    }
    
    
    public void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
