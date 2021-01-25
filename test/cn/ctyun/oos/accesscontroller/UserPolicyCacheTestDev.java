package cn.ctyun.oos.accesscontroller;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;

import org.eclipse.jetty.util.UrlEncoded;
import org.jdom.JDOMException;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.AccessKeyResultUtilsDev;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.server.entity.AccountSummary;
import cn.ctyun.oos.iam.server.entity.Policy;
import cn.ctyun.oos.iam.server.internal.api.OOSPolicyAPI;
import cn.ctyun.oos.iam.server.internal.api.OOSPolicyParam;
import cn.ctyun.oos.iam.server.result.AccessKeyResult;
import cn.ctyun.oos.iam.server.service.AccountSummaryService;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.iam.test.iamaccesscontrol.IAMInterfaceTestUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;
import common.tuple.Pair;

public class UserPolicyCacheTestDev {


    private static MetaClient metaClient = MetaClient.getGlobalClient();
    
    private static final OwnerMeta owner = new OwnerMeta("wangduo@ctyun.cn");
    private static final String accountId = owner.getAccountId();
    private static final String accessKey="ak-wangduo";
    private static final String secretKey="sk-wangduo";
    
    // 用户名
    String policyName = "policyAA112w23423";
    String userName = "testWWW34aas12w3ee1";
    String groupName = "Group111AA";
    
    AccessKeyResult accessKeyResult;
    
    
    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        
      IAMTestUtils.TrancateTable("iam-user");
      IAMTestUtils.TrancateTable("iam-group");
      IAMTestUtils.TrancateTable("iam-policy");
      IAMTestUtils.TrancateTable("iam-changeEvent");
        
      
      AccountSummary accountSummary = AccountSummaryService.getAccountSummary(accountId);
      accountSummary.usersQuota = Long.MAX_VALUE;
      accountSummary.groupsQuota = Long.MAX_VALUE;
      accountSummary.policiesQuota = Long.MAX_VALUE;;
      AccountSummaryService.putAccountQuota(accountSummary);
      
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
        
        // 创建一个组
        body = "Action=CreateGroup&Version=2010-05-08&GroupName=" + groupName;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        
        // 给用户创建一个ak
        body="Action=CreateAccessKey&UserName=" + userName;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(resultPair.second());
        
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListAllMyBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
    }
    
    
    @Test
    public void testAttachPolicy() throws Exception{
        
        URL url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN);
        HttpURLConnection connection = OOSTestUtilsDev.invokeHttpsRequest(url, "GET", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        connection.connect();
        int code = connection.getResponseCode();
        assertEquals(403, code);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
        
        Thread.sleep(2000);
        url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN);
        connection = OOSTestUtilsDev.invokeHttpsRequest(url, "GET", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        connection.connect();
        code = connection.getResponseCode();
        assertEquals(200, code);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
        IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);

    }
    
    
    @Test
    public void testAddToGroup() throws Exception{
        
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName, 200);
        
        Thread.sleep(2000);
        URL url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN);
        HttpURLConnection connection = OOSTestUtilsDev.invokeHttpsRequest(url, "GET", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        connection.connect();
        int code = connection.getResponseCode();
        assertEquals(403, code);
        
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
        
        Thread.sleep(2000);
        url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN);
        connection = OOSTestUtilsDev.invokeHttpsRequest(url, "GET", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        connection.connect();
        code = connection.getResponseCode();
        assertEquals(200, code);

    }
    
    @Test
    public void testAttachGroupPolicy() throws Exception{
        
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName, 200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
        
        Thread.sleep(2000);
        URL url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN);
        HttpURLConnection connection = OOSTestUtilsDev.invokeHttpsRequest(url, "GET", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        connection.connect();
        int code = connection.getResponseCode();
        assertEquals(200, code);
        
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:GetObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        Thread.sleep(2000);
        url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN);
        connection = OOSTestUtilsDev.invokeHttpsRequest(url, "GET", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        connection.connect();
        code = connection.getResponseCode();
        assertEquals(403, code);

    }
    
    @Test
    public void testAttachOOSPolicy() throws Exception{
        
        URL url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN);
        HttpURLConnection connection = OOSTestUtilsDev.invokeHttpsRequest(url, "GET", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        connection.connect();
        int code = connection.getResponseCode();
        assertEquals(403, code);
        
        // 创建并附加系统策略
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListAllMyBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        OOSPolicyParam param = new OOSPolicyParam();
        param.policyName = "oosPolicy";
        param.policyDocument = policyString;
        param.description = "1";
        Policy policy = OOSPolicyAPI.createPolicy(param);
        String body="Action=AttachUserPolicy&Version=2010-05-08&UserName="+ UrlEncoded.encodeString(userName) +"&PolicyArn="+UrlEncoded.encodeString(policy.getArn());
        IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        
        Thread.sleep(2000);
        url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN);
        connection = OOSTestUtilsDev.invokeHttpsRequest(url, "GET", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        connection.connect();
        code = connection.getResponseCode();
        assertEquals(200, code);
        
        // 更新系统策略
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:GetObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        param = new OOSPolicyParam();
        param.policyName = "oosPolicy";
        param.policyDocument = policyString;
        param.description = "1";
        OOSPolicyAPI.updatePolicy(param);
        
        Thread.sleep(2000);
        url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN);
        connection = OOSTestUtilsDev.invokeHttpsRequest(url, "GET", accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        connection.connect();
        code = connection.getResponseCode();
        assertEquals(403, code);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
        IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);

    }
}
