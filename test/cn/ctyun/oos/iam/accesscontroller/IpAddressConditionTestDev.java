package cn.ctyun.oos.iam.accesscontroller;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.Arrays;

import org.jdom.JDOMException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import cn.ctyun.oos.iam.accesscontroller.policy.AccessPolicy;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.Condition;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.IpAddressCondition;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.StringCondition;
import cn.ctyun.oos.iam.server.result.AccessKeyResult;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.iam.util.IAMHttpTestClient;
import common.tuple.Pair;

/**
 * 访问控制测试
 * @author wangduo
 *
 */
public class IpAddressConditionTestDev {

    public static final String accessKey="test_user8_6463084869102845087@a.cn88";
    public static final String secretKey="secretKey88";

    public static IAMHttpTestClient httpTestClient = new IAMHttpTestClient(accessKey, secretKey);

    PolicyTestToolDev policyTestTool = new PolicyTestToolDev();
    
    // 用户名
    String policyName = "CreateGroupPolicyForIPC6";
    String userName = "CreateGroupUserForIPC6";
    String createGroupName = "testCreateGroupForIPC6";
    
    AccessKeyResult accessKeyResult;
    
    @Before
    public void before() throws JDOMException, IOException {
        
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
    public void testUserAllow() throws Exception {
        
        String body;
        Pair<Integer, String> resultPair;
        
        // 创建策略
        AccessPolicy accessPolicy = new AccessPolicy();
        Statement statement = new Statement(Effect.Allow);
        statement.actions.add("iam:CreateGroup");
        statement.resources.add("arn:ctyun:iam::17vdu0cyjo7rh:group/*");
        // 添加条件
        Condition condition = new IpAddressCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("127.0.0.0/4"));
        statement.conditions.add(condition);
        condition = new StringCondition("StringNotLike", "ctyun:username", Arrays.asList("test"));
        statement.conditions.add(condition);
        accessPolicy.statements.add(statement);
        
        String json = new JsonPolicyWriter().writePolicyToString(accessPolicy);
        System.out.println(json);

        // 无权限请求失败
        body = "Action=CreateGroup&Version=2010-05-08&GroupName=" + createGroupName;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        assertEquals(403, resultPair.first().intValue());
        
        // 创建策略
        policyTestTool.createPolicy(policyName, json);
        // 附加策略
        policyTestTool.attachUserPolicy(policyName, userName);
        
        // 有权限请求成功
        body = "Action=CreateGroup&Version=2010-05-08&GroupName=" + createGroupName;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        assertEquals(200, resultPair.first().intValue());
        
        body = "Action=DeleteGroup&Version=2010-05-08&GroupName=" + createGroupName;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
        
        // 清除策略附加
        policyTestTool.detachUserPolicy(policyName, userName);
        // 删除策略 
        policyTestTool.deletePolicy(policyName);
    }
    
    
    @Test
    public void testUserDeny() throws Exception {
        
        String body;
        Pair<Integer, String> resultPair;
        
        // 创建策略
        AccessPolicy accessPolicy = new AccessPolicy();
        Statement statement = new Statement(Effect.Allow);
        statement.actions.add("iam:CreateGroup");
        statement.resources.add("arn:ctyun:iam::17vdu0cyjo7rh:group/*");
        // 添加条件
        Condition condition = new IpAddressCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("192.0.1.0/4"));
        statement.conditions.add(condition);
        accessPolicy.statements.add(statement);
        
        String json = new JsonPolicyWriter().writePolicyToString(accessPolicy);
        System.out.println(json);
        
        // 创建策略
        policyTestTool.createPolicy(policyName, json);
        
        // 无权限请求失败
        body = "Action=CreateGroup&Version=2010-05-08&GroupName=" + createGroupName;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        assertEquals(403, resultPair.first().intValue());
        
        // 附加策略
        policyTestTool.attachUserPolicy(policyName, userName);
        
        // 继续请求失败
        body = "Action=CreateGroup&Version=2010-05-08&GroupName=" + createGroupName;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        assertEquals(403, resultPair.first().intValue());
        
        // 清除策略附加
        policyTestTool.detachUserPolicy(policyName, userName);
        // 删除策略 
        policyTestTool.deletePolicy(policyName);
    }

}
