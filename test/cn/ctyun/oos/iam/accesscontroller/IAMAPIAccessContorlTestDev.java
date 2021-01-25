package cn.ctyun.oos.iam.accesscontroller;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.net.URLEncoder;

import org.jdom.JDOMException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import cn.ctyun.oos.iam.accesscontroller.policy.AccessPolicy;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.server.result.AccessKeyResult;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.iam.util.IAMHttpTestClient;
import common.tuple.Pair;

/**
 * 访问控制测试
 * @author wangduo
 *
 */
public class IAMAPIAccessContorlTestDev {

    public static final String accessKey="test_user8_6463084869102845087@a.cn88";
    public static final String secretKey="secretKey88";

    public static IAMHttpTestClient httpTestClient = new IAMHttpTestClient(accessKey, secretKey);

    PolicyTestToolDev policyTestTool = new PolicyTestToolDev();
    AccessKeyResult accessKeyResult;
    
    String policyName = "testPolicy111";
    String userName = "testUserP111";
    String createUserName = "testCreateUser111";
    
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
    public void testUserHasPolicy() throws Exception {
        
        String body;
        Pair<Integer, String> resultPair;
        
        AccessPolicy accessPolicy = new AccessPolicy();
        Statement statement = new Statement(Effect.Allow);
        statement.actions.add("iam:CreateUser");
        statement.resources.add("*");
        
        accessPolicy.statements.add(statement);
        
        String json = new JsonPolicyWriter().writePolicyToString(accessPolicy);
        
        // 创建策略
        body = "Action=CreatePolicy&Version=2010-05-08&Description=desc1235&PolicyName=" + policyName
                + "&PolicyDocument=" + URLEncoder.encode(json, "UTF-8");
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        
        // 创建一个用户
        body = "Action=CreateUser&Version=2010-05-08&UserName=" + userName;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        
        // 给用户创建一个ak
        body="Action=CreateAccessKey&UserName=" + userName;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(resultPair.second());
        // 附加策略
        body="Action=AttachUserPolicy&PolicyArn=arn:ctyun:iam::17vdu0cyjo7rh:policy/" + policyName + "&UserName=" + userName;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        
        // 有权限请求成功
        body = "Action=CreateUser&Version=2010-05-08&UserName=" + createUserName;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        assertEquals(200, resultPair.first().intValue());
        
        body = "Action=DeleteUser&Version=2010-05-08&UserName=" + createUserName;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
        
        // 清除测试数据
        // 清除策略附加
        body="Action=DetachUserPolicy&PolicyArn=arn:ctyun:iam::17vdu0cyjo7rh:policy/" + policyName + "&UserName=" + userName;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
        // 删除AK
        body="Action=DeleteAccessKey&AccessKeyId=" + accessKeyResult.accessKeyId + "&UserName=" + userName;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
        // 删除用户
        body = "Action=DeleteUser&Version=2010-05-08&UserName=" + userName ;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
        // 删除策略 
        body="Action=DeletePolicy&PolicyArn=arn:ctyun:iam::17vdu0cyjo7rh:policy/" + policyName;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
    }
    
    @Test
    public void testUserHasNoPolicy() throws Exception {
        
        String body;
        Pair<Integer, String> resultPair;
        
        // 创建一个用户
        body = "Action=CreateUser&Version=2010-05-08&UserName=" + userName;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        
        // 给用户创建一个ak
        body="Action=CreateAccessKey&UserName=" + userName;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(resultPair.second());
        // 使用ak创建用户，无权限，请求失败
        body = "Action=CreateUser&Version=2010-05-08&UserName=" + createUserName;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        assertEquals(403, resultPair.first().intValue());
        
        // 子用户删除创建的用户失败
        body = "Action=DeleteUser&Version=2010-05-08&UserName=" + createUserName;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        assertEquals(403, resultPair.first().intValue());
        
        // 清除测试数据
        // 删除AK
        body="Action=DeleteAccessKey&AccessKeyId=" + accessKeyResult.accessKeyId + "&UserName=" + userName;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
        // 删除用户
        body = "Action=DeleteUser&Version=2010-05-08&UserName=" + userName ;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
    }
    
}
