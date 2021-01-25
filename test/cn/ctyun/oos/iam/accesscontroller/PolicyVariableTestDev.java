package cn.ctyun.oos.iam.accesscontroller;

import java.io.IOException;
import java.util.Arrays;

import org.jdom.JDOMException;
import org.junit.Before;
import org.junit.Test;

import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.server.result.AccessKeyResult;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.iam.test.iamaccesscontrol.IAMInterfaceTestUtils;
import cn.ctyun.oos.metadata.OwnerMeta;
import common.tuple.Pair;

public class PolicyVariableTestDev {

    public static final String accessKey="test_user8_6463084869102845087@a.cn88";
    public static final String secretKey="secretKey88";
    
    String accountId = new OwnerMeta("test_user8_6463084869102845087@a.cn").getAccountId();
    // 用户名
    String policyName = "CreateGroupPolicya1";
    String userName = "CreateGroupUsera1";
    String createGroupName = "testCreateGroupa1";
    
    AccessKeyResult accessKeyResult;
    
    @Before
    public void before() throws JDOMException, IOException {
        
        IAMTestUtils.TrancateTable("iam-user");
        IAMTestUtils.TrancateTable("iam-group");
        IAMTestUtils.TrancateTable("iam-policy");
        
        String body;
        Pair<Integer, String> resultPair;
//        
//        // 创建一个用户
        body = "Action=CreateUser&Version=2010-05-08&UserName=" + userName;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        
        // 给用户创建一个ak
        body="Action=CreateAccessKey&UserName=" + userName;
        resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(resultPair.second());
    }
    
    @Test
    /*
     * allow Action=CreateGroup, resource=group/group1
     * 只允许创建group1
     */
    public void test_CreateGroupAllowActionWithPolicyVariable() throws JDOMException, IOException {
        // 创建policy
        String policyName="CreateGroupPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/${ctyun:username}*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 验证请求
        String groupName="testGroup01";
        String useName2 = "useName2";
        IAMTestUtils.invokeHttpsRequest("Action=CreateUser&Version=2010-05-08&UserName=" + useName2, accessKey, secretKey);
        
        // 给用户创建一个ak
        Pair<Integer, String> resultPair = IAMTestUtils.invokeHttpsRequest("Action=CreateAccessKey&UserName=" + useName2, accessKey, secretKey);
        AccessKeyResult accessKeyResult2 = AccessKeyResultUtilsDev.convertToAccessKeyResult(resultPair.second());
        
        IAMInterfaceTestUtils.CreateGroup(accessKeyResult2.accessKeyId, accessKeyResult2.secretAccessKey, groupName, 403);
        IAMInterfaceTestUtils.CreateGroup(accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey,groupName, 403);
        
        IAMInterfaceTestUtils.CreateGroup(accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey,userName, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey,userName + "123", 200);
        String groupName2="testGroup02";
        IAMInterfaceTestUtils.CreateGroup(accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey,groupName2,403);
    }
}
