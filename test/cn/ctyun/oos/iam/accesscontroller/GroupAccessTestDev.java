package cn.ctyun.oos.iam.accesscontroller;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.jdom.JDOMException;
import org.junit.Before;
import org.junit.Test;

import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.Condition;
import cn.ctyun.oos.iam.server.result.AccessKeyResult;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.iam.test.iamaccesscontrol.IAMInterfaceTestUtils;
import cn.ctyun.oos.metadata.OwnerMeta;
import common.tuple.Pair;

public class GroupAccessTestDev {

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
    
//    @After
//    public void after() {
//        
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
//    }
    
    @Test
    /*
    * Deny Action=CreateGroup, NotResource=group/<group>
    * 资源非group1,显示拒绝group1失效，显示拒绝group2生效
    */
   public void test_CreateGroup_Deny_Action_NotResouce_group1() {
       String groupName="testGroup011";
       String groupName2="testGroup021";
       // 创建policy
       String policyName="DenyCreateGroupPolicy";
       String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/"+groupName),null);
       IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
       IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
       
       // 
       IAMInterfaceTestUtils.CreateGroup(accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey, groupName, 403);
       IAMInterfaceTestUtils.CreateGroup(accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey, groupName2, 403);
       
       String policyName2="AllowCreateGroupPolicy";
       String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",
               Arrays.asList("iam:CreateGroup","iam:GetGroup","iam:DeleteGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
       IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
       IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2,200);
       
       // 显示拒绝group1失效
       IAMInterfaceTestUtils.CreateGroup(accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey, groupName, 200);
       IAMInterfaceTestUtils.GetGroup(accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey, groupName, 200);
       IAMInterfaceTestUtils.DeleteGroup(accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey, groupName, 200);
       
       // 显示拒绝group2生效
       IAMInterfaceTestUtils.CreateGroup(accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey, groupName2, 403);
       IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName2, 200);
       IAMInterfaceTestUtils.GetGroup(accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey, groupName2, 200);
       IAMInterfaceTestUtils.DeleteGroup(accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey, groupName2, 200);
       
   }
    
    
    @Test
    /*
     * 
     */
    public void test_CreateGroup_Condition_sourceIP() {
        String groupName="testGroup01";;
        String policyName="allowspecialIP";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("IpAddress","ctyun:SourceIp",Arrays.asList("192.168.1.1/24")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
       
        String body="Action=CreateGroup&Version=2010-05-08&GroupName="+groupName;
        
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        assertEquals(200, result.first().intValue());
        
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest(body, accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
        assertEquals(403, result2.first().intValue());
    }

    @Test
    /*
     * allow Action=CreateGroup, resource=group/group1
     * 只允许创建group1
     */
    public void test_CreateGroup_Allow_Action_group1() throws JDOMException, IOException {
        // 创建policy
        String policyName="CreateGroupPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/testGroup01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 验证请求
        String groupName="testGroup01";
        String useName2 = "useName2";
        IAMTestUtils.invokeHttpsRequest("Action=CreateUser&Version=2010-05-08&UserName=" + useName2, accessKey, secretKey);
        
        // 给用户创建一个ak
        Pair<Integer, String> resultPair = IAMTestUtils.invokeHttpsRequest("Action=CreateAccessKey&UserName=" + useName2, accessKey, secretKey);
        AccessKeyResult accessKeyResult2 = AccessKeyResultUtilsDev.convertToAccessKeyResult(resultPair.second());
        
        String user2xmlString=IAMInterfaceTestUtils.CreateGroup(accessKeyResult2.accessKeyId, accessKeyResult2.secretAccessKey, groupName, 403);
        
        IAMInterfaceTestUtils.CreateGroup(accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey,groupName, 200);
        
        String groupName2="testGroup02";
        String user1bxmlString=IAMInterfaceTestUtils.CreateGroup(accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey,groupName2,403);
    }
    
    @Test
    public void test_Condition_UserAgent_StringEquals_Allow() {
        String policyName="UserAgent_StringEquals_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:UserAgent",Arrays.asList("Java/1.8.0_92")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        //IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        String groupName="testGroup01";
        String body="Action=CreateGroup&Version=2010-05-08&GroupName="+groupName;
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("UserAgent");
        param1.second("Java/1.8.0_91");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey, params);
        assertEquals(403, result.first().intValue());
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("UserAgent");
        param2.second("Java/1.8.0_92");
        params2.add(param2);
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey,params2);
        assertEquals(200, result2.first().intValue());
        
    }

    @Test
    public void test_Condition_Referer_StringEquals_Allow() {
        String policyName="Referer_StringEquals_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:Referer",Arrays.asList("http://www.yourwebsitename.com/login.html")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        //IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        String groupName="testGroup01";
        String body="Action=CreateGroup&Version=2010-05-08&GroupName="+groupName;
        
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("Referer");
        param1.second("http://www.yourwebsitename.com/console.html");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey, params);
        assertEquals(403, result.first().intValue());
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("Referer");
        param2.second("http://www.yourwebsitename.com/login.html");
        params2.add(param2);
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey, params2);
        assertEquals(200, result2.first().intValue());
        
    }

}
