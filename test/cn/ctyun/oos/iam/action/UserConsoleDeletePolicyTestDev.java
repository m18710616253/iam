package cn.ctyun.oos.iam.action;

import static org.junit.Assert.assertEquals;

import java.net.URLEncoder;
import java.util.Arrays;
import java.util.List;

import org.junit.BeforeClass;
import org.junit.Test;

import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.Condition;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;
import common.tuple.Pair;

/**
 * 控制台删除策略测试
 * @author wangduo
 *
 */
public class UserConsoleDeletePolicyTestDev {

    private static MetaClient metaClient = MetaClient.getGlobalClient();
    
    public static final String OOS_IAM_DOMAIN="https://oos-cd-iam.ctyunapi.cn:9460/";
    public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
    public static final String regionName="cd";
    
    private static String ownerName = "rootuser@test.com";
    public static final String accessKey="rootuseraccesskey";
    public static final String secretKey="rootusersecretkey";
    
    private static OwnerMeta owner = new OwnerMeta(ownerName);
    private static String userName = "adminUser";
    private static String deletePolicyName = "deletePolicy";
    private static String deletePolicyArn = "arn:ctyun:iam::" + owner.getAccountId() + ":policy/"+deletePolicyName;
    private static String policyName = "adminPolicy";
    private static String policyArn="arn:ctyun:iam::" + owner.getAccountId() + ":policy/"+policyName;
    private static String adminUserAk;
    private static String adminUserSk;
    
    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        IAMTestUtils.TrancateTable("oos-owner");
        IAMTestUtils.TrancateTable("oos-aksk");
        IAMTestUtils.TrancateTable(IAMTestUtils.iamAccountSummaryTable);
        IAMTestUtils.TrancateTable("iam-user");
        IAMTestUtils.TrancateTable("iam-group");
        IAMTestUtils.TrancateTable("iam-policy");
        
        OwnerMeta owner1 = new OwnerMeta(ownerName);
        owner1.verify = null;
        owner1.currentAKNum = 0;
        metaClient.ownerDelete(owner1);
        metaClient.ownerInsertForTest(owner1);
        metaClient.ownerSelect(owner1);
        
        AkSkMeta asKey = new AkSkMeta(owner1.getId());
        asKey.setSecretKey(secretKey);
        asKey.accessKey =accessKey;
        asKey.status = 1;
        asKey.isPrimary = 1;
        metaClient.akskInsert(asKey);
        
        // 创建执行删除操作的子用户
        createUser(userName);
        User user = new User();
        user.accountId = owner.getAccountId();
        user.userName = userName;
        user = HBaseUtils.get(user);
        // 获取用户的ak
        adminUserAk = user.builtInAccessKey;
        AkSkMeta userAk = new AkSkMeta(adminUserAk);
        metaClient.akskSelectWithoutCache(userAk);
        adminUserSk = userAk.getSecretKey();
        
        createPolicy(Effect.Allow, deletePolicyName,"Action",Arrays.asList("iam:GetUser"),"Resource",Arrays.asList("*"),null);

    }
    
    /**
     * 删除有用户被附加的策略
     * @throws Exception
     */
    @Test
    public void testDeletePolicyWithUser() throws Exception {
        
        String attachedPolicyUser = "attachedPolicyUser";
        createUser(attachedPolicyUser);
        // 将待删除策略附加给用户
        attachPolicyToUser(attachedPolicyUser, deletePolicyArn);
        // 删除策略权限
        createPolicy(Effect.Allow, policyName,"Action",Arrays.asList("iam:DeletePolicy"),"Resource",Arrays.asList("*"),null);
        attachPolicyToUser(userName, policyArn);
        // 没有权限
        deletePolicy(deletePolicyArn, adminUserAk, adminUserSk, 403);
        // 附加删除
        createPolicy(Effect.Allow, policyName,"Action",Arrays.asList("iam:DeletePolicy", "iam:DetachUserPolicy"),"Resource",Arrays.asList("*"),null);
        // 删除成功
        deletePolicy(deletePolicyArn, adminUserAk, adminUserSk, 200);
    }
    
    /**
     * 删除有组被附加的策略
     * @throws Exception
     */
    @Test
    public void testDeletePolicyWithGroup() throws Exception {
        
        String attachedPolicyGroup = "attachedPolicyGroup";
        // 创建待删除组
        createGroup(attachedPolicyGroup);
        // 将待删除策略附加给组
        attachPolicyToGroup(attachedPolicyGroup, deletePolicyArn);
        // 删除策略权限
        createPolicy(Effect.Allow, policyName,"Action",Arrays.asList("iam:DeletePolicy"),"Resource",Arrays.asList("*"),null);
        attachPolicyToUser(userName, policyArn);
        // 没有权限
        deletePolicy(deletePolicyArn, adminUserAk, adminUserSk, 403);
        // 附加删除
        createPolicy(Effect.Allow, policyName,"Action",Arrays.asList("iam:DeletePolicy", "iam:DetachGroupPolicy"),"Resource",Arrays.asList("*"),null);
        // 删除成功
        deletePolicy(deletePolicyArn, adminUserAk, adminUserSk, 200);
    }
    
    public static void createUser(String userName) {
        String body="Action=CreateUser&Version=2010-05-08&UserName=" + userName;
        IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
    }
    
    public static void createGroup(String groupName) {
        String body="Action=CreateGroup&Version=2010-05-08&GroupName=" + groupName;
        IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
    }
    
    public static void deletePolicy(String policyArn, String adminUserAk, String adminUserSk, int code) {
        String body = "Action=DeletePolicy&Version=2010-05-08&PolicyArn=" + policyArn;
        Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest2(body, adminUserAk, adminUserSk, Arrays.asList(new Pair("OOS-PROXY-HOST", "test")));
        assertEquals(code, result.first().intValue());
    }
    
    //创建策略
    public static void createPolicy(Effect effect,String policyName,String actionEffect,List<String> actions,String resourceEffect,List<String> resources,List<Condition> conditions)throws Exception{
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(effect,null, null, actionEffect, actions, resourceEffect, resources, conditions);
        String body="Action=CreatePolicy&Version=2010-05-08&PolicyName="+URLEncoder.encode(policyName)+"&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=test_des";
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200,result.first().intValue());
        System.out.println(result.second());
    }
    
    public static void attachPolicyToUser(String userName,String policyArn)throws Exception{
        String bodyAttach="Action=AttachUserPolicy&Version=2010-05-08&UserName="+ userName +"&PolicyArn="+URLEncoder.encode(policyArn);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
        assertEquals(200,result.first().intValue());
        System.out.println(result.second());
    }
    
    public static void attachPolicyToGroup(String groupName,String policyArn)throws Exception{
        String bodyAttach="Action=AttachGroupPolicy&Version=2010-05-08&GroupName="+ groupName +"&PolicyArn="+URLEncoder.encode(policyArn);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
        assertEquals(200,result.first().intValue());
        System.out.println(result.second());
    }
    
}
