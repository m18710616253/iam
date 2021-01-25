package cn.ctyun.oos.iam.action;

import static org.junit.Assert.assertEquals;

import java.io.StringReader;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;
import org.eclipse.jetty.util.UrlEncoded;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xml.sax.InputSource;

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
 * 控制台删除组测试
 * @author wangduo
 *
 */
public class UserConsoleDeleteGroupTestDev {

    private static MetaClient metaClient = MetaClient.getGlobalClient();
    
    public static final String OOS_IAM_DOMAIN="https://oos-cd-iam.ctyunapi.cn:9460/";
    public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
    public static final String regionName="cd";
    
    private static String ownerName = "rootuser@test.com";
    public static final String accessKey="rootuseraccesskey";
    public static final String secretKey="rootusersecretkey";
    
    private static OwnerMeta owner = new OwnerMeta(ownerName);
    private static String userName = "adminUser";
    private static String deleteGroupName = "deleteGroup";
    private static String policyName = "deleteGroup";
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
        
        createGroup(deleteGroupName);
    }
    
    /**
     * 删除有用户的组
     * @throws Exception
     */
    @Test
    public void testDeleteGroupWithUser() throws Exception {
        
        String userInGroup = "userInGroup";
        createUser(userInGroup);
        // 添加用户到组，无法删除
        String body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+deleteGroupName+"&UserName="+userInGroup;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
        createPolicy(Effect.Allow, policyName,"Action",Arrays.asList("iam:DeleteGroup"),"Resource",Arrays.asList("*"),null);
        attachPolicyToUser(userName,policyArn);
        deleteGroup(deleteGroupName, adminUserAk, adminUserSk, 403);
        // 附加删除ak策略
        createPolicy(Effect.Allow, policyName,"Action",Arrays.asList("iam:DeleteGroup", "iam:RemoveUserFromGroup"),"Resource",Arrays.asList("*"),null);
        // 删除成功
        deleteGroup(deleteGroupName, adminUserAk, adminUserSk, 200);
    }
    
    @Test
    public void testDeleteGroupWithPolicy() throws Exception {
        // 创建待删除用户
        createGroup(deleteGroupName);
        // 创建策略
        String testPolicyName = "testPolicy";
        String testPolicyArn = "arn:ctyun:iam::" + owner.getAccountId() + ":policy/"+testPolicyName;;
        createPolicy(Effect.Allow, testPolicyName,"Action",Arrays.asList("iam:GetUser"),"Resource",Arrays.asList("*"),null);
        // 附加策略，无法删除
        attachPolicyToGroup(deleteGroupName,testPolicyArn);
        createPolicy(Effect.Allow, policyName,"Action",Arrays.asList("iam:DeleteGroup"),"Resource",Arrays.asList("*"),null);
        // 给用户添加删除组策略
        attachPolicyToUser(userName, policyArn);
        deleteGroup(deleteGroupName, adminUserAk, adminUserSk, 403);
        // 附加策略
        createPolicy(Effect.Allow, policyName,"Action",Arrays.asList("iam:DeleteGroup", "iam:DetachGroupPolicy"),"Resource",Arrays.asList("*"),null);
        // 删除成功
        deleteGroup(deleteGroupName, adminUserAk, adminUserSk, 200);
    }
    
    public static void createUser(String userName) {
        String body="Action=CreateUser&Version=2010-05-08&UserName=" + userName;
        IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
    }
    
    public static void createGroup(String groupName) {
        String body="Action=CreateGroup&Version=2010-05-08&GroupName=" + groupName;
        IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
    }
    
    public static void deleteGroup(String deleteGroupName, String adminUserAk, String adminUserSk, int code) {
        String body = "Action=DeleteGroup&Version=2010-05-08&GroupName=" + deleteGroupName;
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
