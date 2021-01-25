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
 * 控制台删除用户测试
 * @author wangduo
 *
 */
public class UserConsoleDeleteUserTestDev {

    private static MetaClient metaClient = MetaClient.getGlobalClient();
    
    public static final String OOS_IAM_DOMAIN="https://oos-cd-iam.ctyunapi.cn:9460/";
    public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
    public static final String regionName="cd";
    
    private static String ownerName = "rootuser@test.com";
    public static final String accessKey="rootuseraccesskey";
    public static final String secretKey="rootusersecretkey";
    
    private static OwnerMeta owner = new OwnerMeta(ownerName);
    private static String userName = "adminUser";
    private static String deleteUserName = "deleteUser";
    private static String policyName = "deleteUser";
    private static String policyArn="arn:ctyun:iam::" + owner.getAccountId() + ":policy/"+policyName;
    private static String adminUserAk;
    private static String adminUserSk;
    
    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        IAMTestUtils.TrancateTable("oos-owner");
        IAMTestUtils.TrancateTable("oos-aksk");
        IAMTestUtils.TrancateTable(IAMTestUtils.iamAccountSummaryTable);
        
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
    }
    
    @Test
    public void testDeleteUserWithLoginProfile() throws Exception {
        // 创建待删除用户
        createUser(deleteUserName);
        // 添加密码，无法删除
        String body = "Action=CreateLoginProfile&UserName="+deleteUserName+"&Password=a12345678";
        Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, createPasswd.first().intValue());
        createPolicy(Effect.Allow, policyName,"Action",Arrays.asList("iam:DeleteUser"),"Resource",Arrays.asList("*"),null);
        attachPolicyToUser(userName,policyArn);
        deleteUser(deleteUserName, adminUserAk, adminUserSk, 403);
        // 附加删除密码策略
        createPolicy(Effect.Allow, policyName,"Action",Arrays.asList("iam:DeleteUser", "iam:DeleteLoginProfile"),"Resource",Arrays.asList("*"),null);
        // 删除成功
        deleteUser(deleteUserName, adminUserAk, adminUserSk, 200);
    }
    
    @Test
    public void testDeleteUserWithAk() throws Exception {
        
        // 创建待删除用户
        createUser(deleteUserName);
        // 添加ak，无法删除
        String body="Action=CreateAccessKey&UserName="+deleteUserName;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
        createPolicy(Effect.Allow, policyName,"Action",Arrays.asList("iam:DeleteUser"),"Resource",Arrays.asList("*"),null);
        attachPolicyToUser(userName,policyArn);
        deleteUser(deleteUserName, adminUserAk, adminUserSk, 403);
        // 附加删除ak策略
        createPolicy(Effect.Allow, policyName,"Action",Arrays.asList("iam:DeleteUser", "iam:DeleteAccessKey"),"Resource",Arrays.asList("*"),null);
        // 删除成功
        deleteUser(deleteUserName, adminUserAk, adminUserSk, 200);
    }
    
    @Test
    public void testDeleteUserWithGroup() throws Exception {
        
        // 创建待删除用户
        createUser(deleteUserName);
        // 创建组
        String groupName = "testGroup";
        String body="Action=CreateGroup&Version=2010-05-08&GroupName=" + groupName;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
        // 添加用户到组，无法删除
        body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+groupName+"&UserName="+deleteUserName;
        resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
        createPolicy(Effect.Allow, policyName,"Action",Arrays.asList("iam:DeleteUser"),"Resource",Arrays.asList("*"),null);
        attachPolicyToUser(userName,policyArn);
        deleteUser(deleteUserName, adminUserAk, adminUserSk, 403);
        // 附加删除ak策略
        createPolicy(Effect.Allow, policyName,"Action",Arrays.asList("iam:DeleteUser", "iam:RemoveUserFromGroup"),"Resource",Arrays.asList("*"),null);
        // 删除成功
        deleteUser(deleteUserName, adminUserAk, adminUserSk, 200);
    }
    
    @Test
    public void testDeleteUserWithPolicy() throws Exception {
        // 创建待删除用户
        createUser(deleteUserName);
        // 创建策略
        String testPolicyName = "testPolicy";
        String testPolicyArn = "arn:ctyun:iam::" + owner.getAccountId() + ":policy/"+testPolicyName;;
        createPolicy(Effect.Allow, testPolicyName,"Action",Arrays.asList("iam:GetUser"),"Resource",Arrays.asList("*"),null);
        // 附加策略，无法删除
        attachPolicyToUser(deleteUserName,testPolicyArn);
        createPolicy(Effect.Allow, policyName,"Action",Arrays.asList("iam:DeleteUser"),"Resource",Arrays.asList("*"),null);
        attachPolicyToUser(userName,policyArn);
        deleteUser(deleteUserName, adminUserAk, adminUserSk, 403);
        // 附加策略
        createPolicy(Effect.Allow, policyName,"Action",Arrays.asList("iam:DeleteUser", "iam:DetachUserPolicy"),"Resource",Arrays.asList("*"),null);
        // 删除成功
        deleteUser(deleteUserName, adminUserAk, adminUserSk, 200);
    }
    
    @Test
    public void testDeleteUserWithMFA() throws Exception {
        // 创建待删除用户
        createUser(deleteUserName);
        // 创建MFA
        String mfaName = "testMFA";
        String testMfaArn = "arn:ctyun:iam::" + owner.getAccountId() + ":mfa/" + mfaName;
        
        String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + mfaName;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(resultPair.second(), testMfaArn);
        
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        body="Action=EnableMFADevice&Version=2010-05-08&UserName=" + deleteUserName + "&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair2.first().intValue());
        
        createPolicy(Effect.Allow, policyName,"Action",Arrays.asList("iam:DeleteUser"),"Resource",Arrays.asList("*"),null);
        attachPolicyToUser(userName,policyArn);
        
        // 添加用户到组，无法删除
        deleteUser(deleteUserName, adminUserAk, adminUserSk, 403);
        // 附加策略
        createPolicy(Effect.Allow, policyName,"Action",Arrays.asList("iam:DeleteUser", "iam:DeactivateMFADevice"),"Resource",Arrays.asList("*"),null);
        // 删除成功
        deleteUser(deleteUserName, adminUserAk, adminUserSk, 200);
    }
    
    
    public static void createUser(String userName) {
        String body="Action=CreateUser&Version=2010-05-08&UserName=" + userName;
        IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
    }
    
    public static void deleteUser(String deleteUserName, String adminUserAk, String adminUserSk, int code) {
        String body = "Action=DeleteUser&Version=2010-05-08&UserName=" + deleteUserName;
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
    
    
    public Pair<String, String> CreateIdentifyingCode(String secret) {
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
     
     public Pair<String, String> AssertcreateVirtualMFADevice(String xml,String serialNumber) {
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
             assertEquals(serialNumber, SerialNumber);
             Pair<String, String> pair = new Pair<String, String>();
             pair.first(SerialNumber);
             pair.second(Base32StringSeed);
             return pair;
         } catch (Exception e) {
             // TODO: handle exception
         }
         
         return null;
     }
}
