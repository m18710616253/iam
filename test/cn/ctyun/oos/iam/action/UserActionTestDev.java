/**
 * 
 */
package cn.ctyun.oos.iam.action;

import java.net.URLEncoder;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.iam.util.IAMHttpTestClient;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;

/**
 * @author wangduo
 *
 */
public class UserActionTestDev {

    public static final String accessKey="test_user8_6463084869102845087@a.cn88";
    public static final String secretKey="secretKey88";

    public static IAMHttpTestClient httpTestClient = new IAMHttpTestClient(accessKey, secretKey);

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
    }

    @Before
    public void setUp() throws Exception {
    }

    @Test
    public void test() throws Exception {
        
        String body="Action=CreateUser&Version=2010-05-08&UserName=" + URLEncoder.encode("userwd") + "&Tags.member.1.Key=tagkey1&Tags.member.1.Value=tagvalue";
        IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);

        body="Action=GetUser&Version=2010-05-08&UserName=" + URLEncoder.encode("userName__4") + "&Tags.member.1.Key=tagkey1&Tags.member.1.Value=tagvalue";
        IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
    }

    @Test
    public void testGetUserRoot() throws Exception {
        
        String body="Action=GetUser&Version=2010-05-08";
        IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
    }
    
    @Test
    public void testDelete() throws Exception {
        
        String body="Action=DeleteUser&Version=2010-05-08&UserName=" + URLEncoder.encode("UserName__4");
        IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);

    }
    
    @Test
    public void testCreateAccessKey() throws Exception {
        String body="Action=CreateAccessKey&UserName=usertest&Version=2010-05-08";
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
    
    @Test
    public void testCreateLoginProfile() throws Exception {
        
        String body="Action=CreateUser&Version=2010-05-08&UserName=testUser111";
        //IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        
        body="Action=CreateLoginProfile&UserName=testUser111&Password=12345678a@Q&PasswordResetRequired=false";
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
   
    @Test
    public void testGetLoginProfile() throws Exception {
        String body="Action=GetLoginProfile&UserName=test_user1";
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
    
    @Test
    public void testListUsers() throws Exception {
        String body="Action=ListUsers&Version=2010-05-08";
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
    
    @Test
    public void testGetUser() throws Exception {
        
        MetaClient metaClient = MetaClient.getGlobalClient();
        String ownerName1 = "testOwner";
        OwnerMeta owner1 = new OwnerMeta(ownerName1);
        
        owner1.verify = null;
        owner1.currentAKNum = 0;
        owner1.maxAKNum = 2;
        owner1.proxyLastLoginTime = System.currentTimeMillis();
        owner1.proxyLastLoginIp = "10.0.0.1";
        metaClient.ownerInsertForTest(owner1);
        metaClient.ownerSelect(owner1);
        
        AkSkMeta asKey = new AkSkMeta(owner1.getId());
        asKey.setSecretKey("secretKey88");
        asKey.accessKey = ownerName1 + "88";
        asKey.status = 1;
        asKey.isPrimary = 1;
        metaClient.akskInsert(asKey);
        String body="Action=GetUser";
        
        IAMHttpTestClient httpTestClient = new IAMHttpTestClient(asKey.accessKey, asKey.getSecretKey());
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
    
    @Test
    public void testTagUser() throws Exception {
        String body="Action=TagUser&UserName=test_user2&Tags.member.1.Key=Phone&Tags.member.1.Value=3&Tags.member.2.Key=Phone1&Tags.member.2.Value=3";
        for (int i = 1; i <= 30; i++) {
            body += "&Tags.member." + i + ".Key=Phone" + i + "&Tags.member." + i + ".Value=value" + i;
        }
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
    
    @Test
    public void testListUserTags() throws Exception {
        String body="Action=ListUserTags&UserName=test_user2";
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
    
    @Test
    public void testUntagUser() throws Exception {
        String body="Action=UntagUser&UserName=test_user1&TagKeys.member.3=1";
        for (int i = 1; i <= 50; i++) {
            body += "&TagKeys.member." + i + "=" + i;
        }
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
    
    @Test
    public void testGetAccountPasswordPolicy() throws Exception {
        String body="Action=GetAccountPasswordPolicy";
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
    
    @Test
    public void testUpdateAccountPasswordPolicy() throws Exception {
        String body="Action=UpdateAccountPasswordPolicy&RequireLowercaseCharacters=true"
                + "&PasswordReusePrevention=2&MaxPasswordAge=1&HardExpiry=false&AllowUsersToChangePassword=false";
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
    
}
