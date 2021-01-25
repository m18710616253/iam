package cn.ctyun.oos.iam.test;

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.io.IOUtils;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.JDOMException;
import org.jdom.input.SAXBuilder;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.xml.sax.InputSource;

import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.server.action.api.AccessKeyAction;
import cn.ctyun.oos.iam.server.action.api.UserAction;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.server.param.CreateAccessKeyParam;
import cn.ctyun.oos.iam.server.param.CreateUserParam;
import cn.ctyun.oos.iam.test.iamaccesscontrol.IAMInterfaceTestUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;
import common.tuple.Pair;

public class AccessKeyActionAPITest {
	
	public static final String OOS_IAM_DOMAIN="https://oos-cd-iam.ctyunapi.cn:9460/";
	public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
	public static final String regionName="cd";
	
	private static String ownerName = "root_user@test.com";
	public static final String accessKey="userak";
	public static final String secretKey="usersk";
	
	public static OwnerMeta owner = new OwnerMeta(ownerName);
    public static MetaClient metaClient = MetaClient.getGlobalClient();
	

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		
		// 创建根用户
		owner.email=ownerName;
        owner.setPwd("123456");
        owner.maxAKNum=10;
        owner.displayName="测试根用户";
        owner.bucketCeilingNum=10;
        metaClient.ownerInsertForTest(owner);

	}

//	@Before
	public void setUp() throws Exception {
		IAMTestUtils.TrancateTable("oos-aksk-yx");
		IAMTestUtils.TrancateTable("iam-user-yx");
		
		AkSkMeta aksk=new AkSkMeta(owner.getId());
        aksk.accessKey=accessKey;
        aksk.setSecretKey(secretKey);
        aksk.isPrimary=1;
        metaClient.akskInsert(aksk);
        
        // 创建第一个子用户
     	CreateUserParam param=new CreateUserParam();
     	param.userName="test_subuser1";
     	metaClient.ownerSelect(owner);
     	param.currentOwner=owner;
     	param.currentAccessKey=new AkSkMeta(owner.getId());
     		
     	UserAction.createUser(param);
     		
     	// 创建第二个子用户
     	CreateUserParam param2=new CreateUserParam();
     	param2.userName="test_subuser2";
     	metaClient.ownerSelect(owner);
     	param2.currentOwner=owner;
     	param2.currentAccessKey=new AkSkMeta(owner.getId());
     				
     	UserAction.createUser(param2);

	}

	@Test
	/*
	 * 创建根ak
	 */
	public void test_createAccessKey_UserNameRoot() throws Exception{
		String username=ownerName;
		String body="Action=CreateAccessKey&UserName="+username;
		
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(404, resultPair.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair.second());
		assertEquals("NoSuchEntity", error.get("Code"));
		assertEquals("The user with name "+username+" cannot be found.", error.get("Message"));
		assertEquals(username, error.get("Resource"));
        
	}
	
	@Test
	/*
	 * 创建子用户不带UserName的值根据aksk判断哪个用户创建，根用户
	 */
	public void test_createAccessKey_noUservalue_Root() throws Exception {
		String body="Action=CreateAccessKey";
		
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateAccessKey(resultPair.second(), ownerName, "Active");
	}
	
	@Test
    /*
     * 创建子用户不带UserName的值根据aksk判断哪个用户创建，子用户
     */
    public void test_createAccessKey_noUservalue_User() throws Exception {
	    String UserName1="subuser1";
        String user1accessKey1="abc1234567890";
        String user1secretKey1="sdfghjkl123456789";
        String accountId="3rmoqzn03g6ga";
        
        User user1=new User();
        user1.accountId=accountId;
        user1.userName=UserName1;
        user1.userId="test1abc";
        user1.createDate=System.currentTimeMillis();
        try {
            boolean success=HBaseUtils.checkAndCreate(user1);
            assertTrue(success);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        // 插入数据库aksk
        AkSkMeta aksk1 = new AkSkMeta(owner.getId());
        aksk1.isRoot = 0;
        aksk1.userId = user1.userId;
        aksk1.userName = UserName1;
        aksk1.accessKey=user1accessKey1;
        aksk1.setSecretKey(user1secretKey1);
        metaClient.akskInsert(aksk1);
        user1.accessKeys = new ArrayList<>();
        user1.accessKeys.add(aksk1.accessKey);
        HBaseUtils.put(user1);
        
        String policyName="getuser";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, UserName1, policyName, 200);

	    
        String body="Action=CreateAccessKey"; 
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, resultPair.first().intValue());
        AssertCreateAccessKey(resultPair.second(), UserName1, "Active");
    }
	
	@Test
    /*
     * 账户上限
     */
    public void test_createAccessKey_root_AKCeiling() throws Exception {
        String body="Action=CreateAccessKey";
        
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
        AssertCreateAccessKey(resultPair.second(), ownerName, "Active");
        
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(409, resultPair2.first().intValue());
        JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair2.second());
        assertEquals("LimitExceeded", error.get("Code"));
        assertEquals("Cannot exceed quota for AccessKeysPerAccount: 2.", error.get("Message"));
        assertEquals(ownerName, error.get("Resource"));
    }
	
	
	
	@Test
	/*
	 * 创建子ak,用户存在,不带version
	 */
	public void test_createAccessKey_UserExist_noVersion() throws Exception {
		String username="test_subuser1";
        String body="Action=CreateAccessKey&UserName="+username;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateAccessKey(resultPair.second(), username, "Active");      
	}
	
	@Test
	/*
	 * 创建子ak,用户存在,带version
	 */
	public void test_createAccessKey_UserExist_hasVersion() throws Exception {
		
		String username="test_subuser1";
        String body="Action=CreateAccessKey&UserName="+username+"&Version=2010-05-08";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateAccessKey(resultPair.second(), username, "Active"); 
        
	}
	
	@Test
	/*
	 * 创建子ak,用户不存在
	 */
	public void test_createAccessKey_NoUser() throws Exception{
		String username="test_subuser1000";
        String body="Action=CreateAccessKey&UserName=test_subuser1000";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(404, resultPair.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair.second());
		assertEquals("NoSuchEntity", error.get("Code"));
		assertEquals("The user with name "+username+" cannot be found.", error.get("Message"));
		assertEquals(username, error.get("Resource"));
	}
	
	@Test
	/*
	 * 创建子ak,ak2个
	 */
	public void test_createAccessKey_ak2() throws Exception{
		String username="test_subuser1";
        String body="Action=CreateAccessKey&UserName="+username;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateAccessKey(resultPair.second(), username, "Active");   
		Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair2.first().intValue());
		AssertCreateAccessKey(resultPair2.second(), username, "Active"); 
	}
	
	@Test
	/*
	 * 创建子ak,ak超限额,最多2个，创建3个
	 */
	public void test_createAccessKey_akMorethan() throws Exception{
		String username="test_subuser1";
        String body="Action=CreateAccessKey&UserName="+username;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateAccessKey(resultPair.second(), username, "Active"); 
		Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair2.first().intValue());
		AssertCreateAccessKey(resultPair2.second(), username, "Active");  
		Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(409, resultPair3.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair3.second());
		assertEquals("LimitExceeded", error.get("Code"));
		assertEquals("Cannot exceed quota for AccessKeysPerUser: 2.", error.get("Message"));
		assertEquals(username, error.get("Resource"));
		
	}
	
	@Test
	/*
	 * list 根用户ak
	 */
	public void test_listAccessKeys_NoUserName_Root() throws Exception{
		AkSkMeta aksk=new AkSkMeta(owner.getId());
        aksk.accessKey="userak2";
        aksk.setSecretKey("usersk2");
        aksk.isPrimary=1;
        metaClient.akskInsert(aksk);
        aksk.accessKey="userak3";
        aksk.setSecretKey("usersk3");
        aksk.isPrimary=1;
        metaClient.akskInsert(aksk);
        
        String body="Action=ListAccessKeys";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		List<Pair<String, String>> aks=new ArrayList<Pair<String,String>>();
		
		Pair<String, String> ak1= new Pair<String, String>();
		ak1.first("userak");
		ak1.second("Active");
		Pair<String, String> ak2= new Pair<String, String>();
		ak2.first("userak2");
		ak2.second("Active");
		Pair<String, String> ak3= new Pair<String, String>();
		ak3.first("userak3");
		ak3.second("Active");
		
		aks.add(ak1);
		aks.add(ak2);
		aks.add(ak3);
		
        AssertListAccessKey(resultPair.second(), ownerName, false, aks);
    }
	
	@Test
	public void test_listAccessKeys_NoUserName_User() throws IOException {
	    String UserName1="subuser1";
        String user1accessKey1="abc1234567890";
        String user1secretKey1="sdfghjkl123456789";
        String accountId="3rmoqzn03g6ga";
        
        User user1=new User();
        user1.accountId=accountId;
        user1.userName=UserName1;
        user1.userId="test1abc";
        user1.createDate=System.currentTimeMillis();
        try {
            boolean success=HBaseUtils.checkAndCreate(user1);
            assertTrue(success);
        } catch (IOException e) {
            e.printStackTrace();
        }

        // 插入数据库aksk
        AkSkMeta aksk1 = new AkSkMeta(owner.getId());
        aksk1.isRoot = 0;
        aksk1.userId = user1.userId;
        aksk1.userName = UserName1;
        aksk1.accessKey=user1accessKey1;
        aksk1.setSecretKey(user1secretKey1);
        metaClient.akskInsert(aksk1);
        user1.accessKeys = new ArrayList<>();
        user1.accessKeys.add(aksk1.accessKey);
        HBaseUtils.put(user1);
        
        String policyName="listak";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, UserName1, policyName, 200);

        String body="Action=ListAccessKeys";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, resultPair.first().intValue());
        
        List<Pair<String, String>> aks=new ArrayList<Pair<String,String>>();
        
        Pair<String, String> ak1= new Pair<String, String>();
        ak1.first("user1accessKey1");
        ak1.second("Active");
        
        AssertListAccessKey(resultPair.second(), UserName1, false, aks);
    }
	
	@Test
	/*
	 * list 根用户ak
	 */
	public void test_listAccessKeys_UserNameRoot() throws Exception{
		AkSkMeta aksk=new AkSkMeta(owner.getId());
        aksk.accessKey="userak2";
        aksk.setSecretKey("usersk2");
        aksk.isPrimary=1;
        metaClient.akskInsert(aksk);
        aksk.accessKey="userak3";
        aksk.setSecretKey("usersk3");
        aksk.isPrimary=1;
        metaClient.akskInsert(aksk);
        String username=ownerName;
        String body="Action=ListAccessKeys&UserName="+username;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(404, resultPair.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair.second());
		assertEquals("NoSuchEntity", error.get("Code"));
		assertEquals("The user with name "+username+" cannot be found.", error.get("Message"));
		assertEquals(username, error.get("Resource"));
    }
	
	@Test
	/*
	 * list 根用户ak,指定MaxItems,截断返回
	 */
	public void test_listAccessKeys_Root_MaxItem() throws Exception{
		AkSkMeta aksk=new AkSkMeta(owner.getId());
		for (int i = 1; i < 10; i++) {
			aksk.accessKey="userak"+i;
	        aksk.setSecretKey("usersk"+i);
	        aksk.isPrimary=1;
	        metaClient.akskInsert(aksk);
		}
        
        
        String body="Action=ListAccessKeys&MaxItems=6";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		
		List<Pair<String, String>> aks=new ArrayList<Pair<String,String>>();
		Pair<String, String> ak1= new Pair<String, String>();
		ak1.first("userak");
		ak1.second("Active");
		aks.add(ak1);
		for (int i = 1; i <=5; i++) {
			Pair<String, String> ak= new Pair<String, String>();
			ak.first("userak"+i);
			ak.second("Active");
			aks.add(ak);
		}
		
		String marker=AssertListAccessKey(resultPair.second(), ownerName, true, aks);
		
		body="Action=ListAccessKeys&MaxItems=6&Marker="+marker;
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair2.first().intValue());
		List<Pair<String, String>> aks2=new ArrayList<Pair<String,String>>();
		for (int i = 6; i < 10; i++) {
			Pair<String, String> ak= new Pair<String, String>();
			ak.first("userak"+i);
			ak.second("Active");
			aks2.add(ak);
		}
		AssertListAccessKey(resultPair2.second(), ownerName, false, aks2);
	}

	@Test
	/*
	 * list 子用户ak
	 */
	public void test_listAccessKeys_UserExist() throws Exception{
		List<Pair<String, String>> aks=new ArrayList<Pair<String,String>>();
		String username="test_subuser1";
        String body="Action=CreateAccessKey&UserName="+username;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String akid1=AssertCreateAccessKey(resultPair.second(), username, "Active"); 
		
		Pair<String, String> ak1= new Pair<String, String>();
		ak1.first(akid1);
		ak1.second("Active");
		aks.add(ak1);
		
		Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair2.first().intValue());
		String akid2=AssertCreateAccessKey(resultPair2.second(), username, "Active");
		
		Pair<String, String> ak2= new Pair<String, String>();
		ak2.first(akid2);
		ak2.second("Active");
		aks.add(ak2);
		
        body="Action=ListAccessKeys&UserName="+username;
        Pair<Integer, String> list=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, list.first().intValue());
		AssertListAccessKey(list.second(), username, false, aks);
	}
	
	@Test
    /*
     * list 子用户ak
     */
    public void test_listAccessKeys_UserNoAK() throws Exception{
        String username="test_subuser1";

        String body="Action=ListAccessKeys&UserName="+username;
        Pair<Integer, String> list=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, list.first().intValue());
        AssertListAccessKey(list.second(), username, false, null);
    }
	
	@Test
	/*
	 * list 子用户ak
	 */
	public void test_listAccessKeys_NoUser() throws Exception{
		String username="nouser";
        String body="Action=ListAccessKeys&UserName="+username;
        Pair<Integer, String> list=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(404, list.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(list.second());
		assertEquals("NoSuchEntity", error.get("Code"));
		assertEquals("The user with name "+username+" cannot be found.", error.get("Message"));
		assertEquals(username, error.get("Resource"));
		
	}
	
	
	@Test
	/*
	 * list 子用户ak,指定MaxItems,截断返回
	 */
	public void test_listAccessKeys_User_MaxItem() throws Exception{
		List<Pair<String, String>> aks1=new ArrayList<Pair<String,String>>();
		List<Pair<String, String>> aks2=new ArrayList<Pair<String,String>>();
		String username="test_subuser1";
        String body="Action=CreateAccessKey&UserName="+username;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String akid1=AssertCreateAccessKey(resultPair.second(), username, "Active"); 
		
		Pair<String, String> ak1= new Pair<String, String>();
		ak1.first(akid1);
		ak1.second("Active");
		aks1.add(ak1);
		
		Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair2.first().intValue());
		String akid2=AssertCreateAccessKey(resultPair2.second(), username, "Active");
		
		Pair<String, String> ak2= new Pair<String, String>();
		ak2.first(akid2);
		ak2.second("Active");
		aks2.add(ak2);
        
        body="Action=ListAccessKeys&UserName=test_subuser1&MaxItems=1";
        Pair<Integer, String> list=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, list.first().intValue());
		String marker=AssertListAccessKey(list.second(), username, true, aks1);
		
		body="Action=ListAccessKeys&UserName=test_subuser1&MaxItems=1&Marker="+marker;
	    Pair<Integer, String> list2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, list2.first().intValue());
		AssertListAccessKey(list2.second(), username, false, aks2);
        
	}

	@Test
	/*
	 * 删除根用户ak，不传UserName
	 */
	public void test_deleteAccessKey_NoUserName_Root() {
		String body="Action=CreateAccessKey";
		
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String akId=AssertCreateAccessKey(resultPair.second(), ownerName, "Active");
		
		body="Action=DeleteAccessKey&AccessKeyId="+akId;
		Pair<Integer, String> delete=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, delete.first().intValue());
        
	}
	
	@Test
    /*
     * 删除根用户ak，不传UserName
     */
    public void test_deleteAccessKey_NoUserName_User() throws IOException {
	    String UserName1="subuser1";
        String user1accessKey1="abc1234567890";
        String user1secretKey1="sdfghjkl123456789";
        String accountId="3rmoqzn03g6ga";
        
        User user1=new User();
        user1.accountId=accountId;
        user1.userName=UserName1;
        user1.userId="test1abc";
        user1.createDate=System.currentTimeMillis();
        try {
            boolean success=HBaseUtils.checkAndCreate(user1);
            assertTrue(success);
        } catch (IOException e) {
            e.printStackTrace();
        }

        // 插入数据库aksk
        AkSkMeta aksk1 = new AkSkMeta(owner.getId());
        aksk1.isRoot = 0;
        aksk1.userId = user1.userId;
        aksk1.userName = UserName1;
        aksk1.accessKey=user1accessKey1;
        aksk1.setSecretKey(user1secretKey1);
        metaClient.akskInsert(aksk1);
        user1.accessKeys = new ArrayList<>();
        user1.accessKeys.add(aksk1.accessKey);
        HBaseUtils.put(user1);
        
        String policyName="Deleteak";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey","iam:DeleteAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, UserName1, policyName, 200);

	    
        String body="Action=CreateAccessKey";
        
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, resultPair.first().intValue());
        String akId=AssertCreateAccessKey(resultPair.second(), UserName1, "Active");
        
        body="Action=DeleteAccessKey&AccessKeyId="+akId;
        Pair<Integer, String> delete=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, delete.first().intValue());
        
    }
	
	@Test
	/*
	 * 删除根用户ak，传UserName
	 */
	public void test_deleteAccessKey_UsernameRoot() throws JSONException {
		String username= ownerName;
		String body="Action=CreateAccessKey";
		
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String akId=AssertCreateAccessKey(resultPair.second(), username, "Active");
		
		body="Action=DeleteAccessKey&AccessKeyId="+akId+"&UserName="+username;
		Pair<Integer, String> delete=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(404, delete.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(delete.second());
		assertEquals("NoSuchEntity", error.get("Code"));
		assertEquals("The user with name "+username+" cannot be found.", error.get("Message"));
		assertEquals(akId, error.get("Resource"));
	}
	
	@Test
	/*
	 * 删除子用户ak
	 */
	public void test_deleteAccessKey_User() throws Exception{
		String username="test_subuser1";
        String body="Action=CreateAccessKey&UserName="+username;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String akId=AssertCreateAccessKey(resultPair.second(), username, "Active");     
        
        body="Action=DeleteAccessKey&UserName=test_subuser1&AccessKeyId="+akId;
        Pair<Integer, String> delete=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, delete.first().intValue());
	}
	
	@Test
	/*
	 * 删除子用户ak不存在
	 */
	public void test_deleteAccessKey_User_noAK() throws Exception{
		String username="test_subuser1";
		String akId="5fccc056696ca8ccb158";
        String body="Action=DeleteAccessKey&UserName="+username+"&AccessKeyId="+akId;
        Pair<Integer, String> delete=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(404, delete.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(delete.second());
		assertEquals("NoSuchEntity", error.get("Code"));
		assertEquals("The Access Key with id "+akId+" cannot be found.", error.get("Message"));
		assertEquals(akId, error.get("Resource"));
	}
	
	@Test
	/*
	 * 删除子用户ak参数为empty
	 */
	public void test_deleteAccessKey_User_noAK2() throws Exception{
		String username="test_subuser1";
		String akId="";
        String body="Action=DeleteAccessKey&UserName="+username+"&AccessKeyId="+akId;
        Pair<Integer, String> delete=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, delete.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(delete.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("2 validation errors detected: Value '' at 'accessKeyId' failed to satisfy constraint: Member must have length greater than or equal to 16; The specified value for 'accessKeyId' is invalid. It must contain only alphanumeric characters", error.get("Message"));
		assertEquals(akId, error.get("Resource"));
	}
	
	@Test
	/*
	 * 删除子用户ak参数不存在
	 */
	public void test_deleteAccessKey_User_noAKParam() throws Exception{

        String body="Action=DeleteAccessKey&UserName=test_subuser1";
        Pair<Integer, String> delete=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, delete.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(delete.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'accessKeyId' failed to satisfy constraint: Member must not be null", error.get("Message"));
		assertEquals("", error.get("Resource"));
	}
	
	@Test
	/*
	 * UserName中没有删除的ak
	 */
	public void test_deleteAccessKey_User_rootAk() throws JSONException {
		String body="Action=CreateAccessKey";
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String rootak=AssertCreateAccessKey(resultPair.second(), ownerName, "Active");
		
		body="Action=DeleteAccessKey&UserName=test_subuser1&AccessKeyId="+rootak;
	    Pair<Integer, String> delete=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
	    assertEquals(404, delete.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(delete.second());
		assertEquals("NoSuchEntity", error.get("Code"));
		assertEquals("The Access Key with id "+rootak+" cannot be found.", error.get("Message"));
		assertEquals(rootak, error.get("Resource"));
	}
	
	@Test
	/*
	 * UserName中没有删除的ak
	 */
	public void test_deleteAccessKey_User_OtherSubAk() throws JSONException {
		String body="Action=CreateAccessKey&UserName=test_subuser2";
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String otherAK=AssertCreateAccessKey(resultPair.second(), "test_subuser2", "Active");
		
		body="Action=DeleteAccessKey&UserName=test_subuser1&AccessKeyId="+otherAK;
	    Pair<Integer, String> delete=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
	    assertEquals(404, delete.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(delete.second());
		assertEquals("NoSuchEntity", error.get("Code"));
		assertEquals("The Access Key with id "+otherAK+" cannot be found.", error.get("Message"));
		assertEquals(otherAK, error.get("Resource"));
	}
	
	@Test
	public void test_updateAccessKey_NoUserName_Root_ActiveToInactive() {

        String body="Action=CreateAccessKey";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String akId=AssertCreateAccessKey(resultPair.second(), ownerName, "Active");

        body="Status=Inactive&Action=UpdateAccessKey&AccessKeyId="+akId;
        Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		List<Pair<String, String>> aks=new ArrayList<Pair<String,String>>();
		Pair<String, String> ak= new Pair<String, String>();
		ak.first(akId);
		ak.second("Inactive");
		aks.add(ak);
		
		body="Action=ListAccessKeys";
        Pair<Integer, String> list=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, list.first().intValue());
		AssertListAccessKey(list.second(), ownerName, false, aks);
	}
	
	@Test
	public void test_updateAccessKey_NoUserName_Root_InactiveToActive() {
        String body="Action=CreateAccessKey";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String akId=AssertCreateAccessKey(resultPair.second(), ownerName, "Active");

        body="Status=Inactive&Action=UpdateAccessKey&AccessKeyId="+akId;
        Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		List<Pair<String, String>> aks=new ArrayList<Pair<String,String>>();
		Pair<String, String> ak= new Pair<String, String>();
		ak.first(akId);
		ak.second("Inactive");
		aks.add(ak);
		
		body="Action=ListAccessKeys";
        Pair<Integer, String> list=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, list.first().intValue());
		AssertListAccessKey(list.second(), ownerName, false, aks);
		
		body="Status=Active&Action=UpdateAccessKey&AccessKeyId="+akId;
	    Pair<Integer, String> update2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update2.first().intValue());
			
		List<Pair<String, String>> aks2=new ArrayList<Pair<String,String>>();
		Pair<String, String> ak2= new Pair<String, String>();
		ak2.first(akId);
		ak2.second("Active");
		aks2.add(ak2);
			
		body="Action=ListAccessKeys";
	    Pair<Integer, String> list2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, list2.first().intValue());
		AssertListAccessKey(list2.second(), ownerName, false, aks2);
	}
	
	@Test
    public void test_updateAccessKey_NoUserName_User_ActiveToInactive() throws IOException {
	    
	    String UserName1="subuser1";
        String user1accessKey1="abc1234567890";
        String user1secretKey1="sdfghjkl123456789";
        String accountId="3rmoqzn03g6ga";
        
        User user1=new User();
        user1.accountId=accountId;
        user1.userName=UserName1;
        user1.userId="test1abc";
        user1.createDate=System.currentTimeMillis();
        try {
            boolean success=HBaseUtils.checkAndCreate(user1);
            assertTrue(success);
        } catch (IOException e) {
            e.printStackTrace();
        }

        // 插入数据库aksk
        AkSkMeta aksk1 = new AkSkMeta(owner.getId());
        aksk1.isRoot = 0;
        aksk1.userId = user1.userId;
        aksk1.userName = UserName1;
        aksk1.accessKey=user1accessKey1;
        aksk1.setSecretKey(user1secretKey1);
        metaClient.akskInsert(aksk1);
        user1.accessKeys = new ArrayList<>();
        user1.accessKeys.add(aksk1.accessKey);
        HBaseUtils.put(user1);
        
        String policyName="updateak";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListAccessKeys","iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, UserName1, policyName, 200);

        String body="Action=CreateAccessKey&UserName="+UserName1;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
        String akId=AssertCreateAccessKey(resultPair.second(), UserName1, "Active");

        body="Status=Inactive&Action=UpdateAccessKey&AccessKeyId="+akId;
        Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, update.first().intValue());
        
        List<Pair<String, String>> aks=new ArrayList<Pair<String,String>>();
        Pair<String, String> ak= new Pair<String, String>();
        ak.first(akId);
        ak.second("Inactive");
        aks.add(ak);
        
        body="Action=ListAccessKeys";
        Pair<Integer, String> list=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, list.first().intValue());
        AssertListAccessKey(list.second(), UserName1, false, aks);
    }
	
	@Test
    public void test_updateAccessKey_NoUserName_User_InactiveToActive() throws IOException {
	    String UserName1="subuser1";
        String user1accessKey1="abc1234567890";
        String user1secretKey1="sdfghjkl123456789";
        String accountId="3rmoqzn03g6ga";
        
        User user1=new User();
        user1.accountId=accountId;
        user1.userName=UserName1;
        user1.userId="test1abc";
        user1.createDate=System.currentTimeMillis();
        try {
            boolean success=HBaseUtils.checkAndCreate(user1);
            assertTrue(success);
        } catch (IOException e) {
            e.printStackTrace();
        }

        // 插入数据库aksk
        AkSkMeta aksk1 = new AkSkMeta(owner.getId());
        aksk1.isRoot = 0;
        aksk1.userId = user1.userId;
        aksk1.userName = UserName1;
        aksk1.accessKey=user1accessKey1;
        aksk1.setSecretKey(user1secretKey1);
        metaClient.akskInsert(aksk1);
        user1.accessKeys = new ArrayList<>();
        user1.accessKeys.add(aksk1.accessKey);
        HBaseUtils.put(user1);
        
        String policyName="updateak";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListAccessKeys","iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, UserName1, policyName, 200);

	    
        String body="Action=CreateAccessKey&UserName="+UserName1;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
        String akId=AssertCreateAccessKey(resultPair.second(), UserName1, "Active");

        body="Status=Inactive&Action=UpdateAccessKey&AccessKeyId="+akId;
        Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, update.first().intValue());
        
        List<Pair<String, String>> aks=new ArrayList<Pair<String,String>>();
        Pair<String, String> ak= new Pair<String, String>();
        ak.first(akId);
        ak.second("Inactive");
        aks.add(ak);
        
        body="Action=ListAccessKeys";
        Pair<Integer, String> list=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, list.first().intValue());
        AssertListAccessKey(list.second(), UserName1, false, aks);
        
        body="Status=Active&Action=UpdateAccessKey&AccessKeyId="+akId;
        Pair<Integer, String> update2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, update2.first().intValue());
            
        List<Pair<String, String>> aks2=new ArrayList<Pair<String,String>>();
        Pair<String, String> ak2= new Pair<String, String>();
        ak2.first(akId);
        ak2.second("Active");
        aks2.add(ak2);
            
        body="Action=ListAccessKeys";
        Pair<Integer, String> list2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, list2.first().intValue());
        AssertListAccessKey(list2.second(), UserName1, false, aks2);
    }
	
	@Test
	/*
	 * 更新子用户ak的Status从Active to Active
	 */
	public void test_updateAccessKey_User_ActiveToActive() throws Exception{
		String username="test_subuser1";
        String body="Action=CreateAccessKey&UserName="+username;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String akId=AssertCreateAccessKey(resultPair.second(), username, "Active");

        body="Status=Active&Action=UpdateAccessKey&UserName=test_subuser1&AccessKeyId="+akId;
        Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		List<Pair<String, String>> aks=new ArrayList<Pair<String,String>>();
		Pair<String, String> ak= new Pair<String, String>();
		ak.first(akId);
		ak.second("Active");
		aks.add(ak);
		
		body="Action=ListAccessKeys&UserName="+username;
        Pair<Integer, String> list=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, list.first().intValue());
		AssertListAccessKey(list.second(), username, false, aks);
	}
	
	@Test
	/*
	 * 更新子用户ak的Status从Active to Inactive
	 */
	public void test_updateAccessKey_User_ActiveToInactive() throws Exception{
		String username="test_subuser1";
        String body="Action=CreateAccessKey&UserName="+username;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String akId=AssertCreateAccessKey(resultPair.second(), username, "Active");

        body="Status=Inactive&Action=UpdateAccessKey&UserName=test_subuser1&AccessKeyId="+akId;
        Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		List<Pair<String, String>> aks=new ArrayList<Pair<String,String>>();
		Pair<String, String> ak= new Pair<String, String>();
		ak.first(akId);
		ak.second("Inactive");
		aks.add(ak);
		
		body="Action=ListAccessKeys&UserName="+username;
        Pair<Integer, String> list=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, list.first().intValue());
		AssertListAccessKey(list.second(), username, false, aks);
		
	}
	
	@Test
	/*
	 * 更新子用户ak的Status从Inactive to Inactive
	 */
	public void test_updateAccessKey_User_InactiveToInactive() throws Exception{
		String username="test_subuser1";
        String body="Action=CreateAccessKey&UserName="+username;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String akId=AssertCreateAccessKey(resultPair.second(), username, "Active");

        body="Status=Inactive&Action=UpdateAccessKey&UserName=test_subuser1&AccessKeyId="+akId;
        Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		List<Pair<String, String>> aks=new ArrayList<Pair<String,String>>();
		Pair<String, String> ak= new Pair<String, String>();
		ak.first(akId);
		ak.second("Inactive");
		aks.add(ak);
		
		body="Action=ListAccessKeys&UserName="+username;
        Pair<Integer, String> list=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, list.first().intValue());
		AssertListAccessKey(list.second(), username, false, aks);
		
		body="Status=Inactive&Action=UpdateAccessKey&UserName=test_subuser1&AccessKeyId="+akId;
	    Pair<Integer, String> update2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update2.first().intValue());
			
		List<Pair<String, String>> aks2=new ArrayList<Pair<String,String>>();
		Pair<String, String> ak2= new Pair<String, String>();
		ak2.first(akId);
		ak2.second("Inactive");
		aks2.add(ak2);
			
		body="Action=ListAccessKeys&UserName="+username;
	    Pair<Integer, String> list2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, list2.first().intValue());
		AssertListAccessKey(list2.second(), username, false, aks2);

	}
	
	@Test
	/*
	 * 更新子用户ak的Status从Inactive to Active
	 */
	public void test_updateAccessKey_User_InactiveToActive() throws Exception{
		String username="test_subuser1";
        String body="Action=CreateAccessKey&UserName="+username;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String akId=AssertCreateAccessKey(resultPair.second(), username, "Active");

        body="Status=Inactive&Action=UpdateAccessKey&UserName=test_subuser1&AccessKeyId="+akId;
        Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		List<Pair<String, String>> aks=new ArrayList<Pair<String,String>>();
		Pair<String, String> ak= new Pair<String, String>();
		ak.first(akId);
		ak.second("Inactive");
		aks.add(ak);
		
		body="Action=ListAccessKeys&UserName="+username;
        Pair<Integer, String> list=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, list.first().intValue());
		AssertListAccessKey(list.second(), username, false, aks);
		
		body="Status=Active&Action=UpdateAccessKey&UserName=test_subuser1&AccessKeyId="+akId;
	    Pair<Integer, String> update2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update2.first().intValue());
			
		List<Pair<String, String>> aks2=new ArrayList<Pair<String,String>>();
		Pair<String, String> ak2= new Pair<String, String>();
		ak2.first(akId);
		ak2.second("Active");
		aks2.add(ak2);
			
		body="Action=ListAccessKeys&UserName="+username;
	    Pair<Integer, String> list2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, list2.first().intValue());
		AssertListAccessKey(list2.second(), username, false, aks2);
	}
	
	@Test
	/*
	 * 更新子用户ak的Status非Inactive非Active
	 */
	public void test_updateAccessKey_User_noInactivenoActive() throws Exception{
		String username="test_subuser1";
        String body="Action=CreateAccessKey&UserName="+username;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String akId=AssertCreateAccessKey(resultPair.second(), username, "Active");

        body="Status=hello&Action=UpdateAccessKey&UserName=test_subuser1&AccessKeyId="+akId;
        Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, update.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(update.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value 'hello' at 'status' failed to satisfy constraint: Member must satisfy enum value set: [Active, Inactive]", error.get("Message"));
		assertEquals(akId, error.get("Resource"));
		
	}
	
	@Test
	/*
	 * 更新子用户ak的Status为inactive
	 */
	public void test_updateAccessKey_User_Inactive_lowercase() throws Exception{
		String username="test_subuser1";
        String body="Action=CreateAccessKey&UserName="+username;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String akId=AssertCreateAccessKey(resultPair.second(), username, "Active");

        body="Status=inactive&Action=UpdateAccessKey&UserName=test_subuser1&AccessKeyId="+akId;
        Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		List<Pair<String, String>> aks=new ArrayList<Pair<String,String>>();
		Pair<String, String> ak= new Pair<String, String>();
		ak.first(akId);
		ak.second("Inactive");
		aks.add(ak);
		
		body="Action=ListAccessKeys&UserName="+username;
        Pair<Integer, String> list=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, list.first().intValue());
		AssertListAccessKey(list.second(), username, false, aks);
	}
	
	@Test
	/*
	 * 更新子用户ak的Status为active
	 */
	public void test_updateAccessKey_User_active_lowercase() throws Exception{
		String username="test_subuser1";
        String body="Action=CreateAccessKey&UserName="+username;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String akId=AssertCreateAccessKey(resultPair.second(), username, "Active");

        body="Status=active&Action=UpdateAccessKey&UserName=test_subuser1&AccessKeyId="+akId;
        Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		List<Pair<String, String>> aks=new ArrayList<Pair<String,String>>();
		Pair<String, String> ak= new Pair<String, String>();
		ak.first(akId);
		ak.second("Active");
		aks.add(ak);
		
		body="Action=ListAccessKeys&UserName="+username;
        Pair<Integer, String> list=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, list.first().intValue());
		AssertListAccessKey(list.second(), username, false, aks);
	}
	
	@Test
	/*
	 * 更新子用户ak 没有AccessKeyId参数和Status参数
	 */
	public void test_updateAccessKey_User_noaknostatus() throws Exception{
        
        String body="Status=&Action=UpdateAccessKey&UserName=test_subuser1&AccessKeyId=";
        Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, update.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(update.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("3 validation errors detected: Value '' at 'accessKeyId' failed to satisfy constraint: Member must have length greater than or equal to 16; The specified value for 'accessKeyId' is invalid. It must contain only alphanumeric characters; Value '' at 'status' failed to satisfy constraint: Member must satisfy enum value set: [Active, Inactive]", error.get("Message"));
		assertEquals("", error.get("Resource"));
	}
	
	@Test
	/*
	 * 更新子用户ak 没有Status参数
	 */
	public void test_updateAccessKey_User_nostatus() throws Exception{
		String username="test_subuser1";
        String body="Action=CreateAccessKey&UserName="+username;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String akId=AssertCreateAccessKey(resultPair.second(), username, "Active");

        body="Status=&Action=UpdateAccessKey&UserName=test_subuser1&AccessKeyId="+akId;
        Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, update.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(update.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value '' at 'status' failed to satisfy constraint: Member must satisfy enum value set: [Active, Inactive]", error.get("Message"));
		assertEquals(akId, error.get("Resource"));
	}
	
	@Ignore
	/*
	 * 产品本期去掉了此接口
	 * 获取子ak的最后访问秘钥的时间
	 */
	public void test_getAccessKeyLastUsed() throws Exception{
		String username="test_subuser1";
        String body="Action=CreateAccessKey&UserName="+username;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String akId=AssertCreateAccessKey(resultPair.second(), username, "Active");  
        
        body="Action=GetAccessKeyLastUsed&AccessKeyId="+akId;
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair2.first().intValue());
        AssertGetAccessKeyLastUsed(resultPair2.second(), username,"N/A");
	}
	
	@Ignore
	/*
	 * 获取子ak的最后访问秘钥的时间
	 */
	public void test_getAccessKeyLastUsed_UserChangePasswd() throws Exception{
		String userName="test_subuser31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String userId=AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		
		// 插入数据库aksk
		String ak="yx1234567890123456";
		String sk="lalalal";
		AkSkMeta aksk = new AkSkMeta(owner.getId());
		aksk.isRoot = 0;
		aksk.userId = userId;
		aksk.userName = userName;
		aksk.accessKey=ak;
		aksk.setSecretKey(sk);
		metaClient.akskInsert(aksk);
		User user1 = new User();
		user1.accountId = "3fdmxmc3pqvmp";
		user1.userName = userName;
		user1.accessKeys = new ArrayList<>();
		user1.accessKeys.add(aksk.accessKey);       
		HBaseUtils.put(user1);
		
		body="Action=ChangePassword&UserName="+userName+"&OldPassword=a12345678&NewPassword=cdef1234";
		Pair<Integer, String> changePasswd=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
		assertEquals(200, changePasswd.first().intValue());
        
        body="Action=GetAccessKeyLastUsed&AccessKeyId="+ak;
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair2.first().intValue());
        AssertGetAccessKeyLastUsed(resultPair2.second(), userName,"iam");
	}
	
	@Test
	/*
	 * list 子用户ak
	 */
	public void test_listAccessKey_UserExist() throws Exception{
		URL url = new URL(OOS_IAM_DOMAIN);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        
        String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                url, "POST", "sts", regionName);
        headers.put("Authorization", authorization);
        
        String body="Action=ListAccessKey&UserName=test_subuser1";
        
        HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
        OutputStream out = connection.getOutputStream();
        out.write(body.getBytes());
        out.flush();
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        out.close();        
        if (connection != null) {
            connection.disconnect();
        }
	}
	
	/**
	 * GetSessionToken
	 * **/
	@Test
	public void test_GetSessionToken()throws Exception{
		String body="Action=GetSessionToken&DurationSeconds=7200";
		Pair<Integer, String> response=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, response.first().intValue());
		String msg=response.second();
		System.out.println(msg);
		JSONObject result = ParseXmlToJson1(msg,"GetSessionToken");
		assertNotNull(result.get("SessionToken"));
		assertNotNull(result.get("AccessKeyId"));
		assertNotNull(result.get("SecretAccessKey"));
		assertNotNull(result.get("Expiration"));
		
	}
	//时间为15min
	@Test
	public void test_GetSessionToken_DurationSeconds()throws Exception{
		String body="Action=GetSessionToken&DurationSeconds=900";
		Pair<Integer, String> response=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, response.first().intValue());
		String msg=response.second();
		System.out.println(msg);
		JSONObject result = ParseXmlToJson1(msg,"GetSessionToken");
		assertNotNull(result.get("SessionToken"));
		assertNotNull(result.get("AccessKeyId"));
		assertNotNull(result.get("SecretAccessKey"));
		assertNotNull(result.get("Expiration"));
		
	}
	//时间为36h
	@Test
	public void test_GetSessionToken_DurationSeconds2()throws Exception{
		String body="Action=GetSessionToken&DurationSeconds=129600";
		Pair<Integer, String> response=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, response.first().intValue());
		String msg=response.second();
		System.out.println(msg);
		JSONObject result = ParseXmlToJson1(msg,"GetSessionToken");
		assertNotNull(result.get("SessionToken"));
		assertNotNull(result.get("AccessKeyId"));
		assertNotNull(result.get("SecretAccessKey"));
		assertNotNull(result.get("Expiration"));
		
	}
	
	/**
	 * DurationSeconds参数错误，取值范围：15min-36h，设置时间为15*60-1
	 * **/
	@Test
	public void test_GetSessionToken_InvalidDurationSeconds1()throws Exception{
		String body="Action=GetSessionToken&DurationSeconds=899";
		Pair<Integer, String> response=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, response.first().intValue());
		String msg=response.second();
		System.out.println(msg);
		JSONObject error= IAMTestUtils.ParseErrorToJson(msg);
		assertEquals("InvalidDurationSeconds",error.get("Code"));
		
	}
	/**
	 * DurationSeconds参数错误，取值范围：15min-36h，设置时间为36*3600+1
	 * **/
	@Test
	public void test_GetSessionToken_InvalidDurationSeconds2()throws Exception{
		String body="Action=GetSessionToken&DurationSeconds=129601";
		Pair<Integer, String> response=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, response.first().intValue());
		String msg=response.second();
		System.out.println(msg);
		JSONObject error= IAMTestUtils.ParseErrorToJson(msg);
		assertEquals("InvalidDurationSeconds",error.get("Code"));
		
	}
	
	/**
	 * 参数缺失
	 * */
	@Test
	public void test_GetSessionToken_DurationSecond()throws Exception{
		String body="Action=GetSessionToken";
		Pair<Integer, String> response=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, response.first().intValue());
		String msg=response.second();
		System.out.println(msg);
		JSONObject error= IAMTestUtils.ParseErrorToJson(msg);
		assertEquals("InvalidDurationSeconds",error.get("Code"));
		
	}
	/**
	 * DurationSecond为空字符串
	 * */
	@Test
	public void test_GetSessionToken_InvalidDurationSecond()throws Exception{
		String body="Action=GetSessionToken&DurationSeconds=";
		Pair<Integer, String> response=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, response.first().intValue());
		String msg=response.second();
		System.out.println(msg);
		JSONObject error= IAMTestUtils.ParseErrorToJson(msg);
		assertEquals("MalformedInput",error.get("Code"));
		
	}
	/**子用户无权限获取**/
	@Test
	public void test_GetSessionToken_user_deny()throws Exception{
		//创建子用户
		String username = "createuserfortestgetsessionToken";
		String userbody="Action=CreateUser&Version=2010-05-08&UserName="+username;
		Pair<Integer, String> createuserresponse=IAMTestUtils.invokeHttpsRequest(userbody, accessKey, secretKey);
		assertEquals(200, createuserresponse.first().intValue());
		String akbody="Action=CreateAccessKey&UserName="+username;
		Pair<Integer, String> createakresponse=IAMTestUtils.invokeHttpsRequest(akbody, accessKey, secretKey);
		assertEquals(200, createakresponse.first().intValue());
		JSONObject result = ParseXmlToJson1(createakresponse.second(),"CreateAccessKey");
		String ak=result.getString("AccessKeyId");
		String sk=result.getString("SecretAccessKey");
		String body="Action=GetSessionToken&DurationSeconds=7200";
		Pair<Integer, String> response=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
		assertEquals(403, response.first().intValue());
		String msg=response.second();
		JSONObject error=IAMTestUtils.ParseErrorToJson(msg);
		assertEquals("AccessDenied",error.get("Code"));
		
		//删除aksk，删除用户
		String delbody="Action=DeleteAccessKey&UserName="+username+"&AccessKeyId="+ak;
        Pair<Integer, String> delete=IAMTestUtils.invokeHttpsRequest(delbody, accessKey, secretKey);
		assertEquals(200, delete.first().intValue());
		body="Action=DeleteUser&UserName="+username;
		Pair<Integer, String> deleteresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, deleteresult.first().intValue());
		
	}

	
	public static JSONObject ParseXmlToJson1(String xml, String actions) {
		
		try {
		
			StringReader sr = new StringReader(xml);
	        InputSource is = new InputSource(sr);
	        Document doc = (new SAXBuilder()).build(is);
	        Element root = null ;
	        JSONObject jObject= new JSONObject();
	        if(actions.equals("GetSessionToken"))
	        	root = doc.getRootElement().getChild("GetSessionTokenResult").getChild("Credentials");
	        if(actions.equals("CreateAccessKey"))
	        	root = doc.getRootElement().getChild("CreateAccessKeyResult").getChild("AccessKey");		        		        
	        List<Element> result=root.getChildren();
	        System.out.println(result);
	        Iterator<Element> iterator=result.iterator();
	        
	        while(iterator.hasNext()){
	        	Element root2 = iterator.next();
	        	
	        	String key=root2.getName();
	        	String value=root2.getValue();
	        	
	        	jObject.put(key, value);
	        	
	        }

	        return jObject;
	        
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
        return null;
        
	}	
	
	
	
	public String AssertCreateAccessKey(String xml,String username,String status) {
		try {
			StringReader sr = new StringReader(xml);
	        InputSource is = new InputSource(sr);
	        Document doc = (new SAXBuilder()).build(is);
	        Element root = doc.getRootElement();
	        
	        Element createAKResultElement=root.getChild("CreateAccessKeyResult");
	        Element AkElement=createAKResultElement.getChild("AccessKey");
	        assertEquals(username, AkElement.getChild("UserName").getValue());
	        assertEquals(status, AkElement.getChild("Status").getValue());
	        String ak=AkElement.getChild("AccessKeyId").getValue();
	        System.out.println(ak);
	        System.out.println(AkElement.getChild("SecretAccessKey").getValue());
	        System.out.println(AkElement.getChild("CreateDate").getValue());
	        
	        return ak;
		} catch (Exception e) {
			// TODO: handle exception
		}
		return null;
	}
	
	public String AssertListAccessKey(String xml,String username,boolean truncated,List<Pair<String, String>>aks) {
		String marker="";
		try {
			StringReader sr = new StringReader(xml);
	        InputSource is = new InputSource(sr);
	        Document doc = (new SAXBuilder()).build(is);
	        Element root = doc.getRootElement();
	        
	        Element listAKResultElement=root.getChild("ListAccessKeysResult");
	        Element AkMetaElement=listAKResultElement.getChild("AccessKeyMetadata");
	        assertEquals(username, listAKResultElement.getChild("UserName").getValue());
	        assertEquals(String.valueOf(truncated), listAKResultElement.getChild("IsTruncated").getValue());
	        
	        if (truncated) {
	        	marker=listAKResultElement.getChild("Marker").getValue();
			}
	        if (aks!=null&&aks.size()>0) {
	        	List<Element> memberElements=AkMetaElement.getChildren("member");
	        	for (int i = 0; i < aks.size(); i++) {
	        		Pair<String, String> pair= aks.get(i);
	        		assertEquals(pair.first(), memberElements.get(i).getChild("AccessKeyId").getValue());
	                assertEquals(pair.second(), memberElements.get(i).getChild("Status").getValue());
	                System.out.println("CreateDate="+memberElements.get(i).getChild("CreateDate").getValue());
				}	
			}

		} catch (Exception e) {
			// TODO: handle exception
		}
		return marker;
	}

	public void AssertGetAccessKeyLastUsed(String xml,String username,String serviceName) {
		try {
			StringReader sr = new StringReader(xml);
	        InputSource is = new InputSource(sr);
	        Document doc = (new SAXBuilder()).build(is);
	        Element root = doc.getRootElement();
	        
	        Element getAKLastUsedElement=root.getChild("GetAccessKeyLastUsedResult");
	        Element lastUsed=getAKLastUsedElement.getChild("AccessKeyLastUsed");
	        assertEquals(username, lastUsed.getChild("UserName").getValue());
	        String ServiceName = lastUsed.getChild("ServiceName").getValue();
	        assertEquals(serviceName, ServiceName);
	        if (ServiceName!="N/A") {
	        	System.out.println("LastUsedDate="+lastUsed.getChild("LastUsedDate").getValue());
			}
			
		} catch (Exception e) {
			// TODO: handle exception
		}
	}

	public String AssertCreateUserResult(String xml,String userName,List<Pair<String,String>> tags) {
		try {
			StringReader sr = new StringReader(xml);
	        InputSource is = new InputSource(sr);
	        Document doc = (new SAXBuilder()).build(is);
	        Element root = doc.getRootElement();
	        
	        Element createUserResultElement=root.getChild("CreateUserResult");
	        Element UserElement=createUserResultElement.getChild("User");
	        
	        String userId=UserElement.getChild("UserId").getValue();
	        System.out.println(userId);
	        assertEquals(userName, UserElement.getChild("UserName").getValue());
	       
	        if (tags!=null&&tags.size()>0) {
	        	@SuppressWarnings("unchecked")
				List<Element> memberElements=UserElement.getChild("Tags").getChildren("member");
	        	for (int i = 0; i < tags.size(); i++) {
	        		Pair<String, String> pair= tags.get(i);
	        		assertEquals(pair.first(), memberElements.get(i).getChild("Key").getValue());
	                assertEquals(pair.second(), memberElements.get(i).getChild("Value").getValue());
				}	
				System.out.println("verify tags");
			}
	        
	        System.out.println(UserElement.getChild("CreateDate").getValue());
	        System.out.println(UserElement.getChild("Arn").getValue());
	        
	        return userId;
		} catch (Exception e) {
			// TODO: handle exception
		}
		
		return null;
  
	}
}
