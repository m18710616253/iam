package cn.ctyun.oos.iam.test.iamaccesscontrol;

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import org.eclipse.jetty.util.UrlEncoded;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.JDOMException;
import org.jdom.input.SAXBuilder;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xml.sax.InputSource;

import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.AccessKeyResultUtilsDev;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.Condition;
//import cn.ctyun.oos.iam.accesscontroller.entity.Statement;
//import cn.ctyun.oos.iam.accesscontroller.entity.Statement.Effect;
//import cn.ctyun.oos.iam.accesscontroller.entity.condition.Condition;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.server.result.AccessKeyResult;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;
import common.tuple.Pair;

public class AccessKeyActionAccessTest {

	public static final String OOS_IAM_DOMAIN="https://oos-cd-iam.ctyunapi.cn:9460/";
	public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
	public static final String regionName="cd";
	
	private static String ownerName = "root_user@test.com";
	public static final String accessKey="userak";
	public static final String secretKey="usersk";
	
	public static final String user1Name="ak_test_1";
	public static final String user2Name="ak_test_2";
	public static final String user3Name="user_3";
	public static final String user1accessKey1="abcdefghijklmnop";
	public static final String user1secretKey1="cccccccccccccccc";
	public static final String user1accessKey2="1234567890123456";
	public static final String user1secretKey2="user1secretKey2lllll";
	public static final String user2accessKey="qrstuvwxyz0000000";
	public static final String user2secretKey="bbbbbbbbbbbbbbbbbb";
	public static final String user3accessKey="abcdefgh12345678";
	public static final String user3secretKey="3333333333333333";
	
	public static final String testUser1="test_User_01";
	public static final String testUser2="test_User_02";
	
	public static final String policyName="AccessKeyPolicy";
	
	public static String accountId="3rmoqzn03g6ga";
	public static String mygroupName="mygroup";
	
	
	
	public static OwnerMeta owner = new OwnerMeta(ownerName);
    public static MetaClient metaClient = MetaClient.getGlobalClient();
    
    
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		IAMTestUtils.TrancateTable("oos-aksk");
		IAMTestUtils.TrancateTable("iam-user");
		IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
		IAMTestUtils.TrancateTable(IAMTestUtils.iamGroupTable);
		
		// 创建根用户
		owner.email=ownerName;
		owner.setPwd("123456");
		owner.maxAKNum=10;
		owner.displayName="测试根用户";
		owner.bucketCeilingNum=10;
		metaClient.ownerInsertForTest(owner);
		
		AkSkMeta aksk=new AkSkMeta(owner.getId());
        aksk.accessKey=accessKey;
        aksk.setSecretKey(secretKey);
        aksk.isPrimary=1;
        metaClient.akskInsert(aksk);
        
        //创建用户ak_test_1
		String UserName1=user1Name;
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("email");
		tag.second("test1@oos.com");
		
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName1+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		String userId1=AssertCreateUserResult(resultPair.second(), UserName1, tags);

		// 插入数据库aksk
		AkSkMeta aksk1 = new AkSkMeta(owner.getId());
        aksk1.isRoot = 0;
        aksk1.userId = userId1;
        aksk1.userName = UserName1;
        aksk1.accessKey=user1accessKey1;
        aksk1.setSecretKey(user1secretKey1);
        metaClient.akskInsert(aksk1);
        User user1 = new User();
        user1.accountId = accountId;
        user1.userName = UserName1;
        user1.accessKeys = new ArrayList<>();
        user1.accessKeys.add(aksk1.accessKey); 
        aksk1.accessKey=user1accessKey2;
        aksk1.setSecretKey(user1secretKey2);
        metaClient.akskInsert(aksk1);
        user1.accessKeys.add(aksk1.accessKey);
        HBaseUtils.put(user1);
		
        //创建用户ak_test_2
		String UserName2=user2Name;
		body="Action=CreateUser&Version=2010-05-08&UserName="+UserName2;
		Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair2.first().intValue());
		String userId2=AssertCreateUserResult(resultPair2.second(), UserName2, null);
		
		//插入aksk
		AkSkMeta aksk2 = new AkSkMeta(owner.getId());
        aksk2.isRoot = 0;
        aksk2.userId = userId2;
        aksk2.userName = UserName2;
        aksk2.accessKey=user2accessKey;
        aksk2.setSecretKey(user2secretKey);
        metaClient.akskInsert(aksk2);
        User user2 = new User();
        user2.accountId = accountId;
        user2.accessKeys = new ArrayList<>();
        user2.userName=UserName2;
        user2.accessKeys.add(aksk2.accessKey);
        HBaseUtils.put(user2);
		
        //创建用户ak_test_3
		String UserName3=user3Name;
		body="Action=CreateUser&Version=2010-05-08&UserName="+UserName3;
		Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair3.first().intValue());
		String userId3=AssertCreateUserResult(resultPair3.second(), UserName3, null);
		
		//插入aksk
		AkSkMeta aksk3 = new AkSkMeta(owner.getId());
		aksk3.isRoot = 0;
		aksk3.userId = userId3;
		aksk3.userName = UserName3;
		aksk3.accessKey=user3accessKey;
		aksk3.setSecretKey(user3secretKey);
        metaClient.akskInsert(aksk3);
        
        User user3 = new User();
        user3.accountId = accountId;
        user3.userName = UserName1;
        user3.accessKeys = new ArrayList<>();
        user3.userName=UserName3;
        user3.accessKeys.add(aksk3.accessKey);
        HBaseUtils.put(user3);
        
        //创建组
	    String groupName="mygroup";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey,groupName,200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, user1Name,200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, user3Name,200);
        
        //创建testUser01用户
		body="Action=CreateUser&Version=2010-05-08&UserName="+testUser1;
		Pair<Integer, String> resultPair_test01=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair_test01.first().intValue());
		
		//创建testUser02用户
		body="Action=CreateUser&Version=2010-05-08&UserName="+testUser2;
		Pair<Integer, String> resultPair_test02=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair_test02.first().intValue());
        
	}

	@Before
	public void setUp() throws Exception {
		IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
		IAMTestUtils.TrancateTable(IAMTestUtils.iamGroupTable);
		IAMTestUtils.TrancateTable(IAMTestUtils.iammfaDeviceTable);
		
		String groupName="mygroup";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey,groupName,200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, user1Name,200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, user3Name,200);
		
	}
	
	//CreateAccessKey接口
	
	@Test
	/*
	 * Allow Action=CreateAccessKey Resource=policy/testUser01
	 * 只允许为testUser01创建ak
	 */
	public void test_CreateAccessKey_Allow_Action_Resource_testUser01() throws JSONException {
		// 创建policy
		String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+testUser1),null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
		
		// 给用户添加policy
		String userName=user1Name;
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
		
		// 验证请求
		//有权限创建成功
		IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1, 200);
		//无权限创建失败
		String user2xmlString=IAMInterfaceTestUtils.CreateAccessKey(user2accessKey, user2secretKey,testUser1,403);
		JSONObject error=IAMTestUtils.ParseErrorToJson(user2xmlString);
        assertEquals("AccessDenied", error.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+" is not authorized to perform: iam:CreateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/test_User_01.", error.get("Message"));
        assertEquals("", error.get("Resource"));
		//无权限创建失败
		String user1bxmlString=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser2,403);
		JSONObject error2=IAMTestUtils.ParseErrorToJson(user1bxmlString);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/test_User_02.", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
	}
	
	@Test
	/*
	 * allow Action=CreateAccessKey, resource=user/*
	 * 可以为所有用户创建ak
	 */
	public void test_CreateAccessKey_Allow_Action_Resource_all() throws JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);

        // 给用户添加policy
        String userName=user1Name;
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 验证请求
        //有权限
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1, 200);
        //无权限
        String user2xmlString=IAMInterfaceTestUtils.CreateAccessKey(user2accessKey, user2secretKey,testUser1,403);
        JSONObject error=IAMTestUtils.ParseErrorToJson(user2xmlString);
        assertEquals("AccessDenied", error.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+" is not authorized to perform: iam:CreateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/test_User_01.", error.get("Message"));
        assertEquals("", error.get("Resource"));
        //有权限
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser2,200);
	}
	
	@Test
	/*
	 * allow Action=CreateAccessKey, resource=*
	 * 可以为所有用户创建ak
	 */
	public void test_CreateAccessKey_Allow_Action_all2() throws JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);

        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        
        // 验证请求
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1, 200);

        String user2xmlString=IAMInterfaceTestUtils.CreateAccessKey(user2accessKey, user2secretKey,testUser1,403);
        JSONObject error=IAMTestUtils.ParseErrorToJson(user2xmlString);
        assertEquals("AccessDenied", error.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+" is not authorized to perform: iam:CreateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+testUser1+".", error.get("Message"));
        assertEquals("", error.get("Resource"));
        
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser2,200);
	}
	
	@Test
	/*
	 * allow Action=CreateAccessKey, resource=group/*
	 * 资源和请求的action不匹配，policy不生效
	 */
	public void test_CreateAccessKey_Allow_Action_resourceNotMatch() throws JSONException {
	    // 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        // 验证请求
        String user1xmlString=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+testUser1+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user2xmlString=IAMInterfaceTestUtils.CreateAccessKey(user2accessKey, user2secretKey,testUser1,403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user2xmlString);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+" is not authorized to perform: iam:CreateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+testUser1+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
	}
	
	@Test
	/*
	 * allow NotAction=CreateAccessKey, resource=user/test_user_01
	 * 由于资源resource只能匹配除了CreateAccessKey的其他user相关操作
	 */
	public void test_CreateAccessKey_Allow_NotAction_test_user_01() throws JSONException, IOException {
	    // 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+testUser1),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        // 给testUser1创建ak 
        String user1xmlString=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+testUser1+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        //验证除了createAccessKey，其他跟user相关的操作都可以
        List<String> excludes=new ArrayList<String>();
        excludes.add("CreateAccessKey");
        List<Pair<String,String>> tags=new ArrayList<Pair<String,String>>();
        Pair<String,String> tag=new Pair<String,String>();
        tag.first("key");
        tag.second("value");
        tags.add(tag);
        IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, testUser1, tags, policyName, policyString, accountId);
        
        //验证和test_user_01资源不匹配的全都不通过
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user1accessKey1, user1secretKey1, testUser2, tags, policyName, policyString, accountId);
        
        //验证跟mfa相关的都不允许
        IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user1accessKey1, user1secretKey1, accountId, "MFADevice");
        
        //验证跟group相关的都不允许
        IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey, user1accessKey1, user1secretKey1, "newGroup", testUser1, accountId, policyName, policyString);
        
        //跟policy相关的都不允许
        IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey1, user1secretKey1, policyName, policyString, accountId);
        
        // 验证 其他资源不匹配接口都不允许
        IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}
	
	@Test
	/*
	 * allow NotAction=CreateAccessKey, resource=user/*
	 * 由于资源resource只能匹配除了CreateAccessKey的其他group相关操作
	 */
	public void test_CreateAccessKey_Allow_NotAction_all() throws JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        //创建ak
        String user1xmlString=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+testUser1+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        // 验证 除了CreateAccessKey其他跟user resource相关的方法都允许
        List<String> excludes=new ArrayList<String>();
        excludes.add("CreateAccessKey");
        List<Pair<String,String>> tags=new ArrayList<Pair<String,String>>();
        Pair<String,String> tag=new Pair<String,String>();
        tag.first("key");
        tag.second("value");
        tags.add(tag);
        IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, "newUser", tags, policyName, policyString, accountId);
        
        // 验证 跟MFA资源相关接口都不允许
        IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1, accountId, "mfa1");
        // 验证 跟policy资源相关接口都不允许
        IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1, policyName, policyString, accountId);
        // 验证 跟group资源相关接口都不允许
        IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "newGroup", "user", accountId, policyName, policyString);
        // 验证 其他资源不匹配接口都不允许
        IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}
	
	@Test
	/*
	 * allow NotAction=CreateAccessKey, resource=*
	 * 可匹配除了CreateAccessKey的所有其他操作
	 */
	public void test_CreateAccessKey_Allow_NotAction_all2() throws JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        //创建ak
        String user1xmlString=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+testUser1+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
     // 验证 除了CreateAccessKey所有方法都允許
        List<String> excludes=new ArrayList<String>();
        excludes.add("CreateAccessKey");

        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        String policyName2="policy2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        
        IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey,excludes, user1accessKey1, user1secretKey1, "test_7", tags, policyName2, policyString2, accountId,"mygroup","mfa2");
	}
	
	@Test
	/*
	 * allow action=createAccessKey notResource=user/test_User_01
	 * 允许为除了test_User_01之外的其他用户创建ak
	 */
	public void test_CreateAccessKey_Allow_Action_NotResource_test_User_01() throws JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+testUser1),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        //创建ak
        String user1xmlString=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+testUser1+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser2,200);
	}
	
	@Test
	/*
	 * allow action=createAccessKey NotResource=user/*
	 * 不允许为任何用户创建ak
	 */
	public void test_CreateAccessKey_Allow_Action_NotResource_all() throws JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        //创建ak
        String user1xmlString=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+testUser1+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString1=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser2,403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+testUser2+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
	}
	
	@Test
	/*
	 * allow action=createAccessKey NotResource=*
	 * 不允许为任何用户创建ak
	 */
	public void test_CreateAccessKey_Allow_Action_NotResource_all2() throws JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        //创建ak
        String user1xmlString=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+testUser1+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString1=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser2,403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+testUser2+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
	}
	
	@Test
	/*
	 * allow notaction=createAccessKey notResource=user/ak_test_02
	 */
	public void test_CreateAccessKey_Allow_NotAction_NotResource_ak_test_02() throws JSONException, IOException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user2Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName,200);
        
        //创建ak
        String user1xmlString=IAMInterfaceTestUtils.CreateAccessKey(user2accessKey, user2secretKey,user2Name,403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+" is not authorized to perform: iam:CreateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString1=IAMInterfaceTestUtils.CreateAccessKey(user2accessKey, user2secretKey,testUser2,403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+" is not authorized to perform: iam:CreateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+testUser2+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
        
        // 资源为user/ak_test_02的是都不允许
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user2accessKey, user2secretKey, user2Name, tags, policyName, policyString, accountId);
        
        // 验证 跟MFA资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null,user2accessKey, user2secretKey, accountId, "mfa1");
        // 验证 跟policy资源相关接口都允许
        String policyName1="testPolicy";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+testUser1),null);
        IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null,user2accessKey, user2secretKey, policyName1, policyString1, accountId);
         //验证 跟group资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceGroupALL(accessKey, secretKey, null, user2accessKey, user2secretKey, "newGroup", "newUser", accountId, policyName, policyString);
        // 验证 其他资源不匹配接口都允许
        IAMInterfaceTestUtils.AllowActionResourceOthers(user2accessKey, user2secretKey,null);
	}
	
	@Test
	/*
	 * allow notaction=createAccessKey notResource=user/*
	 */
	public void test_CreateAccessKey_Allow_NotAction_NotResource_all() throws JSONException, IOException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        //创建ak
        String user1xmlString=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+testUser1+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString1=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser2,403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+testUser2+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
        
        //跟user相关的都拒绝
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "newUser", tags, policyName, policyString, accountId);
        
        // 验证 跟MFA资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null,user1accessKey1, user1secretKey1, accountId, "mfa1");
        // 验证 跟policy资源相关接口都允许
        String policyName1="testPolicy";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null,user1accessKey1, user1secretKey1, policyName1, policyString1, accountId);
         //验证 跟group资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceGroupALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1, "newGroup", "newUser", accountId, policyName, policyString);
    
        // 验证 其他资源不匹配接口都允许
        IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1,null);
	}
	
	@Test
	/*
	 * allow notaction=createAccessKey notResource=*
	 */
	public void test_CreateAccessKey_Allow_NotAction_NotResource_all2() throws JSONException, IOException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        //创建ak
        String user1xmlString=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+testUser1+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString1=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser2,403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+testUser2+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
        
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        IAMInterfaceTestUtils.DenyActionResourceALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "test_21", tags, policyName, policyString, accountId,"newGroup","mfa3");
	}
	
	@Test
	/*
	 * deny action=CreateAccessKey resource=user/test_User_01
	 */
	public void test_CreateAccessKey_Deny_Action_Resource_test_User_01() throws JSONException, JDOMException, IOException {
		// 添加一条deny策略
		String denypolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+testUser1),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denypolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denypolicyName,200);
        
        //创建ak
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,403);
        
        // 添加一条allow策略
        String allowpolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey","iam:DeleteAccessKey","iam:GetAccessKeyLastUsed","iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowpolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowpolicyName,200);
        
        //创建ak
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,403);
        AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(accessKey, secretKey, testUser1, 200));
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 200);
	}
	
	@Test
	/*
	 * deny action=CreateAccessKey resource=user/*
	 */
	public void test_CreateAccessKey_Deny_Action_Resource_all() throws JSONException, JDOMException, IOException {
		// 添加一条deny策略
		String denypolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denypolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denypolicyName,200);
        
        //创建ak
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,403);
        
        // 添加一条allow策略
        String allowpolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey","iam:DeleteAccessKey","iam:GetAccessKeyLastUsed","iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowpolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowpolicyName,200);
        
        //创建ak
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,403);
        AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(accessKey, secretKey, testUser1, 200));
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 200);
	}
	
	@Test
	/*
	 * deny action=CreateAccessKey resource=*
	 */
	public void test_CreateAccessKey_Deny_Action_Resource_all2() throws JSONException, JDOMException, IOException {
		// 添加一条deny策略
		String denypolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denypolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denypolicyName,200);
        
        //创建ak
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,403);
        
        // 添加一条allow策略
        String allowpolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey","iam:DeleteAccessKey","iam:GetAccessKeyLastUsed","iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowpolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowpolicyName,200);
        
        //创建ak
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,403);
        AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(accessKey, secretKey, testUser1, 200));
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 200);
	}
	
	@Test
	/*
	 * deny action=createaccesskey resource=group/*
	 */
	public void test_CreateAccessKey_Deny_Action_Resource_resourceNotMatch() throws JSONException, JDOMException, IOException {
		// 添加一条deny策略
		String denypolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denypolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denypolicyName,200);
        
        //创建ak
        String user1xmlString=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+testUser1+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        // 添加一条allow策略
        String allowpolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey","iam:DeleteAccessKey","iam:GetAccessKeyLastUsed","iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowpolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowpolicyName,200);
        
        //创建ak
        AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,200));
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 200);
	}
	
	@Test
	/*
	 * deny action=CreateAccessKey notresource=user/test_User_01
	 */
	public void test_CreateAccessKey_Deny_Action_NotResource_test_User_01() throws JSONException, JDOMException, IOException {
		// 添加一条deny策略
		String denypolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+testUser1),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denypolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denypolicyName,200);
        
        //创建ak
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,403);
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser2,403);
        
        // 添加一条allow策略
        String allowpolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey","iam:DeleteAccessKey","iam:GetAccessKeyLastUsed","iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowpolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowpolicyName,200);
        
        //创建ak
        AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,200));
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 200);
        
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser2,403);
        AccessKeyResult accessKeyResult1 = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(accessKey, secretKey,testUser2,200));
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult1.accessKeyId, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult1.accessKeyId, testUser2, "Inactive", 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult1.accessKeyId, testUser2, 200);
        
	}
	
	@Test
	/*
	 * deny action=CreateAccessKey notresource=user/*
	 */
	public void test_CreateAccessKey_Deny_Action_NotResource_all() throws JSONException, JDOMException, IOException {
		// 添加一条deny策略
		String denypolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denypolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denypolicyName,200);
        
        //创建ak
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,403);
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser2,403);
        
        // 添加一条allow策略
        String allowpolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey","iam:DeleteAccessKey","iam:GetAccessKeyLastUsed","iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowpolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowpolicyName,200);
        
        //创建ak
        AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,200));
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 200);
        
        AccessKeyResult accessKeyResult1 = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser2,200));
//        AccessKeyResult accessKeyResult1 = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(accessKey, secretKey,testUser2,200));
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult1.accessKeyId, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult1.accessKeyId, testUser2, "Inactive", 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult1.accessKeyId, testUser2, 200);
        
	}
	
	@Test
	/*
	 * deny action=CreateAccessKey notresource=*
	 */
	public void test_CreateAccessKey_Deny_Action_NotResource_all2() throws JSONException, JDOMException, IOException {
		// 添加一条deny策略
		String denypolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denypolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denypolicyName,200);
        
        //创建ak
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,403);
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser2,403);
        
        // 添加一条allow策略
        String allowpolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey","iam:DeleteAccessKey","iam:GetAccessKeyLastUsed","iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowpolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowpolicyName,200);
        
        //创建ak
        AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,200));
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 200);
        
        AccessKeyResult accessKeyResult1 = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser2,200));
//        AccessKeyResult accessKeyResult1 = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(accessKey, secretKey,testUser2,200));
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult1.accessKeyId, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult1.accessKeyId, testUser2, "Inactive", 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult1.accessKeyId, testUser2, 200);
        
	}
	

	/*
	 * Deny NotAction=CreateAccessKey Resource=user/testUser1
	 */
	@Test
	public void test_CreateAccessKey_Deny_NotAction_Resource_testUser1() throws JSONException, JDOMException, IOException  {
		// 添加一条deny策略
		String denypolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:CreateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+testUser1),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denypolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denypolicyName,200);
        
        //创建ak
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,403);
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser2,403);
        
        // 添加一条allow策略
        String allowpolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey","iam:DeleteAccessKey","iam:GetAccessKeyLastUsed","iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowpolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowpolicyName,200);
        
        
        AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,200));
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 403);
        
        AccessKeyResult accessKeyResult1 = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser2,200));
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult1.accessKeyId, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult1.accessKeyId, testUser2, "Inactive", 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult1.accessKeyId, testUser2, 200);
        
	}
	
	/*
	 * Deny NotAction=CreateAccessKey Resource=user/*
	 */
	@Test
	public void test_CreateAccessKey_Deny_NotAction_Resource_all() throws JSONException, JDOMException, IOException  {
		// 添加一条deny策略
		String denypolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:CreateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denypolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denypolicyName,200);
        
        //创建ak
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,403);
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser2,403);
        
        // 添加一条allow策略
        String allowpolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey","iam:DeleteAccessKey","iam:GetAccessKeyLastUsed","iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowpolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowpolicyName,200);
        
        
        AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,200));
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 403);
        
        AccessKeyResult accessKeyResult1 = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser2,200));
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult1.accessKeyId, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult1.accessKeyId, testUser2, "Inactive", 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult1.accessKeyId, testUser2, 403);
        
	}
	
	/*
	 * Deny NotAction=CreateAccessKey Resource=*
	 */
	@Test
	public void test_CreateAccessKey_Deny_NotAction_Resource_all2() throws JSONException, JDOMException, IOException  {
		// 添加一条deny策略
		String denypolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:CreateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denypolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denypolicyName,200);
        
        //创建ak
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,403);
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser2,403);
        
        // 添加一条allow策略
        String allowpolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey","iam:DeleteAccessKey","iam:GetAccessKeyLastUsed","iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowpolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowpolicyName,200);
        
        
        AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,200));
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 403);
        
        AccessKeyResult accessKeyResult1 = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser2,200));
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult1.accessKeyId, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult1.accessKeyId, testUser2, "Inactive", 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult1.accessKeyId, testUser2, 403);
        
	}
	
	/*
	 * Deny NotAction=CreateAccessKey NotResource=user/testUser1
	 */
	@Test
	public void test_CreateAccessKey_Deny_NotAction_NotResource_testUser1() throws JSONException, JDOMException, IOException  {
		// 添加一条deny策略
		String denypolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:CreateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+testUser1),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denypolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denypolicyName,200);
        
        //创建ak
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,403);
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser2,403);
        
        // 添加一条allow策略
        String allowpolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey","iam:DeleteAccessKey","iam:GetAccessKeyLastUsed","iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowpolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowpolicyName,200);
        
        
        AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,200));
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 200);
        
        AccessKeyResult accessKeyResult1 = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser2,200));
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult1.accessKeyId, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult1.accessKeyId, testUser2, "Inactive", 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult1.accessKeyId, testUser2, 403);
        
	}
	
	/*
	 * Deny NotAction=CreateAccessKey NotResource=user/*
	 */
	@Test
	public void test_CreateAccessKey_Deny_NotAction_NotResource_all() throws JSONException, JDOMException, IOException  {
		// 添加一条deny策略
		String denypolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:CreateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denypolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denypolicyName,200);
        
        //创建ak
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,403);
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser2,403);
        
        // 添加一条allow策略
        String allowpolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey","iam:DeleteAccessKey","iam:GetAccessKeyLastUsed","iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowpolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowpolicyName,200);
        
        
        AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,200));
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 200);
        
        AccessKeyResult accessKeyResult1 = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser2,200));
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult1.accessKeyId, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult1.accessKeyId, testUser2, "Inactive", 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult1.accessKeyId, testUser2, 200);
        
	}
	
	/*
	 * Deny NotAction=CreateAccessKey NotResource=*
	 */
	@Test
	public void test_CreateAccessKey_Deny_NotAction_NotResource_all2() throws JSONException, JDOMException, IOException  {
		// 添加一条deny策略
		String denypolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:CreateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denypolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denypolicyName,200);
        
        //创建ak
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,403);
        IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser2,403);
        
        // 添加一条allow策略
        String allowpolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey","iam:DeleteAccessKey","iam:GetAccessKeyLastUsed","iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowpolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowpolicyName,200);
        
        
        AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser1,200));
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 200);
        
        AccessKeyResult accessKeyResult1 = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1,testUser2,200));
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult1.accessKeyId, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult1.accessKeyId, testUser2, "Inactive", 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult1.accessKeyId, testUser2, 200);
        
	}
	
	
	
	//deleteAccessKey接口
	
	@Test
	/*
	 * allow action=deleteAccessKey resource=user/ak_test_1
	 * 只允许删除ak_test_1的ak
	 */
	public void test_DeleteAccessKey_Allow_Action_Resource_ak_test_1() throws JDOMException, IOException, JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user1Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        //删除ak
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2,user1Name,200);
        
        String user1xmlString=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user2accessKey,user2Name,403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:DeleteAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
	}
	
	@Test
	/*
	 * allow action=deleteAccessKey resource=user/*
	 * 允许删除所有用户的ak
	 */
	public void test_DeleteAccessKey_Allow_Action_Resource_all() throws JDOMException, IOException, JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        //删除ak
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2,user1Name,200);
        
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user2accessKey,user2Name,200);
	}
	
	@Test
	/*
	 * allow action=deleteAccessKey resource=*
	 * 允许删除所有用户的ak
	 */
	public void test_DeleteAccessKey_Allow_Action_Resource_all2() throws JDOMException, IOException, JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        //删除ak
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2,user1Name,200);
        
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user2accessKey,user2Name,200);
	}
	
	@Test
	/*
	 * allow action=deleteAccessKey resource=group/*
	 */
	public void test_DeleteAccessKey_Allow_Action_resourceNotMatch() throws JDOMException, IOException, JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        //删除ak
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2,user1Name,403);
        
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user2accessKey,user2Name,403);
	}
	
	@Test
	/*
	 * allow action=deleteAccessKey Notresource=user/ak_test_1
	 * 允许删除除了ak_test_1以外其他用户的ak
	 */
	public void test_DeleteAccessKey_Allow_Action_NotResource_ak_test_1() throws JDOMException, IOException, JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user1Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        //删除ak
        String user1xmlString=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user1accessKey2,user1Name,403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:DeleteAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey,user2Name,200);
	}
	
	@Test
	/*
	 * allow action=deleteAccessKey Notresource=user/*
	 * 不允许删除任何用户的ak
	 */
	public void test_DeleteAccessKey_Allow_Action_NotResource_all() throws JDOMException, IOException, JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        //删除ak
        String user1xmlString=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user1accessKey2,user1Name,403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:DeleteAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString1=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user2accessKey,user2Name,403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:DeleteAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
	}
	
	@Test
	/*
	 * allow action=deleteAccessKey Notresource=*
	 * 不允许删除任何用户的ak
	 */
	public void test_DeleteAccessKey_Allow_Action_NotResource_all2() throws JDOMException, IOException, JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        //删除ak
        String user1xmlString=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user1accessKey2,user1Name,403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:DeleteAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString1=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user2accessKey,user2Name,403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:DeleteAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
	}
	
	@Test
	/*
	 * allow notaction=deleteAccessKey resource=user/ak_test_2
	 * 允许对ak_test_1执行除deleteAccessKey以外的操作
	 */
	public void test_DeleteAccessKey_Allow_NotAction_Resource_ak_test_2() throws JDOMException, IOException, JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:DeleteAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user2Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        //删除ak
        String user1xmlString=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user2accessKey,user2Name,403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:DeleteAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        IAMInterfaceTestUtils.DeleteAccessKey(accessKey, secretKey,user2accessKey,user2Name,200);
        
        //验证除了DeleteAccessKey，其他跟user相关的操作都可以
        List<String> excludes=new ArrayList<String>();
        excludes.add("DeleteAccessKey");
        List<Pair<String,String>> tags=new ArrayList<Pair<String,String>>();
        Pair<String,String> tag=new Pair<String,String>();
        tag.first("key");
        tag.second("value");
        tags.add(tag);
        IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, user2Name, tags, policyName, policyString, accountId);
        
        //验证和ak_test_2资源不匹配的全都不通过
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user1accessKey1, user1secretKey1, "newUser", tags, policyName, policyString, accountId);
        
        //验证跟mfa相关的都不允许
        IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user1accessKey1, user1secretKey1, accountId, "MFADevice");
        
        //验证跟group相关的都不允许
        IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey, user1accessKey1, user1secretKey1, "newGroup", testUser1, accountId, policyName, policyString);
        
        //跟policy相关的都不允许
        IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey1, user1secretKey1, policyName, policyString, accountId);
        
        // 验证 其他资源不匹配接口都不允许
        IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}
	
	@Test
	/*
	 * allow notaction=deleteAccessKey resource=user/*
	 * 可以对任何用户执行除deleteAccessKey之外的操作
	 */
	public void test_DeleteAccessKey_Allow_NotAction_Resource_all() throws JDOMException, IOException, JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:DeleteAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        //删除ak
        String user1xmlString=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user1accessKey2,user1Name,403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:DeleteAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
     // 验证 除了DeleteAccessKey其他跟user resource相关的方法都允许
        List<String> excludes=new ArrayList<String>();
        excludes.add("DeleteAccessKey");
        List<Pair<String,String>> tags=new ArrayList<Pair<String,String>>();
        Pair<String,String> tag=new Pair<String,String>();
        tag.first("key");
        tag.second("value");
        tags.add(tag);
        IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, "newUser", tags, policyName, policyString, accountId);
        
        // 验证 跟MFA资源相关接口都不允许
        IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1, accountId, "mfa1");
        // 验证 跟policy资源相关接口都不允许
        IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1, policyName, policyString, accountId);
        // 验证 跟group资源相关接口都不允许
        IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "newGroup", "user", accountId, policyName, policyString);
        // 验证 其他资源不匹配接口都不允许
        IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
        
	}
	
	@Test
	/*
	 * allow NotAction=DeleteAccessKey, resource=*
	 * 可匹配除了CreateAccessKey的所有其他操作
	 */
	public void test_DeleteAccessKey_Allow_NotAction_all2() throws JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:DeleteAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        //
        String user1xmlString=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user1accessKey2,user1Name,403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:DeleteAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
     // 验证 除了DeleteAccessKey所有方法都允許
        List<String> excludes=new ArrayList<String>();
        excludes.add("DeleteAccessKey");

        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        String policyName2="policy2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        
        IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey,excludes, user1accessKey1, user1secretKey1, "test_7", tags, policyName2, policyString2, accountId,"newGroup","mfa2");
	}
	
	@Test
	/*
	 * allow notaction=deleteAccessKey notresource=user/ak_test_02
	 * 允许对除ak_test_01用户执行除deleteAccessKey之外的操作
	 */
	public void test_DeleteAccessKey_Allow_NotAction_NotResource_ak_test_02() throws JDOMException, IOException, JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:DeleteAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user2Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName,200);
        
        //删除ak
        String user1xmlString=IAMInterfaceTestUtils.DeleteAccessKey(user2accessKey, user2secretKey,user1accessKey1,user1Name,403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+" is not authorized to perform: iam:DeleteAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString2=IAMInterfaceTestUtils.DeleteAccessKey(user2accessKey, user2secretKey,user2accessKey,user2Name,403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString2);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+" is not authorized to perform: iam:DeleteAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
        
     // 资源为user/ak_test_02的是都不允许
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user2accessKey, user2secretKey, user2Name, tags, policyName, policyString, accountId);
        
        // 验证 跟MFA资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null,user2accessKey, user2secretKey, accountId, "mfa1");
        // 验证 跟policy资源相关接口都允许
        String policyName1="testPolicy";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+testUser1),null);
        IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null,user2accessKey, user2secretKey, policyName1, policyString1, accountId);
         //验证 跟group资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceGroupALL(accessKey, secretKey, null, user2accessKey, user2secretKey, "newGroup", "newUser", accountId, policyName, policyString);
        // 验证 其他资源不匹配接口都允许
        IAMInterfaceTestUtils.AllowActionResourceOthers(user2accessKey, user2secretKey,null);
	}
	
	@Test
	/*
	 * allow notaction=deleteAccessKey notresource=user/*
	 */
	public void test_DeleteAccessKey_Allow_NotAction_NotResource_all() throws JDOMException, IOException, JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:DeleteAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        //删除ak
        String user1xmlString=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user1accessKey2,user1Name,403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:DeleteAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString2=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user2accessKey,user2Name,403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString2);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:DeleteAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
        
      //跟user相关的都拒绝
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "newUser", tags, policyName, policyString, accountId);
        
        // 验证 跟MFA资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null,user1accessKey1, user1secretKey1, accountId, "mfa1");
        // 验证 跟policy资源相关接口都允许
        String policyName1="testPolicy";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null,user1accessKey1, user1secretKey1, policyName1, policyString1, accountId);
         //验证 跟group资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceGroupALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1, "newGroup", "newUser", accountId, policyName, policyString);
    
        // 验证 其他资源不匹配接口都允许
        IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1,null);
	}
	
	@Test
	/*
	 * allow notaction=deleteAccessKey notresource=*
	 */
	public void test_DeleteAccessKey_Allow_NotAction_NotResource_all2() throws JDOMException, IOException, JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:DeleteAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        //删除ak
        String user1xmlString=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user1accessKey2,user1Name,403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:DeleteAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString2=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user2accessKey,user2Name,403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString2);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:DeleteAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
        
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        IAMInterfaceTestUtils.DenyActionResourceALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "test_21", tags, policyName, policyString, accountId,"newGroup","mfa3");
	}
	
	@Test
	/*
	 * deny action=DeleteAccessKey resource=user/ak_test_01
	 */
	public void test_DeleteAccessKey_Deny_Action_Resource_ak_test_01() throws JDOMException, IOException, JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:DeleteAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user1Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200);
        
        //显示拒绝
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user1accessKey2,user1Name,403);
        
        // 创建policy
     	String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteAccessKey","iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 403);
        
	}
	
	@Test
	/*
	 * deny action=DeleteAccessKey resource=user/*
	 */
	public void test_DeleteAccessKey_Deny_Action_Resource_all() throws JDOMException, IOException, JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:DeleteAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200);
        
        //显示拒绝
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user1accessKey2,user1Name,403);
        
        // 创建policy
     	String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteAccessKey","iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 403);
        
	}
	
	@Test
	/*
	 * deny action=DeleteAccessKey resource=*
	 */
	public void test_DeleteAccessKey_Deny_Action_Resource_all2() throws JDOMException, IOException, JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:DeleteAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200);
        
        //显示拒绝
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user1accessKey2,user1Name,403);
        
        // 创建policy
     	String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteAccessKey","iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 403);
        
	}
	
	@Test
	/*
	 * deny action=DeleteAccessKey resource=group/*
	 */
	public void test_DeleteAccessKey_Deny_Action_Resource_resourceNotMatch() throws JDOMException, IOException, JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:DeleteAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200);
        
        //隐式拒绝
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user1accessKey2,user1Name,403);
        
        // 创建policy
     	String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteAccessKey","iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
	}
	
	@Test
	/*
	 * deny action=DeleteAccessKey notresource=user/ak_test_01
	 */
	public void test_DeleteAccessKey_Deny_Action_NotResource_ak_test_01() throws JDOMException, IOException, JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:DeleteAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user1Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200);
        
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user1accessKey2,user1Name,403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user2accessKey,user2Name,403);
        
        // 创建policy
     	String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteAccessKey","iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 403);
        
	}
	
	@Test
	/*
	 * deny action=DeleteAccessKey notresource=user/*
	 */
	public void test_DeleteAccessKey_Deny_Action_NotResource_all() throws JDOMException, IOException, JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:DeleteAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200);
        
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user1accessKey2,user1Name,403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user2accessKey,user2Name,403);
        
        // 创建policy
     	String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteAccessKey","iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 200);
        
	}
	
	@Test
	/*
	 * deny action=DeleteAccessKey notresource=*
	 */
	public void test_DeleteAccessKey_Deny_Action_NotResource_all2() throws JDOMException, IOException, JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:DeleteAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200);
        
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user1accessKey2,user1Name,403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user2accessKey,user2Name,403);
        
        // 创建policy
     	String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteAccessKey","iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 200);
        
	}
	
	@Test
	/*
	 * deny Notaction=DeleteAccessKey resource=user/ak_test_01
	 */
	public void test_DeleteAccessKey_Deny_NotAction_Resource_ak_test_01() throws JDOMException, IOException, JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:DeleteAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user1Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200);
        
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user1accessKey2,user1Name,403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user2accessKey,user2Name,403);
        
        // 创建policy
     	String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteAccessKey","iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 200);
        
	}
	
	@Test
	/*
	 * deny Notaction=DeleteAccessKey resource=user/*
	 */
	public void test_DeleteAccessKey_Deny_NotAction_Resource_all() throws JDOMException, IOException, JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:DeleteAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200);
        
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user1accessKey2,user1Name,403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user2accessKey,user2Name,403);
        
        // 创建policy
     	String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteAccessKey","iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 200);
        
	}
	
	@Test
	/*
	 * deny Notaction=DeleteAccessKey resource=*
	 */
	public void test_DeleteAccessKey_Deny_NotAction_Resource_all2() throws JDOMException, IOException, JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:DeleteAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200);
        
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user1accessKey2,user1Name,403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user2accessKey,user2Name,403);
        
        // 创建policy
     	String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteAccessKey","iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 200);
        
	}
	
	@Test
	/*
	 * deny Notaction=DeleteAccessKey Notresource=user/ak_test_01
	 */
	public void test_DeleteAccessKey_Deny_NotAction_NotResource_ak_test_01() throws JDOMException, IOException, JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:DeleteAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user1Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200);
        
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user1accessKey2,user1Name,403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user2accessKey,user2Name,403);
        
        // 创建policy
     	String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteAccessKey","iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 200);
        
	}
	
	@Test
	/*
	 * deny Notaction=DeleteAccessKey Notresource=user/*
	 */
	public void test_DeleteAccessKey_Deny_NotAction_NotResource_all() throws JDOMException, IOException, JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:DeleteAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200);
        
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user1accessKey2,user1Name,403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user2accessKey,user2Name,403);
        
        // 创建policy
     	String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteAccessKey","iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 200);
        
	}
	
	@Test
	/*
	 * deny Notaction=DeleteAccessKey Notresource=*
	 */
	public void test_DeleteAccessKey_Deny_NotAction_NotResource_all2() throws JDOMException, IOException, JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:DeleteAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200);
        
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user1accessKey2,user1Name,403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1,user2accessKey,user2Name,403);
        
        // 创建policy
     	String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteAccessKey","iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 200);
        
	}

	
	//UpdateAccessKey接口
	
	@Test
	/*
	 * allow action=updateAccessKey resource=user/ak_test_01
	 */
	public void test_UpdateAccessKey_Allow_Action_Resource_ak_test_01() throws JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user1Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user1accessKey2,user1Name,"Inactive",200);
        
        String user1xmlString=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user2accessKey,user2Name,"Inactive",403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:UpdateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
	}
	
	@Test
	/*
	 * allow action=updateAccessKey resource=user/*
	 */
	public void test_UpdateAccessKey_Allow_Action_Resource_all() throws JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user1accessKey2,user1Name,"Inactive",200);
        
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user2accessKey,user2Name,"Inactive",200);
	}
	
	@Test
	/*
	 * allow action=updateAccessKey resource=*
	 */
	public void test_UpdateAccessKey_Allow_Action_Resource_all2() throws JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user1accessKey2,user1Name,"Inactive",200);
        
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user2accessKey,user2Name,"Inactive",200);
	}
	
	@Test
	/*
	 * allow action=updateAccessKey resource=group/*
	 */
	public void test_UpdateAccessKey_Allow_Action_resourceNotMatch() throws JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user1accessKey2,user1Name,"Inactive",403);
        
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user2accessKey,user2Name,"Inactive",403);
	}
	
	@Test
	/*
	 * allow action=updateAccessKey notresource=user/ak_test_01
	 */
	public void test_UpdateAccessKey_Allow_Action_NotResource_ak_test_01() throws JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:UpdateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user1Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        
        
        String user1xmlString=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user1accessKey2,user1Name,"Inactive",403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:UpdateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user2accessKey,user2Name,"Inactive",200);
	}
	
	@Test
	/*
	 * allow action=updateAccessKey notresource=user/*
	 */
	public void test_UpdateAccessKey_Allow_Action_NotResource_all() throws JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:UpdateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        String user1xmlString1=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user1accessKey2,user1Name,"Inactive",403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:UpdateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString2=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user2accessKey,user2Name,"Inactive",403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString2);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:UpdateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
	}
	
	@Test
	/*
	 * allow action=updateAccessKey notresource=*
	 */
	public void test_UpdateAccessKey_Allow_Action_NotResource_all2() throws JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:UpdateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        String user1xmlString1=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user1accessKey2,user1Name,"Inactive",403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:UpdateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString2=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user2accessKey,user2Name,"Inactive",403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString2);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:UpdateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
	}
	
	@Test
	/*
	 * allow notaction=updateAccessKey resource=user/ak_test_02
	 */
	public void test_UpdateAccessKey_Allow_NotAction_Resource_ak_test_02() throws JSONException, IOException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user2Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        String user1xmlString1=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user1accessKey2,user1Name,"Inactive",403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:UpdateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString2=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user2accessKey,user2Name,"Inactive",403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString2);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:UpdateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
        
        IAMInterfaceTestUtils.DeleteAccessKey(accessKey, secretKey, user2accessKey, user2Name, 200);
        
      //验证除了UpdateAccessKey，其他跟user相关的操作都可以
        List<String> excludes=new ArrayList<String>();
        excludes.add("UpdateAccessKey");
        List<Pair<String,String>> tags=new ArrayList<Pair<String,String>>();
        Pair<String,String> tag=new Pair<String,String>();
        tag.first("key");
        tag.second("value");
        tags.add(tag);
        IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, user2Name, tags, policyName, policyString, accountId);
        
        //验证和ak_test_2资源不匹配的全都不通过
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user1accessKey1, user1secretKey1, "newUser", tags, policyName, policyString, accountId);
        
        //验证跟mfa相关的都不允许
        IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user1accessKey1, user1secretKey1, accountId, "MFADevice");
        
        //验证跟group相关的都不允许
        IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey, user1accessKey1, user1secretKey1, "newGroup", testUser1, accountId, policyName, policyString);
        
        //跟policy相关的都不允许
        IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey1, user1secretKey1, policyName, policyString, accountId);
        
        // 验证 其他资源不匹配接口都不允许
        IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}
	
	@Test
	/*
	 * allow notaction=updateAccessKey resource=user/*
	 */
	public void test_UpdateAccessKey_Allow_NotAction_Resource_all() throws JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        String user1xmlString1=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user1accessKey2,user1Name,"Inactive",403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:UpdateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString2=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user2accessKey,user2Name,"Inactive",403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString2);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:UpdateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
        
     // 验证 除了UpdateAccessKey其他跟user resource相关的方法都允许
        List<String> excludes=new ArrayList<String>();
        excludes.add("UpdateAccessKey");
        List<Pair<String,String>> tags=new ArrayList<Pair<String,String>>();
        Pair<String,String> tag=new Pair<String,String>();
        tag.first("key");
        tag.second("value");
        tags.add(tag);
        IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, "newUser", tags, policyName, policyString, accountId);
        
        // 验证 跟MFA资源相关接口都不允许
        IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1, accountId, "mfa1");
        // 验证 跟policy资源相关接口都不允许
        IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1, policyName, policyString, accountId);
        // 验证 跟group资源相关接口都不允许
        IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "newGroup", "user", accountId, policyName, policyString);
        // 验证 其他资源不匹配接口都不允许
        IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}
	
	@Test
	/*
	 * allow NotAction=UpdateAccessKey, resource=*
	 * 可匹配除了CreateAccessKey的所有其他操作
	 */
	public void test_UpdateAccessKey_Allow_NotAction_Resource_all2() throws JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        String user1xmlString1=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user1accessKey2,user1Name,"Inactive",403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:UpdateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString2=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user2accessKey,user2Name,"Inactive",403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString2);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:UpdateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
        
     // 验证 除了UpdateAccessKey所有方法都允許
        List<String> excludes=new ArrayList<String>();
        excludes.add("UpdateAccessKey");

        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        String policyName2="policy2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        
        IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey,excludes, user1accessKey1, user1secretKey1, "test_7", tags, policyName2, policyString2, accountId,"newGroup","mfa2");
	}
	
	@Test
	/*
	 * allow notaction=updateAccessKey notresource=user/ak_test_02
	 */
	public void test_UpdateAccessKey_Allow_NotAction_NotResource_ak_test_02() throws JSONException, IOException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:UpdateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user2Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName,200); 
        
        String user1xmlString1=IAMInterfaceTestUtils.UpdateAccessKey(user2accessKey,user2secretKey,user1accessKey2,user1Name,"Inactive",403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+" is not authorized to perform: iam:UpdateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString2=IAMInterfaceTestUtils.UpdateAccessKey(user2accessKey,user2secretKey,user2accessKey,user2Name,"Inactive",403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString2);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+" is not authorized to perform: iam:UpdateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
        
     // 资源为user/ak_test_02的是都不允许
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user2accessKey, user2secretKey, user2Name, tags, policyName, policyString, accountId);
        
        // 验证 跟MFA资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null,user2accessKey, user2secretKey, accountId, "mfa1");
        // 验证 跟policy资源相关接口都允许
        String policyName1="testPolicy";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+testUser1),null);
        IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null,user2accessKey, user2secretKey, policyName1, policyString1, accountId);
         //验证 跟group资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceGroupALL(accessKey, secretKey, null, user2accessKey, user2secretKey, "newGroup", "newUser", accountId, policyName, policyString);
        // 验证 其他资源不匹配接口都允许
        IAMInterfaceTestUtils.AllowActionResourceOthers(user2accessKey, user2secretKey,null);
	}
	
	@Test
	/*
	 * allow notaction=updateAccessKey notresource=user/*
	 */
	public void test_UpdateAccessKey_Allow_NotAction_NotResource_all() throws JSONException, IOException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:UpdateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        String user1xmlString1=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user1accessKey2,user1Name,"Inactive",403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:UpdateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString2=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user2accessKey,user2Name,"Inactive",403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString2);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:UpdateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
        
      //跟user相关的都拒绝
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "newUser", tags, policyName, policyString, accountId);
        
        // 验证 跟MFA资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null,user1accessKey1, user1secretKey1, accountId, "mfa1");
        // 验证 跟policy资源相关接口都允许
        String policyName1="testPolicy";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null,user1accessKey1, user1secretKey1, policyName1, policyString1, accountId);
         //验证 跟group资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceGroupALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1, "newGroup", "newUser", accountId, policyName, policyString);
    
        // 验证 其他资源不匹配接口都允许
        IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1,null);
	}
	
	@Test
	/*
	 * allow notaction=updateAccessKey notresource=*
	 */
	public void test_UpdateAccessKey_Allow_NotAction_NotResource_all2() throws JSONException, IOException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:UpdateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        String user1xmlString1=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user1accessKey2,user1Name,"Inactive",403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:UpdateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString2=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user2accessKey,user2Name,"Inactive",403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString2);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:UpdateAccessKey on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
        
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        IAMInterfaceTestUtils.DenyActionResourceALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "test_21", tags, policyName, policyString, accountId,"newGroup","mfa3");
	}
	
	@Test
	/*
	 * deny action=UpdateAccessKey resource=user/ak_test_01
	 */
	public void test_UpdateAccessKey_Deny_Action_Resource_ak_test_01() throws JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user1Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user1accessKey2,user1Name,"Inactive",403);
        
        // 创建policy
     	String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:UpdateAccessKey","iam:CreateAccessKey","iam:DeleteAccessKey","iam:ListAccessKeys","iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
	}
	
	@Test
	/*
	 * deny action=UpdateAccessKey resource=user/*
	 */
	public void test_UpdateAccessKey_Deny_Action_Resource_all() throws JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user1accessKey2,user1Name,"Inactive",403);
        
        // 创建policy
     	String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:UpdateAccessKey","iam:CreateAccessKey","iam:DeleteAccessKey","iam:ListAccessKeys","iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
	}
	
	@Test
	/*
	 * deny action=UpdateAccessKey resource=*
	 */
	public void test_UpdateAccessKey_Deny_Action_Resource_all2() throws JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user1accessKey2,user1Name,"Inactive",403);
        
        // 创建policy
     	String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:UpdateAccessKey","iam:CreateAccessKey","iam:DeleteAccessKey","iam:ListAccessKeys","iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
	}
	
	@Test
	/*
	 * deny action=UpdateAccessKey resource=group/*
	 */
	public void test_UpdateAccessKey_Deny_Action_Resource_resourceNotMatch() throws JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user1accessKey2,user1Name,"Inactive",403);
        
        // 创建policy
     	String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:UpdateAccessKey","iam:CreateAccessKey","iam:DeleteAccessKey","iam:ListAccessKeys","iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
	}
	
	@Test
	/*
	 * deny action=UpdateAccessKey Notresource=user/ak_test_01
	 */
	public void test_UpdateAccessKey_Deny_Action_NotResource_ak_test_01() throws JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:UpdateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user1Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user1accessKey2,user1Name,"Inactive",403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user2accessKey,user2Name,"Inactive",403);
        
        // 创建policy
     	String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:UpdateAccessKey","iam:CreateAccessKey","iam:DeleteAccessKey","iam:ListAccessKeys","iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 200);
	}
	
	@Test
	/*
	 * deny action=UpdateAccessKey Notresource=user/*
	 */
	public void test_UpdateAccessKey_Deny_Action_NotResource_all() throws JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:UpdateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user1accessKey2,user1Name,"Inactive",403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user2accessKey,user2Name,"Inactive",403);
        
        // 创建policy
     	String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:UpdateAccessKey","iam:CreateAccessKey","iam:DeleteAccessKey","iam:ListAccessKeys","iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 200);
	}
	
	@Test
	/*
	 * deny action=UpdateAccessKey Notresource=*
	 */
	public void test_UpdateAccessKey_Deny_Action_NotResource_all2() throws JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:UpdateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user1accessKey2,user1Name,"Inactive",403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user2accessKey,user2Name,"Inactive",403);
        
        // 创建policy
     	String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:UpdateAccessKey","iam:CreateAccessKey","iam:DeleteAccessKey","iam:ListAccessKeys","iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 200);
	}
	
	@Test
	/*
	 * deny Notaction=UpdateAccessKey resource=user/ak_test_01
	 */
	public void test_UpdateAccessKey_Deny_NotAction_Resource_ak_test_01() throws JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user1Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user1accessKey2,user1Name,"Inactive",403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user2accessKey,user2Name,"Inactive",403);
        
        // 创建policy
     	String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:UpdateAccessKey","iam:CreateAccessKey","iam:DeleteAccessKey","iam:ListAccessKeys","iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 403);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 200);
	}
	
	@Test
	/*
	 * deny Notaction=UpdateAccessKey resource=user/*
	 */
	public void test_UpdateAccessKey_Deny_NotAction_Resource_all() throws JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user1accessKey2,user1Name,"Inactive",403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user2accessKey,user2Name,"Inactive",403);
        
        // 创建policy
     	String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:UpdateAccessKey","iam:CreateAccessKey","iam:DeleteAccessKey","iam:ListAccessKeys","iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 403);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 403);
	}
	
	@Test
	/*
	 * deny Notaction=UpdateAccessKey resource=*
	 */
	public void test_UpdateAccessKey_Deny_NotAction_Resource_all2() throws JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user1accessKey2,user1Name,"Inactive",403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user2accessKey,user2Name,"Inactive",403);
        
        // 创建policy
     	String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:UpdateAccessKey","iam:CreateAccessKey","iam:DeleteAccessKey","iam:ListAccessKeys","iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 403);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 403);
	}
	
	@Test
	/*
	 * deny Notaction=UpdateAccessKey notresource=user/ak_test_01
	 */
	public void test_UpdateAccessKey_Deny_NotAction_NotResource_ak_test_01() throws JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:UpdateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user1Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user1accessKey2,user1Name,"Inactive",403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user2accessKey,user2Name,"Inactive",403);
        
        // 创建policy
     	String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:UpdateAccessKey","iam:CreateAccessKey","iam:DeleteAccessKey","iam:ListAccessKeys","iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 403);
	}
	
	@Test
	/*
	 * deny Notaction=UpdateAccessKey notresource=user/*
	 */
	public void test_UpdateAccessKey_Deny_NotAction_NotResource_all() throws JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:UpdateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user1accessKey2,user1Name,"Inactive",403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user2accessKey,user2Name,"Inactive",403);
        
        // 创建policy
     	String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:UpdateAccessKey","iam:CreateAccessKey","iam:DeleteAccessKey","iam:ListAccessKeys","iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 200);
	}
	
	@Test
	/*
	 * deny Notaction=UpdateAccessKey notresource=*
	 */
	public void test_UpdateAccessKey_Deny_NotAction_NotResource_all2() throws JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:UpdateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user1accessKey2,user1Name,"Inactive",403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1,user1secretKey1,user2accessKey,user2Name,"Inactive",403);
        
        // 创建policy
     	String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:UpdateAccessKey","iam:CreateAccessKey","iam:DeleteAccessKey","iam:ListAccessKeys","iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 200);
	}
	
	
	
	//listAccessKey接口
	
	@Test
	/*
	 * allow action=listAccessKeys resource=user/ak_test_01
	 */
	public void test_ListAccessKeys_Allow_Action_Resource_ak_test_01() throws JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user1Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        
        String user1xmlString1=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:ListAccessKeys on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
	}
	
	@Test
	/*
	 * allow action=listAccessKeys resource=user/*
	 */
	public void test_ListAccessKeys_Allow_Action_Resource_all() throws JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
	}
	
	@Test
	/*
	 * allow action=listAccessKeys resource=*
	 */
	public void test_ListAccessKeys_Allow_Action_Resource_all2() throws JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
	}
	
	@Test
	/*
	 * allow action=listAccessKeys resource=group/*
	 */
	public void test_ListAccessKeys_Allow_Action_resourceNotMatch() throws JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
	}
	
	@Test
	/*
	 * allow action=listAccessKeys notresource=user/ak_test_01
	 */
	public void test_ListAccessKeys_Allow_Action_NotResource_ak_test_01() throws JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListAccessKeys"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user1Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        String user1xmlString1=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:ListAccessKeys on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
	}
	
	@Test
	/*
	 * allow action=listAccessKeys notresource=user/*
	 */
	public void test_ListAccessKeys_Allow_Action_NotResource_all() throws JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListAccessKeys"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        String user1xmlString1=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:ListAccessKeys on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString2=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString2);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:ListAccessKeys on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
	}
	
	@Test
	/*
	 * allow action=listAccessKeys notresource=*
	 */
	public void test_ListAccessKeys_Allow_Action_NotResource_all2() throws JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListAccessKeys"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        String user1xmlString1=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:ListAccessKeys on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString2=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString2);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:ListAccessKeys on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
	}
	
	@Test
	/*
	 * allow notaction=listAccessKeys resource=user/ak_test_02
	 */
	public void test_ListAccessKeys_Allow_NotAction_Resource_ak_test_02() throws JSONException, IOException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user2Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        String user1xmlString1=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:ListAccessKeys on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString2=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString2);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:ListAccessKeys on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
        
        IAMInterfaceTestUtils.DeleteAccessKey(accessKey, secretKey, user2accessKey, user2Name, 200);
        
        //验证除了ListAccessKeys，其他跟user相关的操作都可以
          List<String> excludes=new ArrayList<String>();
          excludes.add("ListAccessKeys");
          List<Pair<String,String>> tags=new ArrayList<Pair<String,String>>();
          Pair<String,String> tag=new Pair<String,String>();
          tag.first("key");
          tag.second("value");
          tags.add(tag);
          IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, user2Name, tags, policyName, policyString, accountId);
          
          //验证和ak_test_2资源不匹配的全都不通过
          IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user1accessKey1, user1secretKey1, "newUser", tags, policyName, policyString, accountId);
          
          //验证跟mfa相关的都不允许
          IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user1accessKey1, user1secretKey1, accountId, "MFADevice");
          
          //验证跟group相关的都不允许
          IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey, user1accessKey1, user1secretKey1, "newGroup", testUser1, accountId, policyName, policyString);
          
          //跟policy相关的都不允许
          IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey1, user1secretKey1, policyName, policyString, accountId);
          
          // 验证 其他资源不匹配接口都不允许
          IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}
	
	@Test
	/*
	 * allow notaction=listAccessKeys resource=user/*
	 */
	public void test_ListAccessKeys_Allow_NotAction_Resource_all() throws JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        String user1xmlString1=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:ListAccessKeys on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString2=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString2);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:ListAccessKeys on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
        
     // 验证 除了ListAccessKeys其他跟user resource相关的方法都允许
        List<String> excludes=new ArrayList<String>();
        excludes.add("ListAccessKeys");
        List<Pair<String,String>> tags=new ArrayList<Pair<String,String>>();
        Pair<String,String> tag=new Pair<String,String>();
        tag.first("key");
        tag.second("value");
        tags.add(tag);
        IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, "newUser", tags, policyName, policyString, accountId);
        
        // 验证 跟MFA资源相关接口都不允许
        IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1, accountId, "mfa1");
        // 验证 跟policy资源相关接口都不允许
        IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1, policyName, policyString, accountId);
        // 验证 跟group资源相关接口都不允许
        IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "newGroup", "user", accountId, policyName, policyString);
        // 验证 其他资源不匹配接口都不允许
        IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
        
	}
	
	@Test
	/*
	 * allow NotAction=ListAccessKeys, resource=*
	 * 可匹配除了ListAccessKeys的所有其他操作
	 */
	public void test_ListAccessKeys_Allow_NotAction_Resource_all2() throws JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        String user1xmlString1=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:ListAccessKeys on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString2=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString2);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:ListAccessKeys on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
        
     // 验证 除了ListAccessKeys所有方法都允許
        List<String> excludes=new ArrayList<String>();
        excludes.add("ListAccessKeys");

        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        String policyName2="policy2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        
        IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey,excludes, user1accessKey1, user1secretKey1, "test_7", tags, policyName2, policyString2, accountId,"newGroup","mfa2");
	}
	
	@Test
	/*
	 * allow notaction=listAccessKeys notresource=user/ak_test_02
	 */
	public void test_ListAccessKeys_Allow_NotAction_NotResource_ak_test_02() throws JSONException, IOException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:ListAccessKeys"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user2Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName,200); 
        
        String user1xmlString1=IAMInterfaceTestUtils.ListAccessKeys(user2accessKey, user2secretKey, user1Name, 403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+" is not authorized to perform: iam:ListAccessKeys on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString2=IAMInterfaceTestUtils.ListAccessKeys(user2accessKey, user2secretKey, user2Name, 403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString2);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+" is not authorized to perform: iam:ListAccessKeys on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
        
     // 资源为user/ak_test_02的是都不允许
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user2accessKey, user2secretKey, user2Name, tags, policyName, policyString, accountId);
        
        // 验证 跟MFA资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null,user2accessKey, user2secretKey, accountId, "mfa1");
        // 验证 跟policy资源相关接口都允许
        String policyName1="testPolicy";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+testUser1),null);
        IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null,user2accessKey, user2secretKey, policyName1, policyString1, accountId);
         //验证 跟group资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceGroupALL(accessKey, secretKey, null, user2accessKey, user2secretKey, "newGroup", "newUser", accountId, policyName, policyString);
        // 验证 其他资源不匹配接口都允许
        IAMInterfaceTestUtils.AllowActionResourceOthers(user2accessKey, user2secretKey,null);
	}
	
	@Test
	/*
	 * allow notaction=listAccessKeys notresource=user/*
	 */
	public void test_ListAccessKeys_Allow_NotAction_NotResource_all() throws JSONException, IOException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:ListAccessKeys"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        String user1xmlString1=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:ListAccessKeys on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString2=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString2);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:ListAccessKeys on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
        
      //跟user相关的都拒绝
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "newUser", tags, policyName, policyString, accountId);
        
        // 验证 跟MFA资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null,user1accessKey1, user1secretKey1, accountId, "mfa1");
        // 验证 跟policy资源相关接口都允许
        String policyName1="testPolicy";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null,user1accessKey1, user1secretKey1, policyName1, policyString1, accountId);
         //验证 跟group资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceGroupALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1, "newGroup", "newUser", accountId, policyName, policyString);
    
        // 验证 其他资源不匹配接口都允许
        IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1,null);
	}
	
	@Test
	/*
	 * allow notaction=listAccessKeys notresource=*
	 */
	public void test_ListAccessKeys_Allow_NotAction_NotResource_all2() throws JSONException, IOException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:ListAccessKeys"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        String user1xmlString1=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:ListAccessKeys on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString2=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString2);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:ListAccessKeys on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
        
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        IAMInterfaceTestUtils.DenyActionResourceALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "test_21", tags, policyName, policyString, accountId,"newGroup","mfa3");
	}
	
	@Test
	/*
	 * deny action=listAccessKeys resource=user/ak_test_01
	 */
	public void test_ListAccessKeys_Deny_Action_Resource_ak_test_01() throws JSONException {
		// 创建policy
        String denyPolicyName="denyPolicy";
		String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user1Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        
        // 创建policy
        String allowPolicyName="allowPolicy";
		policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListAccessKeys","iam:CreateAccessKey","iam:UpdateAccessKey","iam:DeleteAccessKey","iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
	}
	
	@Test
	/*
	 * deny action=listAccessKeys resource=user/*
	 */
	public void test_ListAccessKeys_Deny_Action_Resource_all() throws JSONException {
		// 创建policy
        String denyPolicyName="denyPolicy";
		String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        
        // 创建policy
        String allowPolicyName="allowPolicy";
		policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListAccessKeys","iam:CreateAccessKey","iam:UpdateAccessKey","iam:DeleteAccessKey","iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
	}
	
	@Test
	/*
	 * deny action=listAccessKeys resource=*
	 */
	public void test_ListAccessKeys_Deny_Action_Resource_all2() throws JSONException {
		// 创建policy
        String denyPolicyName="denyPolicy";
		String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        
        // 创建policy
        String allowPolicyName="allowPolicy";
		policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListAccessKeys","iam:CreateAccessKey","iam:UpdateAccessKey","iam:DeleteAccessKey","iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
	}
	
	@Test
	/*
	 * deny action=listAccessKeys resource=group/*
	 */
	public void test_ListAccessKeys_Deny_Action_Resource_resourceNotMatch() throws JSONException {
		// 创建policy
        String denyPolicyName="denyPolicy";
		String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        
        // 创建policy
        String allowPolicyName="allowPolicy";
		policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListAccessKeys","iam:CreateAccessKey","iam:UpdateAccessKey","iam:DeleteAccessKey","iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
	}
	
	@Test
	/*
	 * deny action=listAccessKeys notresource=user/ak_test_01
	 */
	public void test_ListAccessKeys_Deny_Action_NotResource_ak_test_01() throws JSONException {
		// 创建policy
        String denyPolicyName="denyPolicy";
		String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:ListAccessKeys"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user1Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
        
        // 创建policy
        String allowPolicyName="allowPolicy";
		policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListAccessKeys","iam:CreateAccessKey","iam:UpdateAccessKey","iam:DeleteAccessKey","iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 200);
	}
	
	@Test
	/*
	 * deny action=listAccessKeys notresource=user/*
	 */
	public void test_ListAccessKeys_Deny_Action_NotResource_all() throws JSONException {
		// 创建policy
        String denyPolicyName="denyPolicy";
		String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:ListAccessKeys"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
        
        // 创建policy
        String allowPolicyName="allowPolicy";
		policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListAccessKeys","iam:CreateAccessKey","iam:UpdateAccessKey","iam:DeleteAccessKey","iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 200);
	}
	
	@Test
	/*
	 * deny action=listAccessKeys notresource=*
	 */
	public void test_ListAccessKeys_Deny_Action_NotResource_all2() throws JSONException {
		// 创建policy
        String denyPolicyName="denyPolicy";
		String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:ListAccessKeys"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
        
        // 创建policy
        String allowPolicyName="allowPolicy";
		policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListAccessKeys","iam:CreateAccessKey","iam:UpdateAccessKey","iam:DeleteAccessKey","iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 200);
	}
	
	@Test
	/*
	 * deny Notaction=listAccessKeys resource=user/ak_user_01
	 */
	public void test_ListAccessKeys_Deny_NotAction_Resource_ak_user_01() throws JSONException {
		// 创建policy
        String denyPolicyName="denyPolicy";
		String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user1Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
        
        // 创建policy
        String allowPolicyName="allowPolicy";
		policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListAccessKeys","iam:CreateAccessKey","iam:UpdateAccessKey","iam:DeleteAccessKey","iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 403);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 200);
	}
	
	@Test
	/*
	 * deny Notaction=listAccessKeys resource=user/*
	 */
	public void test_ListAccessKeys_Deny_NotAction_Resource_all() throws JSONException {
		// 创建policy
        String denyPolicyName="denyPolicy";
		String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
        
        // 创建policy
        String allowPolicyName="allowPolicy";
		policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListAccessKeys","iam:CreateAccessKey","iam:UpdateAccessKey","iam:DeleteAccessKey","iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 403);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 403);
	}
	
	@Test
	/*
	 * deny Notaction=listAccessKeys resource=*
	 */
	public void test_ListAccessKeys_Deny_NotAction_Resource_all2() throws JSONException {
		// 创建policy
        String denyPolicyName="denyPolicy";
		String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
        
        // 创建policy
        String allowPolicyName="allowPolicy";
		policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListAccessKeys","iam:CreateAccessKey","iam:UpdateAccessKey","iam:DeleteAccessKey","iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 403);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 403);
	}
	
	@Test
	/*
	 * deny Notaction=listAccessKeys notresource=user/ak_test_01
	 */
	public void test_ListAccessKeys_Deny_NotAction_NotResource_ak_test_01() throws JSONException {
		// 创建policy
        String denyPolicyName="denyPolicy";
		String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:ListAccessKeys"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user1Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
        
        // 创建policy
        String allowPolicyName="allowPolicy";
		policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListAccessKeys","iam:CreateAccessKey","iam:UpdateAccessKey","iam:DeleteAccessKey","iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 403);
	}
	
	@Test
	/*
	 * deny Notaction=listAccessKeys notresource=user/*
	 */
	public void test_ListAccessKeys_Deny_NotAction_NotResource_all() throws JSONException {
		// 创建policy
        String denyPolicyName="denyPolicy";
		String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:ListAccessKeys"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
        
        // 创建policy
        String allowPolicyName="allowPolicy";
		policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListAccessKeys","iam:CreateAccessKey","iam:UpdateAccessKey","iam:DeleteAccessKey","iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 200);
	}
	
	@Test
	/*
	 * deny Notaction=listAccessKeys notresource=*
	 */
	public void test_ListAccessKeys_Deny_NotAction_NotResource_all2() throws JSONException {
		// 创建policy
        String denyPolicyName="denyPolicy";
		String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:ListAccessKeys"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
        
        // 创建policy
        String allowPolicyName="allowPolicy";
		policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListAccessKeys","iam:CreateAccessKey","iam:UpdateAccessKey","iam:DeleteAccessKey","iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 200);
	}
	
	
	//getAccessKeyLastUsed
	
	@Test
	/*
	 * action=getAccessKeyLastUsed resource=user/ak_test_01
	 */
	public void test_GetAccessKeyLastUsed_Allow_Action_Resource_ak_test_01() throws InterruptedException, JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user1Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey1, 200);
        
        String user1xmlString1=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:GetAccessKeyLastUsed on resource: access key "+user2accessKey+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
	}
	
	@Test
	/*
	 * action=getAccessKeyLastUsed resource=user/*
	 */
	public void test_GetAccessKeyLastUsed_Allow_Action_Resource_all() throws InterruptedException, JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey1, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        
	}
	
	@Test
	/*
	 * action=getAccessKeyLastUsed resource=*
	 */
	public void test_GetAccessKeyLastUsed_Allow_Action_Resource_all2() throws InterruptedException, JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey1, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        
	}
	
	@Test
	/*
	 * action=getAccessKeyLastUsed resource=group/*
	 */
	public void test_GetAccessKeyLastUsed_Allow_Action_resourceNotMatch() throws InterruptedException, JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey1, 403);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        
	}
	
	@Test
	/*
	 * action=getAccessKeyLastUsed notresource=user/ak_test_01
	 */
	public void test_GetAccessKeyLastUsed_Allow_Action_NotResource_ak_test_01() throws InterruptedException, JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetAccessKeyLastUsed"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user1Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        String user1xmlString1=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey1, 403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:GetAccessKeyLastUsed on resource: access key "+user1accessKey1+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        
	}
	
	@Test
	/*
	 * action=getAccessKeyLastUsed notresource=user/*
	 */
	public void test_GetAccessKeyLastUsed_Allow_Action_NotResource_all() throws InterruptedException, JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetAccessKeyLastUsed"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        String user1xmlString1=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey1, 403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:GetAccessKeyLastUsed on resource: access key "+user1accessKey1+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString2=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString2);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:GetAccessKeyLastUsed on resource: access key "+user2accessKey+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
	}
	
	@Test
	/*
	 * action=getAccessKeyLastUsed notresource=*
	 */
	public void test_GetAccessKeyLastUsed_Allow_Action_NotResource_all2() throws InterruptedException, JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetAccessKeyLastUsed"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        String user1xmlString1=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey1, 403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:GetAccessKeyLastUsed on resource: access key "+user1accessKey1+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString2=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString2);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:GetAccessKeyLastUsed on resource: access key "+user2accessKey+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
	}
	
	@Test
	/*
	 * notaction=getAccessKeyLastUsed resource=user/ak_test_02
	 */
	public void test_GetAccessKeyLastUsed_Allow_NotAction_Resource_ak_test_02() throws InterruptedException, JSONException, IOException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user2Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        String user1xmlString1=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey1, 403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:GetAccessKeyLastUsed on resource: access key "+user1accessKey1+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString2=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString2);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:GetAccessKeyLastUsed on resource: access key "+user2accessKey+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
        
        IAMInterfaceTestUtils.DeleteAccessKey(accessKey, secretKey, user2accessKey, user2Name, 200);
        
        //验证除了GetAccessKeyLastUsed，其他跟user相关的操作都可以
          List<String> excludes=new ArrayList<String>();
          excludes.add("GetAccessKeyLastUsed");
          List<Pair<String,String>> tags=new ArrayList<Pair<String,String>>();
          Pair<String,String> tag=new Pair<String,String>();
          tag.first("key");
          tag.second("value");
          tags.add(tag);
          IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, user2Name, tags, policyName, policyString, accountId);
          
          //验证和ak_test_2资源不匹配的全都不通过
          IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user1accessKey1, user1secretKey1, "newUser", tags, policyName, policyString, accountId);
          
          //验证跟mfa相关的都不允许
          IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user1accessKey1, user1secretKey1, accountId, "MFADevice");
          
          //验证跟group相关的都不允许
          IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey, user1accessKey1, user1secretKey1, "newGroup", testUser1, accountId, policyName, policyString);
          
          //跟policy相关的都不允许
          IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey1, user1secretKey1, policyName, policyString, accountId);
          
          // 验证 其他资源不匹配接口都不允许
          IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}
	
	@Test
	/*
	 * notaction=getAccessKeyLastUsed resource=user/*
	 */
	public void test_GetAccessKeyLastUsed_Allow_NotAction_Resource_all() throws InterruptedException, JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        String user1xmlString1=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey1, 403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:GetAccessKeyLastUsed on resource: access key "+user1accessKey1+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString2=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString2);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:GetAccessKeyLastUsed on resource: access key "+user2accessKey+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
        
     // 验证 除了GetAccessKeyLastUsed其他跟user resource相关的方法都允许
        List<String> excludes=new ArrayList<String>();
        excludes.add("GetAccessKeyLastUsed");
        List<Pair<String,String>> tags=new ArrayList<Pair<String,String>>();
        Pair<String,String> tag=new Pair<String,String>();
        tag.first("key");
        tag.second("value");
        tags.add(tag);
        IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, "newUser", tags, policyName, policyString, accountId);
        
        // 验证 跟MFA资源相关接口都不允许
        IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1, accountId, "mfa1");
        // 验证 跟policy资源相关接口都不允许
        IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1, policyName, policyString, accountId);
        // 验证 跟group资源相关接口都不允许
        IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "newGroup", "user", accountId, policyName, policyString);
        // 验证 其他资源不匹配接口都不允许
        IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}
	
	@Test
	/*
	 * allow NotAction=GetAccessKeyLastUsed, resource=*
	 * 可匹配除了GetAccessKeyLastUsed的所有其他操作
	 */
	public void test_GetAccessKeyLastUsed_Allow_NotAction_Resource_all2() throws JSONException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        String user1xmlString1=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey1, 403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:GetAccessKeyLastUsed on resource: access key "+user1accessKey1+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString2=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString2);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:GetAccessKeyLastUsed on resource: access key "+user2accessKey+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
        
     // 验证 除了GetAccessKeyLastUsed所有方法都允許
        List<String> excludes=new ArrayList<String>();
        excludes.add("GetAccessKeyLastUsed");

        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        String policyName2="policy2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        
        IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey,excludes, user1accessKey1, user1secretKey1, "test_7", tags, policyName2, policyString2, accountId,"newGroup","mfa2");
	}
	
	@Test
	/*
	 * allow notaction=getAccessKeyLastUsed notresource=user/ak_test_02
	 */
	public void test_GetAccessKeyLastUsed_Allow_NotAction_NotResource_ak_test_02() throws InterruptedException, JSONException, IOException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:GetAccessKeyLastUsed"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user2Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName,200); 
        
        String user1xmlString1=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user2accessKey, user2secretKey, user1accessKey1, 403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+" is not authorized to perform: iam:GetAccessKeyLastUsed on resource: access key "+user1accessKey1+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString2=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user2accessKey, user2secretKey, user2accessKey, 403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString2);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+" is not authorized to perform: iam:GetAccessKeyLastUsed on resource: access key "+user2accessKey+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
        
     // 资源为user/ak_test_02的是都不允许
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user2accessKey, user2secretKey, user2Name, tags, policyName, policyString, accountId);
        
        // 验证 跟MFA资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null,user2accessKey, user2secretKey, accountId, "mfa1");
        // 验证 跟policy资源相关接口都允许
        String policyName1="testPolicy";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+testUser1),null);
        IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null,user2accessKey, user2secretKey, policyName1, policyString1, accountId);
         //验证 跟group资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceGroupALL(accessKey, secretKey, null, user2accessKey, user2secretKey, "newGroup", "newUser", accountId, policyName, policyString);
        // 验证 其他资源不匹配接口都允许
        IAMInterfaceTestUtils.AllowActionResourceOthers(user2accessKey, user2secretKey,null);
	}
	
	@Test
	/*
	 * allow notaction=getAccessKeyLastUsed notresource=user/*
	 */
	public void test_GetAccessKeyLastUsed_Allow_NotAction_NotResource_all() throws InterruptedException, JSONException, IOException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:GetAccessKeyLastUsed"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        String user1xmlString1=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey1, 403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:GetAccessKeyLastUsed on resource: access key "+user1accessKey1+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString2=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString2);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:GetAccessKeyLastUsed on resource: access key "+user2accessKey+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
        
      //跟user相关的都拒绝
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "newUser", tags, policyName, policyString, accountId);
        
        // 验证 跟MFA资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null,user1accessKey1, user1secretKey1, accountId, "mfa1");
        // 验证 跟policy资源相关接口都允许
        String policyName1="testPolicy";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateAccessKey"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null,user1accessKey1, user1secretKey1, policyName1, policyString1, accountId);
         //验证 跟group资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceGroupALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1, "newGroup", "newUser", accountId, policyName, policyString);
    
        // 验证 其他资源不匹配接口都允许
        IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1,null);
	}
	
	
	@Test
	/*
	 * allow notaction=getAccessKeyLastUsed notresource=*
	 */
	public void test_GetAccessKeyLastUsed_Allow_NotAction_NotResource_all2() throws InterruptedException, JSONException, IOException {
		// 创建policy
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:GetAccessKeyLastUsed"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200); 
        
        String user1xmlString1=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey1, 403);
        JSONObject error1=IAMTestUtils.ParseErrorToJson(user1xmlString1);
        assertEquals("AccessDenied", error1.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:GetAccessKeyLastUsed on resource: access key "+user1accessKey1+".", error1.get("Message"));
        assertEquals("", error1.get("Resource"));
        
        String user1xmlString2=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1xmlString2);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:GetAccessKeyLastUsed on resource: access key "+user2accessKey+".", error2.get("Message"));
        assertEquals("", error2.get("Resource"));
        
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        IAMInterfaceTestUtils.DenyActionResourceALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "test_21", tags, policyName, policyString, accountId,"newGroup","mfa3");
	}
	
	@Test
	/*
	 * deny action=GetAccessKeyLastUsed resource=user/ak_test_01
	 */
	public void test_GetAccessKeyLastUsed_Deny_Action_Resource_ak_test_01() throws InterruptedException, JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user1Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 403);
        
        // 创建policy
        String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetAccessKeyLastUsed","iam:CreateAccessKey","iam:UpdateAccessKey","iam:DeleteAccessKey","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
	}
	
	@Test
	/*
	 * deny action=GetAccessKeyLastUsed resource=user/*
	 */
	public void test_GetAccessKeyLastUsed_Deny_Action_Resource_all() throws InterruptedException, JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 403);
        
        // 创建policy
        String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetAccessKeyLastUsed","iam:CreateAccessKey","iam:UpdateAccessKey","iam:DeleteAccessKey","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
	}
	
	@Test
	/*
	 * deny action=GetAccessKeyLastUsed resource=*
	 */
	public void test_GetAccessKeyLastUsed_Deny_Action_Resource_all2() throws InterruptedException, JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 403);
        
        // 创建policy
        String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetAccessKeyLastUsed","iam:CreateAccessKey","iam:UpdateAccessKey","iam:DeleteAccessKey","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
	}
	
	@Test
	/*
	 * deny action=GetAccessKeyLastUsed resource=group/*
	 */
	public void test_GetAccessKeyLastUsed_Deny_Action_Resource_resourceNotMatch() throws InterruptedException, JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 403);
        
        // 创建policy
        String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetAccessKeyLastUsed","iam:CreateAccessKey","iam:UpdateAccessKey","iam:DeleteAccessKey","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
	}
	
	@Test
	/*
	 * deny action=GetAccessKeyLastUsed Notresource=user/ak_test_01
	 */
	public void test_GetAccessKeyLastUsed_Deny_Action_NotResource_ak_test_01() throws InterruptedException, JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetAccessKeyLastUsed"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user1Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 403);
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        
        // 创建policy
        String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetAccessKeyLastUsed","iam:CreateAccessKey","iam:UpdateAccessKey","iam:DeleteAccessKey","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 200);
	}
	
	@Test
	/*
	 * deny action=GetAccessKeyLastUsed Notresource=user/*
	 */
	public void test_GetAccessKeyLastUsed_Deny_Action_NotResource_all() throws InterruptedException, JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetAccessKeyLastUsed"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 403);
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        
        // 创建policy
        String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetAccessKeyLastUsed","iam:CreateAccessKey","iam:UpdateAccessKey","iam:DeleteAccessKey","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 200);
	}
	
	@Test
	/*
	 * deny action=GetAccessKeyLastUsed Notresource=*
	 */
	public void test_GetAccessKeyLastUsed_Deny_Action_NotResource_all2() throws InterruptedException, JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetAccessKeyLastUsed"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 403);
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        
        // 创建policy
        String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetAccessKeyLastUsed","iam:CreateAccessKey","iam:UpdateAccessKey","iam:DeleteAccessKey","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 200);
	}
	
	@Test
	/*
	 * deny notaction=GetAccessKeyLastUsed resource=user/ak_test_01
	 */
	public void test_GetAccessKeyLastUsed_Deny_NotAction_Resource_ak_test_01() throws InterruptedException, JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user1Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 403);
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        
        // 创建policy
        String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetAccessKeyLastUsed","iam:CreateAccessKey","iam:UpdateAccessKey","iam:DeleteAccessKey","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 403);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 200);
	}
	
	@Test
	/*
	 * deny notaction=GetAccessKeyLastUsed resource=user/*
	 */
	public void test_GetAccessKeyLastUsed_Deny_NotAction_Resource_all() throws InterruptedException, JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 403);
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        
        // 创建policy
        String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetAccessKeyLastUsed","iam:CreateAccessKey","iam:UpdateAccessKey","iam:DeleteAccessKey","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 403);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 403);
	}
	
	@Test
	/*
	 * deny notaction=GetAccessKeyLastUsed resource=*
	 */
	public void test_GetAccessKeyLastUsed_Deny_NotAction_Resource_all2() throws InterruptedException, JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:GetAccessKeyLastUsed"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 403);
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        
        // 创建policy
        String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetAccessKeyLastUsed","iam:CreateAccessKey","iam:UpdateAccessKey","iam:DeleteAccessKey","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 403);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 403);
	}
	
	@Test
	/*
	 * deny notaction=GetAccessKeyLastUsed notresource=user/ak_test_01
	 */
	public void test_GetAccessKeyLastUsed_Deny_NotAction_NotResource_ak_test_01() throws InterruptedException, JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:GetAccessKeyLastUsed"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+user1Name),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 403);
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        
        // 创建policy
        String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetAccessKeyLastUsed","iam:CreateAccessKey","iam:UpdateAccessKey","iam:DeleteAccessKey","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 403);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 403);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 403);
	}
	
	@Test
	/*
	 * deny notaction=GetAccessKeyLastUsed notresource=user/*
	 */
	public void test_GetAccessKeyLastUsed_Deny_NotAction_NotResource_all() throws InterruptedException, JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:GetAccessKeyLastUsed"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 403);
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        
        // 创建policy
        String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetAccessKeyLastUsed","iam:CreateAccessKey","iam:UpdateAccessKey","iam:DeleteAccessKey","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 200);
	}
	
	@Test
	/*
	 * deny notaction=GetAccessKeyLastUsed notresource=*
	 */
	public void test_GetAccessKeyLastUsed_Deny_NotAction_NotResource_all2() throws InterruptedException, JSONException {
		// 创建policy
		String denyPolicyName="denyPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:GetAccessKeyLastUsed"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 403);
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 403);
        
        // 创建policy
        String allowPolicyName="allowPolicy";
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetAccessKeyLastUsed","iam:CreateAccessKey","iam:UpdateAccessKey","iam:DeleteAccessKey","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicyName, policyString,200);
             
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicyName,200); 
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user1accessKey2, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user1Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user1accessKey2, user1Name, 200);
        
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, user2accessKey, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, "Inactive", 200);
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, user2Name, 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, user2accessKey, user2Name, 200);
	}
	
	
	@Test
    /*
     * 在IP范围的允许访问
     */
    public void test_CreateAccessKey_Condition_sourceIP() {
	    String policyName="allowspecialIP";
	    List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("IpAddress","ctyun:SourceIp",Arrays.asList("192.168.1.1/24")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);

        // 在IP范围
        String body="Action=CreateAccessKey&UserName="+testUser1;
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("X-Forwarded-For");
        param1.second("192.168.1.101");
        params.add(param1);
        
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(200, result.first().intValue());
        
        // 不在IP范围
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("X-Forwarded-For");
        param2.second("192.168.2.101");
        params2.add(param2);
        
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result2.first().intValue());
	}
	
	@Test
	/*
	 * 符合username匹配允许访问
	 */
	public void test_DeleteAccessKey_Condition_username() {
        String policyName="allowUsername";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("*test*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        // username 不符合条件
        String body="Action=DeleteAccessKey&AccessKeyId="+user2accessKey+"&UserName="+user2Name;
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest(body, user3accessKey, user3secretKey);
        assertEquals(403, result3.first().intValue());
        
        // username 符合条件
        body="Action=DeleteAccessKey&AccessKeyId="+user2accessKey+"&UserName="+user2Name;
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, result.first().intValue());
        
        
    }
	
	@Test
	/*
	 * 符合实际条件允许访问
	 */
	public void test_UpdateAccessKey_Condition_CurrentTime() {
	    String policyName="allowDateGreate";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("DateGreaterThan","ctyun:CurrentTime",Arrays.asList("2019-01-01T00:00:00Z")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        // 时间符合条件
        String body="Status=Inactive&Action=UpdateAccessKey&AccessKeyId="+user2accessKey+"&UserName="+user2Name;
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, result.first().intValue());
        
        
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("DateGreaterThan","ctyun:CurrentTime",Arrays.asList("2050-01-01T00:00:00Z")));
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:UpdateAccessKey"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),conditions2);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
   
        // 时间不符合条件
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(403, result2.first().intValue());
	}
	
	
	@Test
	/*
	 * 设置不允许ssl访问
	 */
	public void test_ListAccessKeys_Condition_SecureTransport() {
	    String policyName="DenySSL";
	    
	    String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
	    IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
	    
        // 允许ssl访问 
        String body="Action=ListAccessKeys&UserName="+user1Name;
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, result.first().intValue());

        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("Bool","ctyun:SecureTransport",Arrays.asList("false")));
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 不允许ssl访问
        body="Action=ListAccessKeys&UserName="+user1Name;
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(403, result2.first().intValue());
        
    }
	
	@Test
	/*
	 * allow Action=CreateAccessKey,DeleteAccessKey,ListAccessKeys,UpdateAccessKey,GetAccessKeyLastUsed resource=user/testUser1
	         * 只允许上述对testUser1操作
	 */
	public void test_AccessKeyALLMethod_Allow_Action_testUser1() throws JDOMException, IOException  {
	    // 创建policy
	    String policyName="test_AccessKeyAllMethod_Allow_Action_testUser1";
	    String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:DeleteAccessKey","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+testUser1),null);
	    IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
	    
	    // 给用户添加policy
	    IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
	    
	    // 验证请求
	    // user1有testUser1权限
	    AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1, testUser1, 200));
	    IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, testUser1, 200);
	    IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 200);
	    IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 200);
	    IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 200);
	    
	    // user2无权限
	    String user2CreateString=IAMInterfaceTestUtils.CreateAccessKey(user2accessKey, user2secretKey, testUser1, 403);
	    AssertAccessDenyString(user2CreateString, "CreateAccessKey",user2Name, "user/"+testUser1);
	    accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(accessKey, secretKey, testUser1, 200));
	    String user2ListString=IAMInterfaceTestUtils.ListAccessKeys(user2accessKey, user2secretKey, testUser1, 403);
	    AssertAccessDenyString(user2ListString, "ListAccessKeys",user2Name, "user/"+testUser1);
	    String user2GetString=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user2accessKey, user2secretKey, accessKeyResult.accessKeyId, 403);
	    AssertAccessDenyString_GetAccessKeyLastUsed(user2GetString, "GetAccessKeyLastUsed",user2Name, "access key " + accessKeyResult.accessKeyId);
	    String user2UpdateString=IAMInterfaceTestUtils.UpdateAccessKey(user2accessKey, user2secretKey, accessKeyResult.accessKeyId, testUser1, "Inactive", 403);
	    AssertAccessDenyString(user2UpdateString, "UpdateAccessKey",user2Name, "user/"+testUser1);
	    String user2DeleteString=IAMInterfaceTestUtils.DeleteAccessKey(user2accessKey, user2secretKey, accessKeyResult.accessKeyId, testUser1, 403);
	    AssertAccessDenyString(user2DeleteString, "DeleteAccessKey",user2Name, "user/"+testUser1);
	    
	    // user1无其他user权限
	    
	    String user1CreateString=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1, testUser2, 403);
	    AssertAccessDenyString(user1CreateString, "CreateAccessKey",user1Name, "user/"+testUser2);
	    accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(accessKey, secretKey, testUser2, 200));
	    String user1ListString=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, testUser2, 403);
	    AssertAccessDenyString(user1ListString, "ListAccessKeys",user1Name, "user/"+testUser2);
	    String user1GetString=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 403);
	    AssertAccessDenyString_GetAccessKeyLastUsed(user1GetString, "GetAccessKeyLastUsed",user1Name, "access key " + accessKeyResult.accessKeyId);
	    String user1UpdateString=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser2, "Inactive", 403);
	    AssertAccessDenyString(user1UpdateString, "UpdateAccessKey",user1Name, "user/"+testUser2);
	    String user1DeleteString=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser2, 403);
	    AssertAccessDenyString(user1DeleteString, "DeleteAccessKey",user1Name, "user/"+testUser2);
	    
	}

	
	@Test
    /*
     * allow Action=CreateAccessKey,DeleteAccessKey,ListAccessKeys,UpdateAccessKey,GetAccessKeyLastUsed, resource=user/*
             * 可以对所有user操作
     */
	public void test_AccessKeyALLMethod_Allow_Action_userAll() throws JDOMException, IOException {
	    // 创建policy
        String policyName="test_AccessKeyALLMethod_Allow_Action_userAll";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:DeleteAccessKey","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        // 验证请求
        // user1有testUser1权限
        AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1, testUser1, 200));
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, testUser1, 200);
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 200);
        
        // user2无权限
        String user2CreateString=IAMInterfaceTestUtils.CreateAccessKey(user2accessKey, user2secretKey, testUser1, 403);
        AssertAccessDenyString(user2CreateString, "CreateAccessKey",user2Name, "user/"+testUser1);
        accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(accessKey, secretKey, testUser1, 200));
        String user2ListString=IAMInterfaceTestUtils.ListAccessKeys(user2accessKey, user2secretKey, testUser1, 403);
        AssertAccessDenyString(user2ListString, "ListAccessKeys",user2Name, "user/"+testUser1);
        String user2GetString=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user2accessKey, user2secretKey, accessKeyResult.accessKeyId, 403);
        AssertAccessDenyString_GetAccessKeyLastUsed(user2GetString, "GetAccessKeyLastUsed",user2Name, "access key " + accessKeyResult.accessKeyId);
        String user2UpdateString=IAMInterfaceTestUtils.UpdateAccessKey(user2accessKey, user2secretKey, accessKeyResult.accessKeyId, testUser1, "Inactive", 403);
        AssertAccessDenyString(user2UpdateString, "UpdateAccessKey",user2Name, "user/"+testUser1);
        String user2DeleteString=IAMInterfaceTestUtils.DeleteAccessKey(user2accessKey, user2secretKey, accessKeyResult.accessKeyId, testUser1, 403);
        AssertAccessDenyString(user2DeleteString, "DeleteAccessKey",user2Name, "user/"+testUser1);
        
        // user1有其他user权限
        accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1, testUser2, 200));
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, testUser2, 200);
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser2, "Inactive", 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser2, 200);

    }
	
	@Test
	/*
     * allow Action=CreateAccessKey,DeleteAccessKey,ListAccessKeys,UpdateAccessKey,GetAccessKeyLastUsed, resource=*
             * 可以对所有user操作
     */
	public void test_AccessKeyALLMethod_Allow_Action_ALL() throws JDOMException, IOException {
	 // 创建policy
        String policyName="test_AccessKeyALLMethod_Allow_Action_ALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:DeleteAccessKey","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        // 验证请求
        // user1有testUser1权限
        AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1, testUser1, 200));
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, testUser1, 200);
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 200);
        
        // user2无权限
        String user2CreateString=IAMInterfaceTestUtils.CreateAccessKey(user2accessKey, user2secretKey, testUser1, 403);
        AssertAccessDenyString(user2CreateString, "CreateAccessKey",user2Name, "user/"+testUser1);
        accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(accessKey, secretKey, testUser1, 200));
        String user2ListString=IAMInterfaceTestUtils.ListAccessKeys(user2accessKey, user2secretKey, testUser1, 403);
        AssertAccessDenyString(user2ListString, "ListAccessKeys",user2Name, "user/"+testUser1);
        String user2GetString=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user2accessKey, user2secretKey, accessKeyResult.accessKeyId, 403);
        AssertAccessDenyString_GetAccessKeyLastUsed(user2GetString, "GetAccessKeyLastUsed",user2Name, "access key " + accessKeyResult.accessKeyId);
        String user2UpdateString=IAMInterfaceTestUtils.UpdateAccessKey(user2accessKey, user2secretKey, accessKeyResult.accessKeyId, testUser1, "Inactive", 403);
        AssertAccessDenyString(user2UpdateString, "UpdateAccessKey",user2Name, "user/"+testUser1);
        String user2DeleteString=IAMInterfaceTestUtils.DeleteAccessKey(user2accessKey, user2secretKey, accessKeyResult.accessKeyId, testUser1, 403);
        AssertAccessDenyString(user2DeleteString, "DeleteAccessKey",user2Name, "user/"+testUser1);
        
        // user1有其他user权限
        accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1, testUser2, 200));
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, testUser2, 200);
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser2, "Inactive", 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser2, 200);


    }
	
	@Test
    /*
     * allow Action=CreateAccessKey,DeleteAccessKey,ListAccessKeys,UpdateAccessKey,GetAccessKeyLastUsed, resource=group/*
         * 资源和请求的action不匹配，policy不生效
     */
    public void test_AccessKeyALLMethod_Allow_Action_resourceNotMatch() throws JDOMException, IOException {
	 // 创建policy
        String policyName="test_GroupALLMethod_Allow_Action_resourceNotMatch";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:DeleteAccessKey","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        // 验证请求
        // user1因为资源不匹配，无权限
        String user1CreateString=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1, testUser2, 403);
	    AssertAccessDenyString(user1CreateString, "CreateAccessKey",user1Name, "user/"+testUser2);
	    AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(accessKey, secretKey, testUser2, 200));
	    String user1ListString=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, testUser2, 403);
	    AssertAccessDenyString(user1ListString, "ListAccessKeys",user1Name, "user/"+testUser2);
	    String user1GetString=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 403);
	    AssertAccessDenyString_GetAccessKeyLastUsed(user1GetString, "GetAccessKeyLastUsed",user1Name, "access key " + accessKeyResult.accessKeyId);
	    String user1UpdateString=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser2, "Inactive", 403);
	    AssertAccessDenyString(user1UpdateString, "UpdateAccessKey",user1Name, "user/"+testUser2);
	    String user1DeleteString=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser2, 403);
	    AssertAccessDenyString(user1DeleteString, "DeleteAccessKey",user1Name, "user/"+testUser2);
	}
    
	@Test
    /*
     * allow Action=CreateAccessKey,DeleteAccessKey,ListAccessKeys,UpdateAccessKey,GetAccessKeyLastUsed, Notresource=user/testUser1
             * 允许操作， 但是资源是非user/testUser1
     */
    public void test_AccessKeyALLMethod_Allow_Action_NottestUser1() throws JDOMException, IOException {
	    // 创建policy
        String policyName="test_AccessKeyALLMethod_Allow_Action_NottestUser1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:DeleteAccessKey","iam:ListAccessKeys"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+testUser1),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        // 验证请求
        
        // user1有testUser2权限
        AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1, testUser2, 200));
        IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, testUser2, 200);
        IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser2, "Inactive", 200);
        IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser2, 200);
        
        // user2无权限
        String user2CreateString=IAMInterfaceTestUtils.CreateAccessKey(user2accessKey, user2secretKey, testUser1, 403);
        AssertAccessDenyString(user2CreateString, "CreateAccessKey",user2Name, "user/"+testUser1);
        accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(accessKey, secretKey, testUser1, 200));
        String user2ListString=IAMInterfaceTestUtils.ListAccessKeys(user2accessKey, user2secretKey, testUser1, 403);
        AssertAccessDenyString(user2ListString, "ListAccessKeys",user2Name, "user/"+testUser1);
        String user2GetString=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user2accessKey, user2secretKey, accessKeyResult.accessKeyId, 403);
        AssertAccessDenyString_GetAccessKeyLastUsed(user2GetString, "GetAccessKeyLastUsed",user2Name, "access key " + accessKeyResult.accessKeyId);
        String user2UpdateString=IAMInterfaceTestUtils.UpdateAccessKey(user2accessKey, user2secretKey, accessKeyResult.accessKeyId, testUser1, "Inactive", 403);
        AssertAccessDenyString(user2UpdateString, "UpdateAccessKey",user2Name, "user/"+testUser1);
        String user2DeleteString=IAMInterfaceTestUtils.DeleteAccessKey(user2accessKey, user2secretKey, accessKeyResult.accessKeyId, testUser1, 403);
        AssertAccessDenyString(user2DeleteString, "DeleteAccessKey",user2Name, "user/"+testUser1);
        
        // user1对testUser1无权限
        String user1CreateString=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1, testUser1, 403);
	    AssertAccessDenyString(user1CreateString, "CreateAccessKey",user1Name, "user/"+testUser1);
	    accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(accessKey, secretKey, testUser1, 200));
	    String user1ListString=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, testUser1, 403);
	    AssertAccessDenyString(user1ListString, "ListAccessKeys",user1Name, "user/"+testUser1);
	    String user1GetString=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 403);
	    AssertAccessDenyString_GetAccessKeyLastUsed(user1GetString, "GetAccessKeyLastUsed",user1Name, "access key " + accessKeyResult.accessKeyId);
	    String user1UpdateString=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 403);
	    AssertAccessDenyString(user1UpdateString, "UpdateAccessKey",user1Name, "user/"+testUser1);
	    String user1DeleteString=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 403);
	    AssertAccessDenyString(user1DeleteString, "DeleteAccessKey",user1Name, "user/"+testUser1);
    }
    
	@Test
	/*
     * allow Action=CreateAccessKey,DeleteAccessKey,ListAccessKeys,UpdateAccessKey,GetAccessKeyLastUsed, Notresource=user/*
     * AccessKeyAction都无法操作
     */
    public void test_AccessKeyALLMethod_Allow_Action_NotuserALL() throws JDOMException, IOException {
        // 创建policy
        String policyName="test_AccessKeyALLMethod_Allow_Action_NotuserALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:DeleteAccessKey","iam:ListAccessKeys"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        // user1无user所有方法的权限
        String user1CreateString=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1, testUser1, 403);
	    AssertAccessDenyString(user1CreateString, "CreateAccessKey",user1Name, "user/"+testUser1);
	    AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(accessKey, secretKey, testUser1, 200));
	    String user1ListString=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, testUser1, 403);
	    AssertAccessDenyString(user1ListString, "ListAccessKeys",user1Name, "user/"+testUser1);
	    String user1GetString=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 403);
	    AssertAccessDenyString_GetAccessKeyLastUsed(user1GetString, "GetAccessKeyLastUsed",user1Name, "access key " + accessKeyResult.accessKeyId);
	    String user1UpdateString=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 403);
	    AssertAccessDenyString(user1UpdateString, "UpdateAccessKey",user1Name, "user/"+testUser1);
	    String user1DeleteString=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 403);
	    AssertAccessDenyString(user1DeleteString, "DeleteAccessKey",user1Name, "user/"+testUser1);
    }
    
	@Test
	/*
     * allow Action=CreateAccessKey,DeleteAccessKey,ListAccessKeys,UpdateAccessKey,GetAccessKeyLastUsed, Notresource=*
     * AccessKeyAction都无法操作
     */
    public void test_AccessKeyALLMethod_Allow_Action_NotALL() throws JDOMException, IOException {
        // 创建policy
        String policyName="test_AccessKeyALLMethod_Allow_Action_NotALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:DeleteAccessKey","iam:ListAccessKeys"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        // user1无user所有方法的权限
        String user1CreateString=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1, testUser1, 403);
	    AssertAccessDenyString(user1CreateString, "CreateAccessKey",user1Name, "user/"+testUser1);
	    AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(accessKey, secretKey, testUser1, 200));
	    String user1ListString=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, testUser1, 403);
	    AssertAccessDenyString(user1ListString, "ListAccessKeys",user1Name, "user/"+testUser1);
	    String user1GetString=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 403);
	    AssertAccessDenyString_GetAccessKeyLastUsed(user1GetString, "GetAccessKeyLastUsed",user1Name, "access key " + accessKeyResult.accessKeyId);
	    String user1UpdateString=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 403);
	    AssertAccessDenyString(user1UpdateString, "UpdateAccessKey",user1Name, "user/"+testUser1);
	    String user1DeleteString=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 403);
	    AssertAccessDenyString(user1DeleteString, "DeleteAccessKey",user1Name, "user/"+testUser1);
    }
    
	@Test
    /*
     * allow NotAction=CreateAccessKey,DeleteAccessKey,ListAccessKeys,UpdateAccessKey,GetAccessKeyLastUsed,resource=user/testUser1
     * 资源resource只能匹配除了上述操作的其他user资源相关操作
     */
    public void test_AccessKeyALLMethod_Allow_NotAction_testUser1() throws JDOMException, IOException {
	    // 创建policy
        String policyName="test_AccessKeyALLMethod_Allow_NotAction_testUser1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:DeleteAccessKey","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+testUser1),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        // 验证请求
        // user1无上述资源testUser1操作权限，但有其他接口testUser1的操作权限
        String user1CreateString=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1, testUser1, 403);
	    AssertAccessDenyString(user1CreateString, "CreateAccessKey",user1Name, "user/"+testUser1);
	    AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(accessKey, secretKey, testUser1, 200));
	    String user1ListString=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, testUser1, 403);
	    AssertAccessDenyString(user1ListString, "ListAccessKeys",user1Name, "user/"+testUser1);
	    String user1GetString=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 403);
	    AssertAccessDenyString_GetAccessKeyLastUsed(user1GetString, "GetAccessKeyLastUsed",user1Name, "access key " + accessKeyResult.accessKeyId);
	    String user1UpdateString=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 403);
	    AssertAccessDenyString(user1UpdateString, "UpdateAccessKey",user1Name, "user/"+testUser1);
	    String user1DeleteString=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 403);
	    AssertAccessDenyString(user1DeleteString, "DeleteAccessKey",user1Name, "user/"+testUser1);
	    IAMInterfaceTestUtils.DeleteAccessKey(accessKey, secretKey, accessKeyResult.accessKeyId, testUser1, 200);
	    
	    // 验证 除了 上述接口，其他跟group resource相关的接口都允许
	    List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        List<String> excludes=new ArrayList<String>();
        excludes.add("CreateAccessKey");
        excludes.add("ListAccessKeys");
        excludes.add("GetAccessKeyLastUsed");
        excludes.add("UpdateAccessKey");
        excludes.add("DeleteAccessKey");
        String policyName2="test_policy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        
        IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, testUser1, tags, policyName2, policyString2, accountId);
        
    }
    
	@Test
	  /*
     * allow NotAction=CreateAccessKey,DeleteAccessKey,ListAccessKeys,UpdateAccessKey,GetAccessKeyLastUsed,resource=user/*
     * 资源resource只能匹配除了上述操作的其他user/*资源相关操作
     */
    public void test_AccessKeyALLMethod_Allow_NotAction_userAll() throws JDOMException, IOException {
	    // 创建policy
        String policyName="test_AccessKeyALLMethod_Allow_NotAction_userAll";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:DeleteAccessKey","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        // 验证请求
        // user1无上述资源是user操作权限
        String user1CreateString=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1, testUser1, 403);
	    AssertAccessDenyString(user1CreateString, "CreateAccessKey",user1Name, "user/"+testUser1);
	    AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(accessKey, secretKey, testUser1, 200));
	    String user1ListString=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, testUser1, 403);
	    AssertAccessDenyString(user1ListString, "ListAccessKeys",user1Name, "user/"+testUser1);
	    String user1GetString=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 403);
	    AssertAccessDenyString_GetAccessKeyLastUsed(user1GetString, "GetAccessKeyLastUsed",user1Name, "access key " + accessKeyResult.accessKeyId);
	    String user1UpdateString=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 403);
	    AssertAccessDenyString(user1UpdateString, "UpdateAccessKey",user1Name, "user/"+testUser1);
	    String user1DeleteString=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 403);
	    AssertAccessDenyString(user1DeleteString, "DeleteAccessKey",user1Name, "user/"+testUser1);
	    IAMInterfaceTestUtils.DeleteAccessKey(accessKey, secretKey, accessKeyResult.accessKeyId, testUser1, 200);
        
        // 验证 除了上述接口，其他跟user/* resource相关的接口都允许
	    List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        List<String> excludes=new ArrayList<String>();
        excludes.add("CreateAccessKey");
        excludes.add("ListAccessKeys");
        excludes.add("GetAccessKeyLastUsed");
        excludes.add("UpdateAccessKey");
        excludes.add("DeleteAccessKey");
        String policyName2="test_policy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        
        IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, testUser1, tags, policyName2, policyString2, accountId);

    }
	
	@Test
	 /*
     * allow NotAction=CreateAccessKey,DeleteAccessKey,ListAccessKeys,UpdateAccessKey,GetAccessKeyLastUsed,resource=*
     * 资源resource只能匹配除了上述操作的其他*资源相关操作
     */
    public void test_AccessKeyALLMethod_Allow_NotAction_ALL() throws JDOMException, IOException {
		// 创建policy
        String policyName="test_AccessKeyALLMethod_Allow_NotAction_ALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:DeleteAccessKey","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        // 验证请求
        // user1无上述资源user操作权限，但有其他接口user的操作权限
        String user1CreateString=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1, testUser1, 403);
	    AssertAccessDenyString(user1CreateString, "CreateAccessKey",user1Name, "user/"+testUser1);
	    AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(accessKey, secretKey, testUser1, 200));
	    String user1ListString=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, testUser1, 403);
	    AssertAccessDenyString(user1ListString, "ListAccessKeys",user1Name, "user/"+testUser1);
	    String user1GetString=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 403);
	    AssertAccessDenyString_GetAccessKeyLastUsed(user1GetString, "GetAccessKeyLastUsed",user1Name, "access key " + accessKeyResult.accessKeyId);
	    String user1UpdateString=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 403);
	    AssertAccessDenyString(user1UpdateString, "UpdateAccessKey",user1Name, "user/"+testUser1);
	    String user1DeleteString=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 403);
	    AssertAccessDenyString(user1DeleteString, "DeleteAccessKey",user1Name, "user/"+testUser1);
	    IAMInterfaceTestUtils.DeleteAccessKey(accessKey, secretKey, accessKeyResult.accessKeyId, testUser1, 200);
        
        // 验证 除了上述接口，其他跟* resource相关的接口都允许
        List<String> excludes=new ArrayList<String>();
        excludes.add("CreateAccessKey");
        excludes.add("ListAccessKeys");
        excludes.add("GetAccessKeyLastUsed");
        excludes.add("UpdateAccessKey");
        excludes.add("DeleteAccessKey");
        String policyName2="test_policy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey,excludes, user1accessKey1, user1secretKey1, "lala_1", tags, policyName2, policyString2, accountId,"newGroup","mfa2");

    }
    
	@Test
	 /*
     * allow NotAction=CreateAccessKey,DeleteAccessKey,ListAccessKeys,UpdateAccessKey,GetAccessKeyLastUsed,notresource=user/testUser1
     * 资源resource只能匹配除了上述操作的其他非testUser1资源相关操作
     */
    public void test_AccessKeyALLMethod_Allow_NotAction_NottestUser1() throws JDOMException, IOException {
	    // 创建policy
        String policyName="test_AccessKeyALLMethod_Allow_NotAction_NottestUser1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:DeleteAccessKey","iam:ListAccessKeys"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+testUser1),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        // 验证请求
        // user1无上述资源是testUser1操作权限
        String user1CreateString=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1, testUser1, 403);
	    AssertAccessDenyString(user1CreateString, "CreateAccessKey",user1Name, "user/"+testUser1);
	    AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(accessKey, secretKey, testUser1, 200));
	    String user1ListString=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, testUser1, 403);
	    AssertAccessDenyString(user1ListString, "ListAccessKeys",user1Name, "user/"+testUser1);
	    String user1GetString=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 403);
	    AssertAccessDenyString_GetAccessKeyLastUsed(user1GetString, "GetAccessKeyLastUsed",user1Name, "access key " + accessKeyResult.accessKeyId);
	    String user1UpdateString=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 403);
	    AssertAccessDenyString(user1UpdateString, "UpdateAccessKey",user1Name, "user/"+testUser1);
	    String user1DeleteString=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 403);
	    AssertAccessDenyString(user1DeleteString, "DeleteAccessKey",user1Name, "user/"+testUser1);
	    IAMInterfaceTestUtils.DeleteAccessKey(accessKey, secretKey, accessKeyResult.accessKeyId, testUser1, 200);
        
        // 验证 除了 上述接口，其他非testUser1 resource相关的接口都允许
	    List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        List<String> excludes=new ArrayList<String>();
        excludes.add("CreateAccessKey");
        excludes.add("ListAccessKeys");
        excludes.add("GetAccessKeyLastUsed");
        excludes.add("UpdateAccessKey");
        excludes.add("DeleteAccessKey");
        String policyName2="test_policy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        
        // 资源是testUser1的都不允许
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user1accessKey1, user1secretKey1, testUser1, tags, policyName2, policyString2, accountId);
        // 除了上述接口，testUser2可以访问
        IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, testUser2, tags, policyName2, policyString2, accountId);

        // 验证 跟MFA资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null,user1accessKey1, user1secretKey1, accountId, "mfa1");
        // 验证 跟policy资源相关接口允许
        
        String policyName3="test_policy2";
        String policyString3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null,user1accessKey1, user1secretKey1, policyName3, policyString3, accountId);
        // 验证 跟group资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceGroupALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1, "newGroup", "newUser", accountId, policyName2, policyString2);
        // 验证 *资源匹配接口都允许
        IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1,null);
    }
    
	@Test
	/*
     * allow NotAction=CreateAccessKey,DeleteAccessKey,ListAccessKeys,UpdateAccessKey,GetAccessKeyLastUsed,notresource=user/*
     * 资源resource只能匹配除了上述操作的其他非user/*资源相关操作
     */
    public void test_AccessKeyALLMethod_Allow_NotAction_NotuserALL() throws JDOMException, IOException {
	    // 创建policy
        String policyName="test_AccessKeyALLMethod_Allow_NotAction_NotuserALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:DeleteAccessKey","iam:ListAccessKeys"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        // 验证请求
        // user1无上述操作权限
        String user1CreateString=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1, testUser1, 403);
	    AssertAccessDenyString(user1CreateString, "CreateAccessKey",user1Name, "user/"+testUser1);
	    AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(accessKey, secretKey, testUser1, 200));
	    String user1ListString=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, testUser1, 403);
	    AssertAccessDenyString(user1ListString, "ListAccessKeys",user1Name, "user/"+testUser1);
	    String user1GetString=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 403);
	    AssertAccessDenyString_GetAccessKeyLastUsed(user1GetString, "GetAccessKeyLastUsed",user1Name, "access key " + accessKeyResult.accessKeyId);
	    String user1UpdateString=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 403);
	    AssertAccessDenyString(user1UpdateString, "UpdateAccessKey",user1Name, "user/"+testUser1);
	    String user1DeleteString=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 403);
	    AssertAccessDenyString(user1DeleteString, "DeleteAccessKey",user1Name, "user/"+testUser1);
	    IAMInterfaceTestUtils.DeleteAccessKey(accessKey, secretKey, accessKeyResult.accessKeyId, testUser1, 200);
        
        String policyName2="test_policy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        // 资源是user/的都不允许
        IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user1secretKey1, testUser1, tags, policyName2, policyString2, accountId);
        // 资源是group*都不允许
        IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user1secretKey1, testUser2, tags, policyName2, policyString2, accountId);

        // 验证 跟MFA资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null,user1accessKey1, user1secretKey1, accountId, "mfa1");
        // 验证 跟policy资源相关接口允许
        String policyName3="test_policy2";
        String policyString3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null,user1accessKey1, user1secretKey1, policyName3, policyString3, accountId);
        // 验证 跟group资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceGroupALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1, "newGroup", "newUser", accountId, policyName2, policyString2);
        // 验证 *资源匹配接口都允许
        IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1,null);
    }
    
	@Test
	/*
     * allow NotAction=CreateAccessKey,DeleteAccessKey,ListAccessKeys,UpdateAccessKey,GetAccessKeyLastUsed,notresource=*
     */
    public void test_AccessKeyALLMethod_Allow_NotAction_NotALL() throws JDOMException, IOException {
	    // 创建policy
        String policyName="test_AccessKeyALLMethod_Allow_NotAction_NotALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:DeleteAccessKey","iam:ListAccessKeys"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        // 验证请求
        // user1无上述操作权限
        String user1CreateString=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1, testUser1, 403);
	    AssertAccessDenyString(user1CreateString, "CreateAccessKey",user1Name, "user/"+testUser1);
	    AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(accessKey, secretKey, testUser1, 200));
	    String user1ListString=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, testUser1, 403);
	    AssertAccessDenyString(user1ListString, "ListAccessKeys",user1Name, "user/"+testUser1);
	    String user1GetString=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 403);
	    AssertAccessDenyString_GetAccessKeyLastUsed(user1GetString, "GetAccessKeyLastUsed",user1Name, "access key " + accessKeyResult.accessKeyId);
	    String user1UpdateString=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 403);
	    AssertAccessDenyString(user1UpdateString, "UpdateAccessKey",user1Name, "user/"+testUser1);
	    String user1DeleteString=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 403);
	    AssertAccessDenyString(user1DeleteString, "DeleteAccessKey",user1Name, "user/"+testUser1);
	    IAMInterfaceTestUtils.DeleteAccessKey(accessKey, secretKey, accessKeyResult.accessKeyId, testUser1, 200);
        
        String policyName2="test_policy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        IAMInterfaceTestUtils.DenyActionResourceALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "lala_3", tags, policyName2, policyString2, accountId, "newGroup", "mfa3");
    }
    
	@Test
	/*
     * Deny Action=CreateAccessKey,DeleteAccessKey,ListAccessKeys,UpdateAccessKey,GetAccessKeyLastUsed, resource=user/testUser1
     * 拒绝操作group1
     */
    public void test_AccessKeyALLMethod_Deny_Action_testUser1() throws JDOMException, IOException {
	    // 创建policy
        String policyName="Allow_user";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
	    
	    // 创建policy
        String policyName1="test_GroupALLMethod_Deny_Action_group1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:DeleteAccessKey","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+testUser1),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1,200);
        
        // user1对testUser1资源无操作权限
        String user1CreateString=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1, testUser1, 403);
	    AssertAccessDenyString(user1CreateString, "CreateAccessKey",user1Name, "user/"+testUser1);
	    AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(accessKey, secretKey, testUser1, 200));
	    String user1ListString=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, testUser1, 403);
	    AssertAccessDenyString(user1ListString, "ListAccessKeys",user1Name, "user/"+testUser1);
	    String user1GetString=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 403);
	    AssertAccessDenyString_GetAccessKeyLastUsed(user1GetString, "GetAccessKeyLastUsed",user1Name, "access key " + accessKeyResult.accessKeyId);
	    String user1UpdateString=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 403);
	    AssertAccessDenyString(user1UpdateString, "UpdateAccessKey",user1Name, "user/"+testUser1);
	    String user1DeleteString=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 403);
	    AssertAccessDenyString(user1DeleteString, "DeleteAccessKey",user1Name, "user/"+testUser1);
	    IAMInterfaceTestUtils.DeleteAccessKey(accessKey, secretKey, accessKeyResult.accessKeyId, testUser1, 200);
        
        // user资源其他未列出的操作允许
        // 验证 除了 上述接口，其他跟user resource相关的接口都允许
	    List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        List<String> excludes=new ArrayList<String>();
        excludes.add("CreateAccessKey");
        excludes.add("DeleteAccessKey");
        excludes.add("ListAccessKeys");
        excludes.add("UpdateAccessKey");
        excludes.add("GetAccessKeyLastUsed");
        String policyName2="test_policy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        
        IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, testUser1, tags, policyName2, policyString2, accountId);
        
        // user1对testUser2资源所有操作权限
        IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, null, user1accessKey1, user1secretKey1, testUser2, tags, policyName2, policyString2, accountId);
    }
    
	@Test
	/*
     * Deny Action=CreateAccessKey,DeleteAccessKey,ListAccessKeys,UpdateAccessKey,GetAccessKeyLastUsed, resource=user/*
     * 拒绝操作user/*资源的所有操作
     */
    public void test_AccessKeyALLMethod_Deny_Action_userAll() throws JDOMException, IOException {
        // 创建policy
        String policyName="Allow_user";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 创建policy
        String policyName1="test_AccessKeyALLMethod_Deny_Action_userAll";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:DeleteAccessKey","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1,200);
        
        // user1对testUser1资源无操作权限
        String user1CreateString=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1, testUser1, 403);
	    AssertAccessDenyString(user1CreateString, "CreateAccessKey",user1Name, "user/"+testUser1);
	    AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(accessKey, secretKey, testUser1, 200));
	    String user1ListString=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, testUser1, 403);
	    AssertAccessDenyString(user1ListString, "ListAccessKeys",user1Name, "user/"+testUser1);
	    String user1GetString=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 403);
	    AssertAccessDenyString_GetAccessKeyLastUsed(user1GetString, "GetAccessKeyLastUsed",user1Name, "access key " + accessKeyResult.accessKeyId);
	    String user1UpdateString=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 403);
	    AssertAccessDenyString(user1UpdateString, "UpdateAccessKey",user1Name, "user/"+testUser1);
	    String user1DeleteString=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 403);
	    AssertAccessDenyString(user1DeleteString, "DeleteAccessKey",user1Name, "user/"+testUser1);
	    IAMInterfaceTestUtils.DeleteAccessKey(accessKey, secretKey, accessKeyResult.accessKeyId, testUser1, 200);
        
        // 验证 除了 上述接口，其他跟user resource相关的接口都允许
	    List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        List<String> excludes=new ArrayList<String>();
        excludes.add("CreateAccessKey");
        excludes.add("DeleteAccessKey");
        excludes.add("ListAccessKeys");
        excludes.add("UpdateAccessKey");
        excludes.add("GetAccessKeyLastUsed");
        String policyName2="test_policy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        
        // 除了以上接口都可以操作资源testUser1
        IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, testUser1, tags, policyName2, policyString2, accountId);
        
        // 除了以上接口都可以操作资源testUser2
        IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, testUser2, tags, policyName2, policyString2, accountId);
    }
    
	@Test
    /*
     * Deny Action=CreateAccessKey,DeleteAccessKey,ListAccessKeys,UpdateAccessKey,GetAccessKeyLastUsed, resource=*
     * 拒绝操作*资源的所有操作
     */
    public void test_AccessKeyALLMethod_Deny_Action_ALL() throws JDOMException, IOException {
		// 创建policy
        String policyName="Allow_user";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 创建policy
        String policyName1="test_AccessKeyALLMethod_Deny_Action_ALL";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:DeleteAccessKey","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1,200);
        
        // user1对testUser1资源无操作权限
        String user1CreateString=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1, testUser1, 403);
	    AssertAccessDenyString(user1CreateString, "CreateAccessKey",user1Name, "user/"+testUser1);
	    AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(accessKey, secretKey, testUser1, 200));
	    String user1ListString=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, testUser1, 403);
	    AssertAccessDenyString(user1ListString, "ListAccessKeys",user1Name, "user/"+testUser1);
	    String user1GetString=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 403);
	    AssertAccessDenyString_GetAccessKeyLastUsed(user1GetString, "GetAccessKeyLastUsed",user1Name, "access key " + accessKeyResult.accessKeyId);
	    String user1UpdateString=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 403);
	    AssertAccessDenyString(user1UpdateString, "UpdateAccessKey",user1Name, "user/"+testUser1);
	    String user1DeleteString=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 403);
	    AssertAccessDenyString(user1DeleteString, "DeleteAccessKey",user1Name, "user/"+testUser1);
	    IAMInterfaceTestUtils.DeleteAccessKey(accessKey, secretKey, accessKeyResult.accessKeyId, testUser1, 200);
        
        // 验证 除了 上述接口，其他跟user resource相关的接口都允许
	    List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        tags.add(tag);
        List<String> excludes=new ArrayList<String>();
        excludes.add("CreateAccessKey");
        excludes.add("DeleteAccessKey");
        excludes.add("ListAccessKeys");
        excludes.add("UpdateAccessKey");
        excludes.add("GetAccessKeyLastUsed");
        String policyName2="test_policy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        
        // 除了以上接口都可以操作资源testUser1
        IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, testUser1, tags, policyName2, policyString2, accountId);
        
        // 除了以上接口都可以操作资源testUser2
        IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, testUser2, tags, policyName2, policyString2, accountId);
    }
    
    @Test
    /*
     * Deny Action=CreateAccessKey,DeleteAccessKey,ListAccessKeys,UpdateAccessKey,GetAccessKeyLastUsed, resource=group/*
     * 资源不匹配，deny失败
     */
    public void test_AccessKeyALLMethod_Deny_Action_ResourceNotMatch() throws JDOMException, IOException {
        // 创建policy
        String policyName="Allow_user";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 创建policy
        String policyName1="test_AccessKeyALLMethod_Deny_Action_ResourceNotMatch";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:DeleteAccessKey","iam:ListAccessKeys"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1,200);
        
        // 资源不匹配失效
        AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1, testUser1, 200));
	    IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, testUser1, 200);
	    IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 200);
	    IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 200);
	    IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 200);
    }
    
    @Test
    /*
     * Deny Action=CreateAccessKey,DeleteAccessKey,ListAccessKeys,UpdateAccessKey,GetAccessKeyLastUsed, NotResource=user/testUser1
     * 
     */
    public void test_AccessKeyALLMethod_Deny_Action_NottestUser1() throws JDOMException, IOException {
        // 创建policy
        String policyName="Allow_user";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 创建policy
        String policyName1="test_AccessKeyALLMethod_Deny_Action_NottestUser1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:DeleteAccessKey","iam:ListAccessKeys"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/"+testUser1),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1,200);
        
        // user1有testUser1权限
        AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1, testUser1, 200));
	    IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, testUser1, 200);
	    IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 200);
	    IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 200);
	    IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 200);
        
        // user1无其他user权限
	    String user1CreateString=IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1, testUser2, 403);
	    AssertAccessDenyString(user1CreateString, "CreateAccessKey",user1Name, "user/"+testUser2);
	    accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(accessKey, secretKey, testUser2, 200));
	    String user1ListString=IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, testUser2, 403);
	    AssertAccessDenyString(user1ListString, "ListAccessKeys",user1Name, "user/"+testUser2);
	    String user1GetString=IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 403);
	    AssertAccessDenyString_GetAccessKeyLastUsed(user1GetString, "GetAccessKeyLastUsed",user1Name, "access key " + accessKeyResult.accessKeyId);
	    String user1UpdateString=IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser2, "Inactive", 403);
	    AssertAccessDenyString(user1UpdateString, "UpdateAccessKey",user1Name, "user/"+testUser2);
	    String user1DeleteString=IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser2, 403);
	    AssertAccessDenyString(user1DeleteString, "DeleteAccessKey",user1Name, "user/"+testUser2);
	    IAMInterfaceTestUtils.DeleteAccessKey(accessKey, secretKey, accessKeyResult.accessKeyId, testUser2, 200);
    }
    
    @Test
    /*
     * Deny Action=CreateAccessKey,DeleteAccessKey,ListAccessKeys,UpdateAccessKey,GetAccessKeyLastUsed, NotResource=user/*
     * 
     */
    public void test_AccessKeyALLMethod_Deny_Action_NotuserALL() throws JDOMException, IOException {
        // 创建policy
        String policyName="Allow_user";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 创建policy
        String policyName1="test_AccessKeyALLMethod_Deny_Action_NotuserALL";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateAccessKey","iam:UpdateAccessKey","iam:GetAccessKeyLastUsed","iam:DeleteAccessKey","iam:ListAccessKeys"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        
        // 给用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1,200);
        
        // user1有testUser1权限
        AccessKeyResult accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1, testUser1, 200));
	    IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, testUser1, 200);
	    IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 200);
	    IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, "Inactive", 200);
	    IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser1, 200);
        
        // user1其他user权限
	    accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(IAMInterfaceTestUtils.CreateAccessKey(user1accessKey1, user1secretKey1, testUser2, 200));
	    IAMInterfaceTestUtils.ListAccessKeys(user1accessKey1, user1secretKey1, testUser2, 200);
	    IAMInterfaceTestUtils.GetAccessKeyLastUsed(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, 200);
	    IAMInterfaceTestUtils.UpdateAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser2, "Inactive", 200);
	    IAMInterfaceTestUtils.DeleteAccessKey(user1accessKey1, user1secretKey1, accessKeyResult.accessKeyId, testUser2, 200);
    }
	
	
	public static String AssertCreateUserResult(String xml,String userName,List<Pair<String,String>> tags) {
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
	
	public void AssertAccessDenyString(String xml,String methodString,String userName,String resource) {
	    try {
	        JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
	        assertEquals("AccessDenied", error.get("Code"));
	        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+userName+" is not authorized to perform: iam:"+methodString+" on resource: arn:ctyun:iam::3rmoqzn03g6ga:"+resource+".", error.get("Message"));
	        assertEquals("", error.get("Resource"));
        } catch (Exception e) {
            e.printStackTrace();
        }
	    
    }
	
	public void AssertAccessDenyString_GetAccessKeyLastUsed(String xml,String methodString,String userName,String resource) {
	    try {
	        JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
	        assertEquals("AccessDenied", error.get("Code"));
	        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+userName+" is not authorized to perform: iam:"+methodString+" on resource: "+resource+".", error.get("Message"));
	        assertEquals("", error.get("Resource"));
        } catch (Exception e) {
            e.printStackTrace();
        }
	    
    }

}
