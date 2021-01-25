package cn.ctyun.oos.iam.test.iamaccesscontrol;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.StringReader;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xml.sax.InputSource;

import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.Condition;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;
import common.tuple.Pair;

public class GroupActionAccessTest {
	
	public static final String OOS_IAM_DOMAIN="https://oos-cd-iam.ctyunapi.cn:9460/";
	public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
	public static final String regionName="cd";
	
	private static String ownerName = "root_user@test.com";
	public static final String accessKey="userak";
	public static final String secretKey="usersk";
	
	public static final String user1Name="test_1";
	public static final String user2Name="test_2";
	public static final String user3Name="Abc1";
	public static final String user1accessKey1="abcdefghijklmnop";
	public static final String user1secretKey1="cccccccccccccccc";
	public static final String user1accessKey2="1234567890123456";
	public static final String user1secretKey2="user1secretKey2lllll";
	public static final String user2accessKey="qrstuvwxyz0000000";
	public static final String user2secretKey="bbbbbbbbbbbbbbbbbb";
	public static final String user3accessKey="abcdefgh12345678";
	public static final String user3secretKey="3333333333333333";
	
	public static String accountId="3rmoqzn03g6ga";
	public static String mygroupName="mygroup";
	
	
	
	public static OwnerMeta owner = new OwnerMeta(ownerName);
    public static MetaClient metaClient = MetaClient.getGlobalClient();

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {

//		IAMTestUtils.TrancateTable("oos-aksk-yx");
//		IAMTestUtils.TrancateTable(IAMTestUtils.iamAccountSummaryTable);
//		
//		// 创建根用户
//		owner.email=ownerName;
//		owner.setPwd("123456");
//		owner.maxAKNum=10;
//		owner.displayName="测试根用户";
//		owner.bucketCeilingNum=10;
//		metaClient.ownerInsertForTest(owner);
//		
//		AkSkMeta aksk=new AkSkMeta(owner.getId());
//        aksk.accessKey=accessKey;
//        aksk.setSecretKey(secretKey);
//        aksk.isPrimary=1;
//        metaClient.akskInsert(aksk);
//        
//        
//		String UserName1=user1Name;
//		User user1=new User();
//        user1.accountId=accountId;
//        user1.userName=UserName1;
//        user1.userId="test1abc";
//        user1.createDate=System.currentTimeMillis();
//        try {
//            boolean success=HBaseUtils.checkAndCreate(user1);
//            assertTrue(success);
//        } catch (IOException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//        }
//
//		// 插入数据库aksk
//		AkSkMeta aksk1 = new AkSkMeta(owner.getId());
//        aksk1.isRoot = 0;
//        aksk1.userId = user1.userId;
//        aksk1.userName = UserName1;
//        aksk1.accessKey=user1accessKey1;
//        aksk1.setSecretKey(user1secretKey1);
//        metaClient.akskInsert(aksk1);
//        user1.accessKeys = new ArrayList<>();
//        user1.accessKeys.add(aksk1.accessKey);
//        
//        aksk1.accessKey=user1accessKey2;
//        aksk1.setSecretKey(user1secretKey2);
//        metaClient.akskInsert(aksk1);
//        user1.accessKeys.add(aksk1.accessKey);
//        HBaseUtils.put(user1);
//		
//        String UserName2=user2Name;
//        User user2=new User();
//        user2.accountId=accountId;
//        user2.userName=UserName2;
//        user2.userId="Test1Abc";
//        user2.createDate=System.currentTimeMillis();
//        try {
//            boolean success=HBaseUtils.checkAndCreate(user2);
//            assertTrue(success);
//        } catch (IOException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//        }
//		
//		AkSkMeta aksk2 = new AkSkMeta(owner.getId());
//        aksk2.isRoot = 0;
//        aksk2.userId = user2.userId;
//        aksk2.userName = UserName2;
//        aksk2.accessKey=user2accessKey;
//        aksk2.setSecretKey(user2secretKey);
//        metaClient.akskInsert(aksk2);
//        user2.accessKeys = new ArrayList<>();
//        user2.userName=UserName2;
//        user2.accessKeys.add(aksk2.accessKey);
//        HBaseUtils.put(user2);
//		
//        String UserName3=user3Name;
//        User user3=new User();
//        user3.accountId=accountId;
//        user3.userName=UserName3;
//        user3.userId="abc1";
//        user3.createDate=System.currentTimeMillis();
//        try {
//            boolean success=HBaseUtils.checkAndCreate(user3);
//            assertTrue(success);
//        } catch (IOException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//        }
//		
//		AkSkMeta aksk3 = new AkSkMeta(owner.getId());
//		aksk3.isRoot = 0;
//		aksk3.userId = user3.userId;
//		aksk3.userName = UserName3;
//		aksk3.accessKey=user3accessKey;
//		aksk3.setSecretKey(user3secretKey);
//        metaClient.akskInsert(aksk3);
//        
//        user3.accessKeys = new ArrayList<>();
//        user3.userName=UserName3;
//        user3.accessKeys.add(aksk3.accessKey);
//        HBaseUtils.put(user3);   
	}

	@Before
	public void setUp() throws Exception {
		IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
		IAMTestUtils.TrancateTable(IAMTestUtils.iamGroupTable);
		IAMTestUtils.TrancateTable(IAMTestUtils.iammfaDeviceTable);
//		
		String groupName=mygroupName;
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey,groupName,200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, user1Name,200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, user3Name,200);
	}

	@Test
	/*
	 * allow Action=CreateGroup, resource=group/group1
	 * 只允许创建group1
	 */
	public void test_CreateGroup_Allow_Action_group1() throws JSONException {
		// 创建policy
		String policyName="test_CreateGroup_Allow_Action_group1";
		String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/testGroup01"),null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
		
		// 给用户添加policy
		String userName="test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
		
		// 验证请求
		String groupName="testGroup01";

		String user2xmlString=IAMInterfaceTestUtils.CreateGroup(user2accessKey, user2secretKey,groupName,403);
		JSONObject error=IAMTestUtils.ParseErrorToJson(user2xmlString);
        assertEquals("AccessDenied", error.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+" is not authorized to perform: iam:CreateGroup on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup01.", error.get("Message"));
        assertEquals(groupName, error.get("Resource"));
        
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1,groupName, 200);
		
        String groupName2="testGroup02";
		String user1bxmlString=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1,groupName2,403);
		JSONObject error2=IAMTestUtils.ParseErrorToJson(user1bxmlString);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateGroup on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup02.", error2.get("Message"));
        assertEquals(groupName2, error2.get("Resource"));
	}
	
	@Test
	/*
	 * allow Action=CreateGroup, resource=group/*
	 * 可以创建所有group
	 */
	public void test_CreateGroup_Allow_Action_all() throws JSONException {
	    // 创建policy
        String policyName="CreateGroupPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);

        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        
        // 验证请求
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1,groupName, 200);

        String user2xmlString=IAMInterfaceTestUtils.CreateGroup(user2accessKey, user2secretKey,groupName,403);
        JSONObject error=IAMTestUtils.ParseErrorToJson(user2xmlString);
        assertEquals("AccessDenied", error.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+" is not authorized to perform: iam:CreateGroup on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup01.", error.get("Message"));
        assertEquals(groupName, error.get("Resource"));
        
        String groupName2="testGroup02";
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1,groupName2,200);
        
	}
	
	@Test
	/*
	 * allow Action=CreateGroup, resource=*
	 * 可以创建所有group
	 */
	public void test_CreateGroup_Allow_Action_all2() throws JSONException {
	 // 创建policy
        String policyName="CreateGroupPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);

        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        
        // 验证请求
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1,groupName, 200);

        String user2xmlString=IAMInterfaceTestUtils.CreateGroup(user2accessKey, user2secretKey,groupName,403);
        JSONObject error=IAMTestUtils.ParseErrorToJson(user2xmlString);
        assertEquals("AccessDenied", error.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+" is not authorized to perform: iam:CreateGroup on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup01.", error.get("Message"));
        assertEquals(groupName, error.get("Resource"));
        
        String groupName2="testGroup02";
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1,groupName2,200);
	}
	
	@Test
	/*
	 * allow Action=CreateGroup, resource=user/*
	 * 资源和请求的action不匹配，policy不生效
	 */
	public void test_CreateGroup_Allow_Action_resourceNotMatch() throws JSONException {
	    // 创建policy
        String policyName="CreateGroupPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);

        // 验证请求
        String groupName="testGroup01";
        String user1a=IAMInterfaceTestUtils.CreateGroup(user2accessKey, user2secretKey, groupName, 403);
        JSONObject error=IAMTestUtils.ParseErrorToJson(user1a);
        assertEquals("AccessDenied", error.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+" is not authorized to perform: iam:CreateGroup on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup01.", error.get("Message"));
        assertEquals(groupName, error.get("Resource"));
        
        String groupName2="testGroup02";
        String user1b=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(user1b);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateGroup on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup02.", error2.get("Message"));
        assertEquals(groupName2, error2.get("Resource"));
	}
	
	@Test
	/*
	 * allow NotAction=CreateGroup, resource=group/group1
	 * 资源resource只能匹配除了CreateGroup的其他group相关操作
	 */
	public void test_CreateGroup_Allow_NotAction_group1() throws JSONException {
		//
	    String groupName="testGroup01";
	    String groupName2="testGroup02";
	    String policyName="CreateGroupPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/"+groupName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);

        // 验证创建group1 和group2都不允许
        String createGroup1String=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        JSONObject error=IAMTestUtils.ParseErrorToJson(createGroup1String);
        assertEquals("AccessDenied", error.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateGroup on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup01.", error.get("Message"));
        assertEquals("testGroup01", error.get("Resource"));
        
        String createGroup2String=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(createGroup2String);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateGroup on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup02.", error2.get("Message"));
        assertEquals("testGroup02", error2.get("Resource"));

        // 验证 除了 create group其他跟group resource相关的方法都允许
        List<String> excludes=new ArrayList<String>();
        excludes.add("CreateGroup");
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, groupName, userName, accountId, policyName, policyString);
        
        // 和資源不匹配的group02不允許
        IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1, groupName2, userName, accountId, policyName, policyString);
        
        // list group拒绝
        String listgroupString=IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 403);
        JSONObject error3=IAMTestUtils.ParseErrorToJson(listgroupString);
        assertEquals("AccessDenied", error3.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:ListGroups on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/*.", error3.get("Message"));
        assertEquals("/", error3.get("Resource"));
        
        // 验证 跟MFA资源相关接口都不允许
        IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1, accountId, "mfa1");
        // 验证 跟policy资源相关接口都不允许
        IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1, policyName, policyString, accountId);
        // 验证 跟user资源相关接口都不允许
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "lala_1", tags, policyName, policyString, accountId);
	
        // 验证 其他资源不匹配接口都不允许
        IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}
	
	@Test
	/*
	 * allow NotAction=CreateGroup, resource=group/*
	 * 资源resource只能匹配除了CreateGroup的其他group相关操作
	 */
	public void test_CreateGroup_Allow_NotAction_groupall() throws JSONException {
		//
	    String groupName="testGroup01";
        String groupName2="testGroup02";
        String policyName="CreateGroupPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);

        // 验证创建group1 和group2都不允许
        String createGroup1String=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        JSONObject error=IAMTestUtils.ParseErrorToJson(createGroup1String);
        assertEquals("AccessDenied", error.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateGroup on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup01.", error.get("Message"));
        assertEquals("testGroup01", error.get("Resource"));
        
        String createGroup2String=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(createGroup2String);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateGroup on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup02.", error2.get("Message"));
        assertEquals("testGroup02", error2.get("Resource"));
        
        
        // 验证 除了 create group其他跟group resource相关的方法都允许
        List<String> excludes=new ArrayList<String>();
        excludes.add("CreateGroup");
        IAMInterfaceTestUtils.AllowActionResourceGroupALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, groupName, userName, accountId, policyName, policyString);
        
        IAMInterfaceTestUtils.AllowActionResourceGroupALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, groupName2, userName, accountId, policyName, policyString);
        
        
        // 验证 跟MFA资源相关接口都不允许
        IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1, accountId, "mfa1");
        // 验证 跟policy资源相关接口都不允许
        IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1, policyName, policyString, accountId);
        // 验证 跟user资源相关接口都不允许
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "test_11", tags, policyName, policyString, accountId);
    
        // 验证 其他资源不匹配接口都不允许
        IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
		
	}
	
	@Test
	/*
	 * allow NotAction=CreateGroup, resource=*
	 * 可匹配除了CreateGroup的所有其他操作
	 */
	public void test_CreateGroup_Allow_NotAction_all() throws JSONException {
	    String groupName="testGroup01";
        String groupName2="testGroup02";
        String policyName="CreateGroupPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);

        // 验证创建group1 和group2都不允许
        String createGroup1String=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        JSONObject error=IAMTestUtils.ParseErrorToJson(createGroup1String);
        assertEquals("AccessDenied", error.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateGroup on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup01.", error.get("Message"));
        assertEquals("testGroup01", error.get("Resource"));
        
        String createGroup2String=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(createGroup2String);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateGroup on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup02.", error2.get("Message"));
        assertEquals("testGroup02", error2.get("Resource"));
        
        
        // 验证 除了 create group所有方法都允許
        List<String> excludes=new ArrayList<String>();
        excludes.add("CreateGroup");

        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        String policyName2="CreateGroupPolicy2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        
        IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey,excludes, user1accessKey1, user1secretKey1, "test_7", tags, policyName2, policyString2, accountId,groupName,"mfa2");
	}
	
	@Test
    /*
     * allow Action=CreateGroup, Notresource=group/group1
             * 允许create group 但是资源是非group/group1
     */
    public void test_CreateGroup_Allow_Action_Notgroup1() throws JSONException {
	    // 创建policy
        String policyName="CreateGroupPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/testGroup01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 验证请求
        String groupName="testGroup01";
        String createGroupString=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1,groupName, 403);
        JSONObject error=IAMTestUtils.ParseErrorToJson(createGroupString);
        assertEquals("AccessDenied", error.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateGroup on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup01.", error.get("Message"));
        assertEquals("testGroup01", error.get("Resource"));
        
        String groupName2="testGroup02";
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1,groupName2,200); 
    }
	
	@Test
    /*
     * allow Action=CreateGroup, Notresource=group/*
             * 允许create group 但是资源是非group/*
     */
    public void test_CreateGroup_Allow_Action_NotgroupALL() throws JSONException {
	    // 创建policy
        String policyName="CreateGroupPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 验证请求
        String groupName="testGroup01";
        String createGroupString=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1,groupName, 403);
        JSONObject error=IAMTestUtils.ParseErrorToJson(createGroupString);
        assertEquals("AccessDenied", error.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateGroup on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup01.", error.get("Message"));
        assertEquals("testGroup01", error.get("Resource"));
        
        String groupName2="testGroup02";
        String createGroup2String=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1,groupName2,403); 
        JSONObject error2=IAMTestUtils.ParseErrorToJson(createGroup2String);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateGroup on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup02.", error2.get("Message"));
        assertEquals("testGroup02", error2.get("Resource"));
    }
	
	@Test
    /*
     * allow Action=CreateGroup, Notresource*
     * 允许create group 但是资源是非*
     */
    public void test_CreateGroup_Allow_Action_NotALL() throws JSONException {
	    // 创建policy
        String policyName="CreateGroupPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 验证请求
        String groupName="testGroup01";
        String createGroupString=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1,groupName, 403);
        JSONObject error=IAMTestUtils.ParseErrorToJson(createGroupString);
        assertEquals("AccessDenied", error.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateGroup on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup01.", error.get("Message"));
        assertEquals("testGroup01", error.get("Resource"));
        
        String groupName2="testGroup02";
        String createGroup2String=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1,groupName2,403); 
        JSONObject error2=IAMTestUtils.ParseErrorToJson(createGroup2String);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user1Name+" is not authorized to perform: iam:CreateGroup on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup02.", error2.get("Message"));
        assertEquals("testGroup02", error2.get("Resource"));
    }
	
	
	@Test
	/*
     * allow NotAction=CreateGroup, NotResource=group/groupname
     * 允许非create group 但是资源是非group/<group>
     */
    public void test_CreateGroup_Allow_NotAction_Notgroup1() throws JSONException {
	    String groupName="testGroup01";
        String groupName2="testGroup02";
        // 创建policy
        String policyName="CreateGroupPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/"+groupName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName="test_2";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 验证创建group1 和group2都不允许
        String createGroup1String=IAMInterfaceTestUtils.CreateGroup(user2accessKey, user2secretKey, groupName, 403);
        JSONObject error=IAMTestUtils.ParseErrorToJson(createGroup1String);
        assertEquals("AccessDenied", error.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+" is not authorized to perform: iam:CreateGroup on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup01.", error.get("Message"));
        assertEquals("testGroup01", error.get("Resource"));
        
        String createGroup2String=IAMInterfaceTestUtils.CreateGroup(user2accessKey, user2secretKey, groupName2, 403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(createGroup2String);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+" is not authorized to perform: iam:CreateGroup on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup02.", error2.get("Message"));
        assertEquals("testGroup02", error2.get("Resource"));
        
        // 资源为group/<group>的是都不允许
        IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey, user2accessKey, user2secretKey, groupName, userName, accountId, policyName, policyString);
        // list groups 允许
        IAMInterfaceTestUtils.ListGroups(user2accessKey, user2secretKey, groupName, 200);
        
        // 验证 跟MFA资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null,user2accessKey, user2secretKey, accountId, "mfa1");
        // 验证 跟policy资源相关接口都允许
        String policyName1="testPolicy";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/"+groupName),null);
        IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null,user2accessKey, user2secretKey, policyName1, policyString1, accountId);
         //验证 跟user资源相关接口都允许
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, null,user2accessKey, user2secretKey, "lala_18", tags, policyName, policyString, accountId);
    
        // 验证 其他资源不匹配接口都允许
        IAMInterfaceTestUtils.AllowActionResourceOthers(user2accessKey, user2secretKey,null);
        
    }
	
	@Test
	/*
     * allow NotAction=CreateGroup, NotResource=group/*
     * 允许非create group 但是资源是非group/*
     */
    public void test_CreateGroup_Allow_NotAction_NotgroupALL() throws JSONException {
	    String groupName="testGroup01";
        String groupName2="testGroup02";
        // 创建policy
        String policyName="CreateGroupPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName="test_2";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 验证创建group1 和group2都不允许
        String createGroup1String=IAMInterfaceTestUtils.CreateGroup(user2accessKey, user2secretKey, groupName, 403);
        JSONObject error=IAMTestUtils.ParseErrorToJson(createGroup1String);
        assertEquals("AccessDenied", error.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+" is not authorized to perform: iam:CreateGroup on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup01.", error.get("Message"));
        assertEquals("testGroup01", error.get("Resource"));
        
        String createGroup2String=IAMInterfaceTestUtils.CreateGroup(user2accessKey, user2secretKey, groupName2, 403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(createGroup2String);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+" is not authorized to perform: iam:CreateGroup on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup02.", error2.get("Message"));
        assertEquals("testGroup02", error2.get("Resource"));
        
        IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user2accessKey, user2secretKey, groupName2, userName, accountId, policyName, policyString);
        
        // 验证 跟MFA资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null,user2accessKey, user2secretKey, accountId, "mfa1");
        // 验证 跟policy资源相关接口都允许
        String policyName1="testPolicy";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/"+groupName),null);
        IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null,user2accessKey, user2secretKey, policyName1, policyString1, accountId);
         //验证 跟user资源相关接口都允许
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, null,user2accessKey, user2secretKey, "lala_4", tags, policyName, policyString, accountId);
    
        // 验证 其他资源不匹配接口都允许
        IAMInterfaceTestUtils.AllowActionResourceOthers(user2accessKey, user2secretKey,null);
    }
	
	@Test
	/*
     * allow NotAction=CreateGroup, NotResource=*
     * 允许非create group 但是资源是非group/*
     */
    public void test_CreateGroup_Allow_NotAction_NotALL() throws JSONException {
	    String groupName="testGroup01";
        String groupName2="testGroup02";
        // 创建policy
        String policyName="CreateGroupPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName="test_2";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 验证创建group1 和group2都不允许
        String createGroup1String=IAMInterfaceTestUtils.CreateGroup(user2accessKey, user2secretKey, groupName, 403);
        JSONObject error=IAMTestUtils.ParseErrorToJson(createGroup1String);
        assertEquals("AccessDenied", error.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+" is not authorized to perform: iam:CreateGroup on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup01.", error.get("Message"));
        assertEquals("testGroup01", error.get("Resource"));
        
        String createGroup2String=IAMInterfaceTestUtils.CreateGroup(user2accessKey, user2secretKey, groupName2, 403);
        JSONObject error2=IAMTestUtils.ParseErrorToJson(createGroup2String);
        assertEquals("AccessDenied", error2.get("Code"));
        assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+user2Name+" is not authorized to perform: iam:CreateGroup on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup02.", error2.get("Message"));
        assertEquals("testGroup02", error2.get("Resource"));
        
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        IAMInterfaceTestUtils.DenyActionResourceALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "test_21", tags, policyName, policyString, accountId,groupName,"mfa3");
    }
	
	@Test
	/*
	 * Deny Action=CreateGroup, resource=group/group1
	 * 显示拒绝创建group1
	 */
	public void test_CreateGroup_Deny_Action_group1() {
	    String groupName="testGroup01";
	    String userName="test_1";
	    // 创建policy
        String policyName="DenyCreateGroupPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/"+groupName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 显示拒绝
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        
        String policyName2="AllowCreateGroupPolicy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:GetGroup","iam:DeleteGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/"+groupName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2,200);
        
        // 显示拒绝优先，user1没有权限创建用户组，但有权限get 和delete用户组
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName, 200);
        
	}
	
	
	@Test
	/*
	 * Deny Action=CreateGroup, resource=group/*
	 */
	public void test_CreateGroup_Deny_Action_groupall() {
	    String groupName="testGroup01";
	    String userName="test_1";
        // 创建policy
        String policyName="DenyCreateGroupPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 显示拒绝
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        
        String policyName2="AllowCreateGroupPolicy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:GetGroup","iam:DeleteGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/"+groupName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2,200);
        
        // 显示拒绝优先，user1没有权限创建用户组，但有权限get 和delete用户组
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName, 200);
	}
	
	@Test
    /*
     * Deny Action=CreateGroup, resource=group/*
     */
    public void test_CreateGroup_Deny_Action_all() {
        String groupName="testGroup01";
        String userName="test_1";
        // 创建policy
        String policyName="DenyCreateGroupPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 显示拒绝
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
          
        String policyName2="AllowCreateGroupPolicy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:GetGroup","iam:DeleteGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/"+groupName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2,200);
        
        // user1没有权限创建用户组，但有权限get 和delete用户组
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName, 200);
    }
	
	@Test
    /*
     * Deny Action=CreateGroup, resource=user/*
     * 资源不匹配，deny失败
     */
    public void test_CreateGroup_Deny_Action_ReourceNotMatch() {
        String groupName="testGroup01";
        String userName="test_1";
        // 创建policy
        String policyName="DenyCreateGroupPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 显示拒绝资源不匹配未生效
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        
        String policyName2="AllowCreateGroupPolicy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:GetGroup","iam:DeleteGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/"+groupName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2,200);
        
        // 显示拒绝未生效，有显示允许，user1可以create，get 和delete用户组
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName, 200);
    }
	
	@Test
	 /*
     * Deny Action=CreateGroup, NotResource=group/<group>
     * 资源非group1,显示拒绝group1失效，显示拒绝group2生效
     */
	public void test_CreateGroup_Deny_Action_NotResouce_group1() {
	    String groupName="testGroup01";
	    String groupName2="testGroup02";
        String userName="test_1";
        // 创建policy
        String policyName="DenyCreateGroupPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/"+groupName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 403);
        
        String policyName2="AllowCreateGroupPolicy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:GetGroup","iam:DeleteGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2,200);
        
        // 显示拒绝group1失效
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName, 200);
        
        // 显示拒绝group2生效
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 403);
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName2, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        
    }
	
	
	
	@Test
    /*
    * Deny Action=CreateGroup, NotResource=group/*
    */
	public void test_CreateGroup_Deny_Action_NotResouce_groupAll() {
       String groupName="testGroup01";
       String groupName2="testGroup02";
       String userName="test_1";
       // 创建policy
       String policyName="DenyCreateGroupPolicy";
       String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
       IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
       IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
       
       // 
       IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
       IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 403);
       
       String policyName2="AllowCreateGroupPolicy";
       String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:GetGroup","iam:DeleteGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
       IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
       IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2,200);
       
       // 显示拒绝group1失效
       IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200);
       IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
       IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName, 200);
       
       // 显示拒绝group2失效
       IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 200);
       IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName2, 200);
       IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName2, 200);
       
	}
	
	@Test
    /*
    * Deny Action=CreateGroup, NotResource=*
    */
    public void test_CreateGroup_Deny_Action_NotResouce_All() {
       String groupName="testGroup01";
       String groupName2="testGroup02";
       String userName="test_1";
       // 创建policy
       String policyName="DenyCreateGroupPolicy";
       String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
       IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
       IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
       
       // 
       IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
       IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 403);
       
       String policyName2="AllowCreateGroupPolicy";
       String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:GetGroup","iam:DeleteGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
       IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
       IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2,200);
       
       // 显示拒绝group1失效
       IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200);
       IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
       IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName, 200);
       
       // 显示拒绝group2失效
       IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 200);
       IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName2, 200);
       IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName2, 200);
       
    }
	
	@Test
	/*
	 * Deny NotAction=CreateGroup, Resource=group/<group1>
	 */
	public void test_CreateGroup_Deny_NotAction_Resource_group1() {
	       String groupName="testGroup01";
	       String groupName2="testGroup02";
	       String userName="test_1";
	       // 创建policy
	       String policyName="DenyCreateGroupPolicy";
	       String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/"+groupName),null);
	       IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
	       IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
	       
	       // 
	       IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
	       IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 403);
	       
	       String policyName2="AllowCreateGroupPolicy";
	       String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:GetGroup","iam:DeleteGroup","iam:GetAccountPasswordPolicy"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
	       IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
	       IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2,200);
	       
	       // 显示拒绝group1的get和delete方法
	       IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200);
	       IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 403);
	       IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName, 403);
	       
	       // 显示拒绝group2失效
	       IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 200);
	       IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName2, 200);
	       IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName2, 200);
	       
	       IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey1, user1secretKey1, 200);
    }
	
	@Test
    /*
     * Deny NotAction=CreateGroup, Resource=group/*
     */
    public void test_CreateGroup_Deny_NotAction_Resource_groupAll() {
           String groupName="testGroup01";
           String groupName2="testGroup02";
           String userName="test_1";
           // 创建policy
           String policyName="DenyCreateGroupPolicy";
           String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
           IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
           IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
           
           // 
           IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
           IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 403);
           
           String policyName2="AllowCreateGroupPolicy";
           String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:GetGroup","iam:DeleteGroup","iam:GetAccountPasswordPolicy"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
           IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
           IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2,200);
           
           // 显示拒绝group1的get和delete方法
           IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200);
           IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 403);
           IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName, 403);
           
           // 显示拒绝group2的get和delete方法
           IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 200);
           IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName2, 403);
           IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName2, 403);
           
           IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey1, user1secretKey1, 200);
    }
	
	@Test
    /*
     * Deny NotAction=CreateGroup, Resource=*
     */
    public void test_CreateGroup_Deny_NotAction_Resource_All() {
           String groupName="testGroup01";
           String groupName2="testGroup02";
           String userName="test_1";
           // 创建policy
           String policyName="DenyCreateGroupPolicy";
           String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
           IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
           IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
           
           // 
           IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
           IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 403);
           
           String policyName2="AllowCreateGroupPolicy";
           String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:GetGroup","iam:DeleteGroup","iam:GetAccountPasswordPolicy"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
           IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
           IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2,200);
           
           // 显示拒绝group1的get和delete方法
           IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200);
           IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 403);
           IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName, 403);
           
           // 显示拒绝group2的get和delete方法
           IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 200);
           IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName2, 403);
           IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName2, 403);
           
           IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
    }
	
	@Test
	/*
     * Deny NotAction=CreateGroup, NotResource=group/<group>
     */
	public void test_CreateGroup_Deny_NotAction_NotResource_group1() {
	    String groupName="testGroup01";
        String groupName2="testGroup02";
        String userName="test_1";
        // 创建policy
        String policyName="DenyCreateGroupPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/"+groupName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 403);
        
        String policyName2="AllowCreateGroupPolicy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:GetGroup","iam:DeleteGroup","iam:GetAccountPasswordPolicy"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2,200);
        
        // group1的操作允许
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName, 200);
        
        // group2拒绝get 和delete
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName2, 403);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName2, 403);
        
        // 资源为*的操作拒绝
        IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
    }
	
	@Test
    /*
     * Deny NotAction=CreateGroup, NotResource=group/*
     */
    public void test_CreateGroup_Deny_NotAction_NotResource_groupAll() {
        String groupName="testGroup01";
        String groupName2="testGroup02";
        String userName="test_1";
        // 创建policy
        String policyName="DenyCreateGroupPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 403);
        
        String policyName2="AllowCreateGroupPolicy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:GetGroup","iam:DeleteGroup","iam:GetAccountPasswordPolicy"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2,200);
        
        // group1的方法允许
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName, 200);
        
        // group2的方法允许
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        
        // 资源为*的操作拒绝
        IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
    }
	
	@Test
    /*
     * Deny NotAction=CreateGroup, NotResource=*
     */
    public void test_CreateGroup_Deny_NotAction_NotResource_All() {
        String groupName="testGroup01";
        String groupName2="testGroup02";
        String userName="test_1";
        // 创建policy
        String policyName="DenyCreateGroupPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 403);
        
        String policyName2="AllowCreateGroupPolicy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:GetGroup","iam:DeleteGroup","iam:GetAccountPasswordPolicy"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2,200);
        
        // group1的方法允许
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName, 200);
        
        // group2拒绝get 和delete
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        
        // 资源为*的方法允许
        IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey1, user1secretKey1, 200);
    }
	
	@Test
    /*
     * 在IP范围的允许访问
     */
    public void test_CreateGroup_Condition_sourceIP() {
	    String groupName="testGroup01";;
	    String userName=user1Name;
	    String policyName="allowspecialIP";
	    List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("IpAddress","ctyun:SourceIp",Arrays.asList("192.168.1.1/24")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);

        // 在IP范围
        String body="Action=CreateGroup&Version=2010-05-08&GroupName="+groupName;
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
	public void test_CreateGroup_Condition_username() {
        String policyName="allowUsername";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
       // username 符合条件
        String body="Action=CreateGroup&Version=2010-05-08&GroupName=testGroup01";
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, result.first().intValue());
        
        // username 不符合条件
        body="Action=CreateGroup&Version=2010-05-08&GroupName=testGroup03";
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest(body, user3accessKey, user3secretKey);
        assertEquals(403, result3.first().intValue());
    }
	
	@Test
	/*
	 * 符合实际条件允许访问
	 */
	public void test_CreateGroup_Condition_CurrentTime() {
	    String policyName="allowDateGreate";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("DateGreaterThan","ctyun:CurrentTime",Arrays.asList("2019-01-01T00:00:00Z")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        // 时间符合条件
        String body="Action=CreateGroup&Version=2010-05-08&GroupName=testGroup01";
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, result.first().intValue());
        
        
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("DateGreaterThan","ctyun:CurrentTime",Arrays.asList("2050-01-01T00:00:00Z")));
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions2);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
   
        // 时间不符合条件
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(403, result2.first().intValue());
	}
	
	
	@Test
	/*
	 * 设置不允许ssl访问
	 */
	public void test_CreateGroup_Condition_SecureTransport() {
	    String policyName="DenySSL";
	    
	    String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
	    IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
	    
        // 允许ssl访问 
        String body="Action=CreateGroup&Version=2010-05-08&GroupName=testGroup01";
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, result.first().intValue());

        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("Bool","ctyun:SecureTransport",Arrays.asList("false")));
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 不允许ssl访问
        body="Action=CreateGroup&Version=2010-05-08&GroupName=testGroup02";
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(403, result2.first().intValue());
        
    }
	
	@Test
    /*
     * allow Action=CreateGroup,GetGroup,DeleteGroup,ListGroups, AddUserToGroup,RemoveUserFromGroup resource=group/group1
             * 只允许上述对group1操作
     */
	public void test_GroupALLMethod_Allow_Action_group1()  {
	    // 创建policy
        String policyName="test_GroupAllMethod_Allow_Action_group1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/testGroup01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 验证请求
        String groupName="testGroup01";
        String groupName2="testGroup02";
        // user1有group1权限， 但list资源不匹配
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        String listgroupString=IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(listgroupString, "ListGroups",userName, "group/*");
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user3Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user3Name,200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName,200);
        
        // user2无权限
        String user2GreateString=IAMInterfaceTestUtils.CreateGroup(user2accessKey, user2secretKey, groupName, 403);
        AssertAccessDenyString(user2GreateString, "CreateGroup",user2Name, "group/"+groupName);
        String user2getString=IAMInterfaceTestUtils.GetGroup(user2accessKey, user2secretKey, groupName, 403);
        AssertAccessDenyString(user2getString, "GetGroup",user2Name, "group/"+groupName);
        String user2listString=IAMInterfaceTestUtils.ListGroups(user2accessKey, user2secretKey, groupName, 403);
        AssertAccessDenyString(user2listString, "ListGroups",user2Name, "group/*");
        String user2AddString=IAMInterfaceTestUtils.AddUserToGroup(user2accessKey, user2secretKey, groupName, user3Name,403);
        AssertAccessDenyString(user2AddString, "AddUserToGroup",user2Name, "group/"+groupName);
        String user2RemoveString=IAMInterfaceTestUtils.RemoveUserFromGroup(user2accessKey, user2secretKey, groupName, user3Name,403);
        AssertAccessDenyString(user2RemoveString, "RemoveUserFromGroup",user2Name, "group/"+groupName);
        String user2DelString=IAMInterfaceTestUtils.DeleteGroup(user2accessKey, user2secretKey, groupName,403);
        AssertAccessDenyString(user2DelString, "DeleteGroup",user2Name, "group/"+groupName);
        
        // user1无其他group权限
        String user1GreateString=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 403);
        AssertAccessDenyString(user1GreateString, "CreateGroup",user1Name, "group/"+groupName2);
        String user1getString=IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName2, 403);
        AssertAccessDenyString(user1getString, "GetGroup",user1Name, "group/"+groupName2);
        String user1listString=IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName2, 403);
        AssertAccessDenyString(user1listString, "ListGroups",user1Name, "group/*");
        String user1AddString=IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName2, user3Name,403);
        AssertAccessDenyString(user1AddString, "AddUserToGroup",user1Name, "group/"+groupName2);
        String user1RemoveString=IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName2, user3Name,403);
        AssertAccessDenyString(user1RemoveString, "RemoveUserFromGroup",user1Name, "group/"+groupName2);
        String user1DelString=IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName2,403);
        AssertAccessDenyString(user1DelString, "DeleteGroup",user1Name, "group/"+groupName2);
        
    }
	
	@Test
    /*
     * allow allow Action=CreateGroup,GetGroup,DeleteGroup,ListGroups, AddUserToGroup,RemoveUserFromGroup, resource=group/*
             * 可以对所有group操作
     */
	public void test_GroupALLMethod_Allow_Action_groupAll() {
	    // 创建policy
        String policyName="test_GroupALLMethod_Allow_Action_groupAll";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 验证请求
        String groupName="testGroup01";
        String groupName2="testGroup02";
        // user1有group1权限
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user3Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user3Name,200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName,200);
        
        // user2无权限
        String user2GreateString=IAMInterfaceTestUtils.CreateGroup(user2accessKey, user2secretKey, groupName, 403);
        AssertAccessDenyString(user2GreateString, "CreateGroup",user2Name, "group/"+groupName);
        String user2getString=IAMInterfaceTestUtils.GetGroup(user2accessKey, user2secretKey, groupName, 403);
        AssertAccessDenyString(user2getString, "GetGroup",user2Name, "group/"+groupName);
        String user2listString=IAMInterfaceTestUtils.ListGroups(user2accessKey, user2secretKey, groupName, 403);
        AssertAccessDenyString(user2listString, "ListGroups",user2Name, "group/*");
        String user2AddString=IAMInterfaceTestUtils.AddUserToGroup(user2accessKey, user2secretKey, groupName, user3Name,403);
        AssertAccessDenyString(user2AddString, "AddUserToGroup",user2Name, "group/"+groupName);
        String user2RemoveString=IAMInterfaceTestUtils.RemoveUserFromGroup(user2accessKey, user2secretKey, groupName, user3Name,403);
        AssertAccessDenyString(user2RemoveString, "RemoveUserFromGroup",user2Name, "group/"+groupName);
        String user2DelString=IAMInterfaceTestUtils.DeleteGroup(user2accessKey, user2secretKey, groupName,403);
        AssertAccessDenyString(user2DelString, "DeleteGroup",user2Name, "group/"+groupName);
        
        // user1有其他group权限
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName2, user3Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName2, user3Name,200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName2,200);

    }
	
	@Test
	/*
     * allow Action=CreateGroup,GetGroup,DeleteGroup,ListGroups, AddUserToGroup,RemoveUserFromGroup, resource=*
             * 可以对所有group操作
     */
	public void test_GroupALLMethod_Allow_Action_ALL() {
	 // 创建policy
        String policyName="test_GroupALLMethod_Allow_Action_ALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 验证请求
        String groupName="testGroup01";
        String groupName2="testGroup02";
        // user1有group1权限
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user3Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user3Name,200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName,200);
        
        // user2无权限
        String user2GreateString=IAMInterfaceTestUtils.CreateGroup(user2accessKey, user2secretKey, groupName, 403);
        AssertAccessDenyString(user2GreateString, "CreateGroup",user2Name, "group/"+groupName);
        String user2getString=IAMInterfaceTestUtils.GetGroup(user2accessKey, user2secretKey, groupName, 403);
        AssertAccessDenyString(user2getString, "GetGroup",user2Name, "group/"+groupName);
        String user2listString=IAMInterfaceTestUtils.ListGroups(user2accessKey, user2secretKey, groupName, 403);
        AssertAccessDenyString(user2listString, "ListGroups",user2Name, "group/*");
        String user2AddString=IAMInterfaceTestUtils.AddUserToGroup(user2accessKey, user2secretKey, groupName, user3Name,403);
        AssertAccessDenyString(user2AddString, "AddUserToGroup",user2Name, "group/"+groupName);
        String user2RemoveString=IAMInterfaceTestUtils.RemoveUserFromGroup(user2accessKey, user2secretKey, groupName, user3Name,403);
        AssertAccessDenyString(user2RemoveString, "RemoveUserFromGroup",user2Name, "group/"+groupName);
        String user2DelString=IAMInterfaceTestUtils.DeleteGroup(user2accessKey, user2secretKey, groupName,403);
        AssertAccessDenyString(user2DelString, "DeleteGroup",user2Name, "group/"+groupName);
        
        // user1有其他group权限
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName2, user3Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName2, user3Name,200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName2,200);

    }
	
	@Test
    /*
     * allow Action=CreateGroup,GetGroup,DeleteGroup,ListGroups, AddUserToGroup,RemoveUserFromGroup, resource=user/*
         * 资源和请求的action不匹配，policy不生效
     */
    public void test_GroupALLMethod_Allow_Action_resourceNotMatch() {
	 // 创建policy
        String policyName="test_GroupALLMethod_Allow_Action_resourceNotMatch";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 验证请求
        String groupName="testGroup01";
        // user1因为资源不匹配，无权限
        String user1GreateString=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1GreateString, "CreateGroup",user1Name, "group/"+groupName);
        String user1getString=IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1getString, "GetGroup",user1Name, "group/"+groupName);
        String user1listString=IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1listString, "ListGroups",user1Name, "group/*");
        String user1AddString=IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user3Name,403);
        AssertAccessDenyString(user1AddString, "AddUserToGroup",user1Name, "group/"+groupName);
        String user1RemoveString=IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user3Name,403);
        AssertAccessDenyString(user1RemoveString, "RemoveUserFromGroup",user1Name, "group/"+groupName);
        String user1DelString=IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName,403);
        AssertAccessDenyString(user1DelString, "DeleteGroup",user1Name, "group/"+groupName);
	}
    
	@Test
    /*
     * allow Action=CreateGroup,GetGroup,DeleteGroup,ListGroups, AddUserToGroup,RemoveUserFromGroup, Notresource=group/group1
             * 允许操作， 但是资源是非group/group1
     */
    public void test_GroupALLMethod_Allow_Action_Notgroup1() {
	    String groupName="testGroup01";
        String groupName2="testGroup02";
	    // 创建policy
        String policyName="test_GroupALLMethod_Allow_Action_Notgroup1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/"+groupName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 验证请求
        
        // user1有group2权限
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName2, user3Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName2, user3Name,200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName2,200);
        
        // user2无权限
        String user2GreateString=IAMInterfaceTestUtils.CreateGroup(user2accessKey, user2secretKey, groupName2, 403);
        AssertAccessDenyString(user2GreateString, "CreateGroup",user2Name, "group/"+groupName2);
        String user2getString=IAMInterfaceTestUtils.GetGroup(user2accessKey, user2secretKey, groupName2, 403);
        AssertAccessDenyString(user2getString, "GetGroup",user2Name, "group/"+groupName2);
        String user2listString=IAMInterfaceTestUtils.ListGroups(user2accessKey, user2secretKey, groupName2, 403);
        AssertAccessDenyString(user2listString, "ListGroups",user2Name, "group/*");
        String user2AddString=IAMInterfaceTestUtils.AddUserToGroup(user2accessKey, user2secretKey, groupName2, user3Name,403);
        AssertAccessDenyString(user2AddString, "AddUserToGroup",user2Name, "group/"+groupName2);
        String user2RemoveString=IAMInterfaceTestUtils.RemoveUserFromGroup(user2accessKey, user2secretKey, groupName2, user3Name,403);
        AssertAccessDenyString(user2RemoveString, "RemoveUserFromGroup",user2Name, "group/"+groupName2);
        String user2DelString=IAMInterfaceTestUtils.DeleteGroup(user2accessKey, user2secretKey, groupName2,403);
        AssertAccessDenyString(user2DelString, "DeleteGroup",user2Name, "group/"+groupName2);
        
        // user1对group1无权限,可listgroup1
        String user1GreateString=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1GreateString, "CreateGroup",user1Name, "group/"+groupName);
        String user1getString=IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1getString, "GetGroup",user1Name, "group/"+groupName);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 200);
        String user1AddString=IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user3Name,403);
        AssertAccessDenyString(user1AddString, "AddUserToGroup",user1Name, "group/"+groupName);
        String user1RemoveString=IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user3Name,403);
        AssertAccessDenyString(user1RemoveString, "RemoveUserFromGroup",user1Name, "group/"+groupName);
        String user1DelString=IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName,403);
        AssertAccessDenyString(user1DelString, "DeleteGroup",user1Name, "group/"+groupName);
    }
    
	@Test
	/*
     * allow Action=CreateGroup,GetGroup,DeleteGroup,ListGroups, AddUserToGroup,RemoveUserFromGroup, Notresource=group/*
     * groupAction都无法操作
     */
    public void test_GroupALLMethod_Allow_Action_NotgroupALL() {
        String groupName="testGroup01";
        // 创建policy
        String policyName="test_GroupALLMethod_Allow_Action_NotgroupALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // user1无group所有方法的权限
        String user1GreateString=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1GreateString, "CreateGroup",user1Name, "group/"+groupName);
        String user1getString=IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1getString, "GetGroup",user1Name, "group/"+groupName);
        String user1listString=IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1listString, "ListGroups",user1Name, "group/*");
        String user1AddString=IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user3Name,403);
        AssertAccessDenyString(user1AddString, "AddUserToGroup",user1Name, "group/"+groupName);
        String user1RemoveString=IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user3Name,403);
        AssertAccessDenyString(user1RemoveString, "RemoveUserFromGroup",user1Name, "group/"+groupName);
        String user1DelString=IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName,403);
        AssertAccessDenyString(user1DelString, "DeleteGroup",user1Name, "group/"+groupName);
    }
    
	@Test
	/*
     * allow Action=CreateGroup,GetGroup,DeleteGroup,ListGroups, AddUserToGroup,RemoveUserFromGroup, Notresource=group/*
     * groupAction都无法操作
     */
    public void test_GroupALLMethod_Allow_Action_NotALL() {
	    String groupName="testGroup01";
        // 创建policy
        String policyName="test_GroupALLMethod_Allow_Action_NotALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // user1无group所有方法的权限
        String user1GreateString=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1GreateString, "CreateGroup",user1Name, "group/"+groupName);
        String user1getString=IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1getString, "GetGroup",user1Name, "group/"+groupName);
        String user1listString=IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1listString, "ListGroups",user1Name, "group/*");
        String user1AddString=IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user3Name,403);
        AssertAccessDenyString(user1AddString, "AddUserToGroup",user1Name, "group/"+groupName);
        String user1RemoveString=IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user3Name,403);
        AssertAccessDenyString(user1RemoveString, "RemoveUserFromGroup",user1Name, "group/"+groupName);
        String user1DelString=IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName,403);
        AssertAccessDenyString(user1DelString, "DeleteGroup",user1Name, "group/"+groupName);
    }
    
	@Test
    /*
     * allow NotAction=CreateGroup,GetGroup,DeleteGroup,ListGroups, AddUserToGroup,RemoveUserFromGroup,resource=group/group1
     * 资源resource只能匹配除了上述操作的其他group资源相关操作
     */
    public void test_GroupALLMethod_Allow_NotAction_group1() {
	    // 创建policy
        String policyName="test_GroupALLMethod_Allow_NotAction_group1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/testGroup01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 验证请求
        String groupName="testGroup01";
        
        // user1无上述资源是group1操作权限，但有其他接口group1的操作权限
        String user1GreateString=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1GreateString, "CreateGroup",user1Name, "group/"+groupName);
        String user1getString=IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1getString, "GetGroup",user1Name, "group/"+groupName);
        String user1listString=IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1listString, "ListGroups",user1Name, "group/*");
        String user1AddString=IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user3Name,403);
        AssertAccessDenyString(user1AddString, "AddUserToGroup",user1Name, "group/"+groupName);
        String user1RemoveString=IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user3Name,403);
        AssertAccessDenyString(user1RemoveString, "RemoveUserFromGroup",user1Name, "group/"+groupName);
        String user1DelString=IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName,403);
        AssertAccessDenyString(user1DelString, "DeleteGroup",user1Name, "group/"+groupName);
        
        // 验证 除了 上述接口，其他跟group resource相关的接口都允许
        List<String> excludes=new ArrayList<String>();
        excludes.add("CreateGroup");
        excludes.add("GetGroup");
        excludes.add("ListGroups");
        excludes.add("AddUserToGroup");
        excludes.add("RemoveUserFromGroup");
        excludes.add("DeleteGroup");
        String policyName2="test_policy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, groupName, userName, accountId, policyName2, policyString2);
        
    }
    
	@Test
	  /*
     * allow NotAction=CreateGroup,GetGroup,DeleteGroup,ListGroups, AddUserToGroup,RemoveUserFromGroup,resource=group/*
     * 资源resource只能匹配除了上述操作的其他group/*资源相关操作
     */
    public void test_GroupALLMethod_Allow_NotAction_groupAll() {
	    // 创建policy
        String policyName="test_GroupALLMethod_Allow_NotAction_groupAll";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 验证请求
        String groupName="testGroup01";
        
        // user1无上述资源是group1操作权限，但有其他接口group1的操作权限
        String user1GreateString=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1GreateString, "CreateGroup",user1Name, "group/"+groupName);
        String user1getString=IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1getString, "GetGroup",user1Name, "group/"+groupName);
        String user1listString=IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1listString, "ListGroups",user1Name, "group/*");
        String user1AddString=IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user3Name,403);
        AssertAccessDenyString(user1AddString, "AddUserToGroup",user1Name, "group/"+groupName);
        String user1RemoveString=IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user3Name,403);
        AssertAccessDenyString(user1RemoveString, "RemoveUserFromGroup",user1Name, "group/"+groupName);
        String user1DelString=IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName,403);
        AssertAccessDenyString(user1DelString, "DeleteGroup",user1Name, "group/"+groupName);
        
        // 验证 除了上述接口，其他跟group/* resource相关的接口都允许
        List<String> excludes=new ArrayList<String>();
        excludes.add("CreateGroup");
        excludes.add("GetGroup");
        excludes.add("ListGroups");
        excludes.add("AddUserToGroup");
        excludes.add("RemoveUserFromGroup");
        excludes.add("DeleteGroup");
        String policyName2="test_policy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.AllowActionResourceGroupALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, groupName, userName, accountId, policyName2, policyString2);

    }
	
	@Test
	 /*
     * allow NotAction=CreateGroup,GetGroup,DeleteGroup,ListGroups, AddUserToGroup,RemoveUserFromGroup,resource=*
     * 资源resource只能匹配除了上述操作的其他*资源相关操作
     */
    public void test_GroupALLMethod_Allow_NotAction_ALL() {
	 // 创建policy
        String policyName="test_GroupALLMethod_Allow_NotAction_groupAll";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 验证请求
        String groupName="testGroup01";
        
        // user1无上述资源是group1操作权限，但有其他接口group1的操作权限
        String user1GreateString=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1GreateString, "CreateGroup",user1Name, "group/"+groupName);
        String user1getString=IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1getString, "GetGroup",user1Name, "group/"+groupName);
        String user1listString=IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1listString, "ListGroups",user1Name, "group/*");
        String user1AddString=IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user3Name,403);
        AssertAccessDenyString(user1AddString, "AddUserToGroup",user1Name, "group/"+groupName);
        String user1RemoveString=IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user3Name,403);
        AssertAccessDenyString(user1RemoveString, "RemoveUserFromGroup",user1Name, "group/"+groupName);
        String user1DelString=IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName,403);
        AssertAccessDenyString(user1DelString, "DeleteGroup",user1Name, "group/"+groupName);
        
        // 验证 除了上述接口，其他跟group/* resource相关的接口都允许
        List<String> excludes=new ArrayList<String>();
        excludes.add("CreateGroup");
        excludes.add("GetGroup");
        excludes.add("ListGroups");
        excludes.add("AddUserToGroup");
        excludes.add("RemoveUserFromGroup");
        excludes.add("DeleteGroup");
        String policyName2="test_policy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey,excludes, user1accessKey1, user1secretKey1, "lala_1", tags, policyName2, policyString2, accountId,groupName,"mfa2");

    }
    
	@Test
	 /*
     * allow NotAction=CreateGroup,GetGroup,DeleteGroup,ListGroups, AddUserToGroup,RemoveUserFromGroup,resource=group/group1
     * 资源resource只能匹配除了上述操作的其他非group1资源相关操作
     */
    public void test_GroupALLMethod_Allow_NotAction_Notgroup1() {
	    // 创建policy
        String policyName="test_GroupALLMethod_Allow_NotAction_group1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/testGroup01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 验证请求
        String groupName="testGroup01";
        String groupName2="testGroup02";
        
        // user1无上述资源是group1操作权限，但有其他接口group1的操作权限
        String user1GreateString=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1GreateString, "CreateGroup",user1Name, "group/"+groupName);
        String user1getString=IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1getString, "GetGroup",user1Name, "group/"+groupName);
        String user1listString=IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1listString, "ListGroups",user1Name, "group/*");
        String user1AddString=IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user3Name,403);
        AssertAccessDenyString(user1AddString, "AddUserToGroup",user1Name, "group/"+groupName);
        String user1RemoveString=IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user3Name,403);
        AssertAccessDenyString(user1RemoveString, "RemoveUserFromGroup",user1Name, "group/"+groupName);
        String user1DelString=IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName,403);
        AssertAccessDenyString(user1DelString, "DeleteGroup",user1Name, "group/"+groupName);
        
        // 验证 除了 上述接口，其他非group1 resource相关的接口都允许
        List<String> excludes=new ArrayList<String>();
        excludes.add("CreateGroup");
        excludes.add("GetGroup");
        excludes.add("ListGroups");
        excludes.add("AddUserToGroup");
        excludes.add("RemoveUserFromGroup");
        excludes.add("DeleteGroup");
        String policyName2="test_policy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        
        // 资源是group1的都不允许
        IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1, groupName, userName, accountId, policyName2, policyString2);
        // 除了上述接口，group2可以访问
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, groupName2, userName, accountId, policyName2, policyString2);

        // 验证 跟MFA资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null,user1accessKey1, user1secretKey1, accountId, "mfa1");
        // 验证 跟policy资源相关接口允许
        
        String policyName3="test_policy2";
        String policyString3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null,user1accessKey1, user1secretKey1, policyName3, policyString3, accountId);
        // 验证 跟user资源相关接口都允许
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, null,user1accessKey1, user1secretKey1, "lala_2", tags, policyName2, policyString2, accountId);
    
        // 验证 *资源匹配接口都允许
        IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1,null);
    }
    
	@Test
	/*
     * allow NotAction=CreateGroup,GetGroup,DeleteGroup,ListGroups, AddUserToGroup,RemoveUserFromGroup,resource=group/*
     * 资源resource只能匹配除了上述操作的其他非group/*资源相关操作
     */
    public void test_GroupALLMethod_Allow_NotAction_NotgroupALL() {
	    // 创建policy
        String policyName="test_GroupALLMethod_Allow_NotAction_NotgroupALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 验证请求
        String groupName="testGroup01";
        String groupName2="testGroup02";
        
        // user1无上述资源是group1操作权限，但有其他接口group1的操作权限
        String user1GreateString=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1GreateString, "CreateGroup",user1Name, "group/"+groupName);
        String user1getString=IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1getString, "GetGroup",user1Name, "group/"+groupName);
        String user1listString=IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1listString, "ListGroups",user1Name, "group/*");
        String user1AddString=IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user3Name,403);
        AssertAccessDenyString(user1AddString, "AddUserToGroup",user1Name, "group/"+groupName);
        String user1RemoveString=IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user3Name,403);
        AssertAccessDenyString(user1RemoveString, "RemoveUserFromGroup",user1Name, "group/"+groupName);
        String user1DelString=IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName,403);
        AssertAccessDenyString(user1DelString, "DeleteGroup",user1Name, "group/"+groupName);
        
        String policyName2="test_policy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        
        // 资源是group1的都不允许
        IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1, groupName, userName, accountId, policyName2, policyString2);
        // 资源是group*都不允许
        IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1, groupName2, userName, accountId, policyName2, policyString2);

        // 验证 跟MFA资源相关接口都允许
        IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null,user1accessKey1, user1secretKey1, accountId, "mfa1");
        // 验证 跟policy资源相关接口允许
        
        String policyName3="test_policy2";
        String policyString3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null,user1accessKey1, user1secretKey1, policyName3, policyString3, accountId);
        // 验证 跟user资源相关接口都允许
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, null,user1accessKey1, user1secretKey1, "lala_3", tags, policyName2, policyString2, accountId);
    
        // 验证 *资源匹配接口都允许
        IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1,null);
    }
    
	@Test
	/*
     * allow NotAction=CreateGroup,GetGroup,DeleteGroup,ListGroups, AddUserToGroup,RemoveUserFromGroup,resource=*
     */
    public void test_GroupALLMethod_Allow_NotAction_NotALL() {
	    // 创建policy
        String policyName="test_GroupALLMethod_Allow_NotAction_NotALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        // 验证请求
        String groupName="testGroup01";
        
        // user1无上述资源是group1操作权限，但有其他接口group1的操作权限
        String user1GreateString=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1GreateString, "CreateGroup",user1Name, "group/"+groupName);
        String user1getString=IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1getString, "GetGroup",user1Name, "group/"+groupName);
        String user1listString=IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1listString, "ListGroups",user1Name, "group/*");
        String user1AddString=IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user3Name,403);
        AssertAccessDenyString(user1AddString, "AddUserToGroup",user1Name, "group/"+groupName);
        String user1RemoveString=IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user3Name,403);
        AssertAccessDenyString(user1RemoveString, "RemoveUserFromGroup",user1Name, "group/"+groupName);
        String user1DelString=IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName,403);
        AssertAccessDenyString(user1DelString, "DeleteGroup",user1Name, "group/"+groupName);
        
        String policyName2="test_policy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        IAMInterfaceTestUtils.DenyActionResourceALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "lala_3", tags, policyName2, policyString2, accountId, groupName, "mfa3");
    }
    
	@Test
	/*
     * Deny Action=CreateGroup,GetGroup,DeleteGroup,ListGroups, AddUserToGroup,RemoveUserFromGroup, resource=group/group1
     * 拒绝操作group1
     */
    public void test_GroupALLMethod_Deny_Action_group1() {
	    String groupName="testGroup01";
	    String groupName2="testGroup02";
	    // 创建policy
        String policyName="Allow_group";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*Group*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
	    
	    // 创建policy
        String policyName1="test_GroupALLMethod_Deny_Action_group1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/"+groupName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName1,200);
        
        // user1对group1资源无操作权限
        String user1GreateString=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1GreateString, "CreateGroup",user1Name, "group/"+groupName);
        String user1getString=IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1getString, "GetGroup",user1Name, "group/"+groupName);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 200);
        String user1AddString=IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user3Name,403);
        AssertAccessDenyString(user1AddString, "AddUserToGroup",user1Name, "group/"+groupName);
        String user1RemoveString=IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user3Name,403);
        AssertAccessDenyString(user1RemoveString, "RemoveUserFromGroup",user1Name, "group/"+groupName);
        String user1DelString=IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName,403);
        AssertAccessDenyString(user1DelString, "DeleteGroup",user1Name, "group/"+groupName);
        
        // group资源其他未列出的操作允许
        // 验证 除了 上述接口，其他跟group resource相关的接口都允许
        List<String> excludes=new ArrayList<String>();
        excludes.add("CreateGroup");
        excludes.add("GetGroup");
        excludes.add("ListGroups");
        excludes.add("AddUserToGroup");
        excludes.add("RemoveUserFromGroup");
        excludes.add("DeleteGroup");
        String policyName2="test_policy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, groupName, userName, accountId, policyName2, policyString2);
        
        // user1对group2资源所有操作权限
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user1accessKey1, user1secretKey1, groupName2, userName, accountId, policyName2, policyString2);
    }
    
	@Test
	/*
     * Deny Action=CreateGroup,GetGroup,DeleteGroup,ListGroups, AddUserToGroup,RemoveUserFromGroup, resource=group/group1
     * 拒绝操作group/*资源的所有操作
     */
    public void test_GroupALLMethod_Deny_Action_groupAll() {
	    String groupName="testGroup01";
        String groupName2="testGroup02";
        // 创建policy
        String policyName="Allow_group";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*Group*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 创建policy
        String policyName1="test_GroupALLMethod_Deny_Action_group1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName1,200);
        
        // user1对group1资源无操作权限
        String user1GreateString=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1GreateString, "CreateGroup",user1Name, "group/"+groupName);
        String user1getString=IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1getString, "GetGroup",user1Name, "group/"+groupName);
        String user1listString=IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1listString, "ListGroups",user1Name, "group/*");
        String user1AddString=IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user3Name,403);
        AssertAccessDenyString(user1AddString, "AddUserToGroup",user1Name, "group/"+groupName);
        String user1RemoveString=IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user3Name,403);
        AssertAccessDenyString(user1RemoveString, "RemoveUserFromGroup",user1Name, "group/"+groupName);
        String user1DelString=IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName,403);
        AssertAccessDenyString(user1DelString, "DeleteGroup",user1Name, "group/"+groupName);
        
        // 验证 除了 上述接口，其他跟group resource相关的接口都允许
        List<String> excludes=new ArrayList<String>();
        excludes.add("CreateGroup");
        excludes.add("GetGroup");
        excludes.add("ListGroups");
        excludes.add("AddUserToGroup");
        excludes.add("RemoveUserFromGroup");
        excludes.add("DeleteGroup");
        String policyName2="test_policy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        
        // 除了以上接口都可以操作资源group1
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, groupName, userName, accountId, policyName2, policyString2);
        
        // 除了以上接口都可以操作资源group2
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, groupName2, userName, accountId, policyName2, policyString2);
    }
    
	@Test
    /*
     * Deny Action=CreateGroup,GetGroup,DeleteGroup,ListGroups, AddUserToGroup,RemoveUserFromGroup, resource=*
     * 拒绝操作*资源的所有操作
     */
    public void test_GroupALLMethod_Deny_Action_ALL() {
	    String groupName="testGroup01";
        String groupName2="testGroup02";
        // 创建policy
        String policyName="Allow_group";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*Group*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 创建policy
        String policyName1="test_GroupALLMethod_Deny_Action_group1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName1,200);
        
        // user1对group1资源无操作权限
        String user1GreateString=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1GreateString, "CreateGroup",user1Name, "group/"+groupName);
        String user1getString=IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1getString, "GetGroup",user1Name, "group/"+groupName);
        String user1listString=IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 403);
        AssertAccessDenyString(user1listString, "ListGroups",user1Name, "group/*");
        String user1AddString=IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user3Name,403);
        AssertAccessDenyString(user1AddString, "AddUserToGroup",user1Name, "group/"+groupName);
        String user1RemoveString=IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user3Name,403);
        AssertAccessDenyString(user1RemoveString, "RemoveUserFromGroup",user1Name, "group/"+groupName);
        String user1DelString=IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName,403);
        AssertAccessDenyString(user1DelString, "DeleteGroup",user1Name, "group/"+groupName);
        
        // 验证 除了 上述接口，其他跟group resource相关的接口都允许
        List<String> excludes=new ArrayList<String>();
        excludes.add("CreateGroup");
        excludes.add("GetGroup");
        excludes.add("ListGroups");
        excludes.add("AddUserToGroup");
        excludes.add("RemoveUserFromGroup");
        excludes.add("DeleteGroup");
        String policyName2="test_policy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        
        // 除了以上接口都可以操作资源group1
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, groupName, userName, accountId, policyName2, policyString2);
        
        // 除了以上接口都可以操作资源group2
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, groupName2, userName, accountId, policyName2, policyString2);

    }
    
    @Test
    /*
     * Deny Action=CreateGroup,GetGroup,DeleteGroup,ListGroups, AddUserToGroup,RemoveUserFromGroup, resource=user/*
     * 资源不匹配，deny失败
     */
    public void test_GroupALLMethod_Deny_Action_ReourceNotMatch() {
        String groupName="testGroup01";
        // 创建policy
        String policyName="Allow_group";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*Group*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 创建policy
        String policyName1="test_GroupALLMethod_Deny_Action_group1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName1,200);
        
        // 资源不匹配失效
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user3Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user3Name,200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName,200);

    }
    
    @Test
    /*
     * Deny Action=CreateGroup,GetGroup,DeleteGroup,ListGroups, AddUserToGroup,RemoveUserFromGroup, NotResource=group/<group1>
     * 
     */
    public void test_GroupALLMethod_Deny_Action_Notgroup1() {
        String groupName="testGroup01";
        String groupName2="testGroup02";
        // 创建policy
        String policyName="Allow_group";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*Group*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 创建policy
        String policyName1="test_GroupALLMethod_Deny_Action_Notgroup1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/"+groupName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName1,200);
        
        // user1有group1权限
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 403);
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user3Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user3Name,200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName,200);
        
        // user1无其他group权限
        String user1GreateString=IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 403);
        AssertAccessDenyString(user1GreateString, "CreateGroup",user1Name, "group/"+groupName2);
        String user1getString=IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName2, 403);
        AssertAccessDenyString(user1getString, "GetGroup",user1Name, "group/"+groupName2);
        String user1listString=IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName2, 403);
        AssertAccessDenyString(user1listString, "ListGroups",user1Name, "group/*");
        String user1AddString=IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName2, user3Name,403);
        AssertAccessDenyString(user1AddString, "AddUserToGroup",user1Name, "group/"+groupName2);
        String user1RemoveString=IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName2, user3Name,403);
        AssertAccessDenyString(user1RemoveString, "RemoveUserFromGroup",user1Name, "group/"+groupName2);
        String user1DelString=IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName2,403);
        AssertAccessDenyString(user1DelString, "DeleteGroup",user1Name, "group/"+groupName2);

    }
    
    @Test
    /*
     * Deny Action=CreateGroup,GetGroup,DeleteGroup,ListGroups, AddUserToGroup,RemoveUserFromGroup, NotResource=group/*
     * 
     */
    public void test_GroupALLMethod_Deny_Action_NotgroupALL() {
        String groupName="testGroup01";
        String groupName2="testGroup02";
        // 创建policy
        String policyName="Allow_group";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*Group*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 创建policy
        String policyName1="test_GroupALLMethod_Deny_Action_Notgroup1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName1,200);
        
        // user1有group1权限
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user3Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user3Name,200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName,200);
        
        // user1其他group权限
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName2, user3Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName2, user3Name,200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName2,200);
    }
    
    @Test
    /*
     * Deny Action=CreateGroup,GetGroup,DeleteGroup,ListGroups, AddUserToGroup,RemoveUserFromGroup, NotResource=*
     * 
     */
    public void test_GroupALLMethod_Deny_Action_NotALL() {
        String groupName="testGroup01";
        String groupName2="testGroup02";
        // 创建policy
        String policyName="Allow_group";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*Group*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 创建policy
        String policyName1="test_GroupALLMethod_Deny_Action_NotALL";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName1,200);
        
        // user1有group1权限
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user3Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user3Name,200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName,200);
        
        // user1其他group权限
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName2, user3Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName2, user3Name,200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName2,200);
    }
    
    @Test
    /*
     * Deny NotAction=CreateGroup,GetGroup,DeleteGroup,ListGroups, AddUserToGroup,RemoveUserFromGroup, Resource=group/group1
     * 
     */
    public void test_GroupALLMethod_Deny_NotAction_group1() {
        String groupName="testGroup01";
        String groupName2="testGroup02";
        
        // 创建policy
        String policyName="Allow_group";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*Group*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 创建policy
        String policyName1="test_GroupALLMethod_Allow_NotAction_group1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/testGroup01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName1,200);
        
        // 验证 除了 上述接口，其他跟group resource相关的接口都允许
        List<String> excludes=new ArrayList<String>();
        excludes.add("AttachGroupPolicy");
        excludes.add("ListAttachedGroupPolicies");
        excludes.add("DetachGroupPolicy");
        
        String policyName2="test_policy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, groupName, userName, accountId, policyName2, policyString2);
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user1accessKey1, user1secretKey1, groupName2, userName, accountId, policyName2, policyString2);

    }
    
    @Test
    /*
     * Deny NotAction=CreateGroup,GetGroup,DeleteGroup,ListGroups, AddUserToGroup,RemoveUserFromGroup, Resource=group/*
     * 
     */
    public void test_GroupALLMethod_Deny_NotAction_groupAll() {
        String groupName="testGroup01";
        String groupName2="testGroup02";
        
        // 创建policy
        String policyName="Allow_group";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*Group*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 创建policy
        String policyName1="test_GroupALLMethod_Allow_NotAction_group1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName1,200);
        
        // 验证 除了 上述接口，其他跟group resource相关的接口都允许
        List<String> excludes=new ArrayList<String>();
        excludes.add("AttachGroupPolicy");
        excludes.add("ListAttachedGroupPolicies");
        excludes.add("DetachGroupPolicy");
        
        String policyName2="test_policy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, groupName, userName, accountId, policyName2, policyString2);
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, groupName2, userName, accountId, policyName2, policyString2);

    }
    
    @Test
    /*
     * Deny NotAction=CreateGroup,GetGroup,DeleteGroup,ListGroups, AddUserToGroup,RemoveUserFromGroup, Resource=*
     * 
     */
    public void test_GroupALLMethod_Deny_NotAction_ALL() {
        String groupName="testGroup01";
        String groupName2="testGroup02";
        
        // 创建policy
        String policyName="Allow_group";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*Group*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 创建policy
        String policyName1="test_GroupALLMethod_Allow_NotAction_group1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName1,200);
        
        // 验证 除了 上述接口，其他跟group resource相关的接口都允许
        List<String> excludes=new ArrayList<String>();
        excludes.add("AttachGroupPolicy");
        excludes.add("ListAttachedGroupPolicies");
        excludes.add("DetachGroupPolicy");
        
        String policyName2="test_policy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, groupName, userName, accountId, policyName2, policyString2);
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, groupName2, userName, accountId, policyName2, policyString2);

    }
    
    @Test
    /*
     * Deny NotAction=CreateGroup,GetGroup,DeleteGroup,ListGroups, AddUserToGroup,RemoveUserFromGroup, NotResource=group/group1
     * 
     */
    public void test_GroupALLMethod_Deny_NotAction_Notgroup1() {
        String groupName="testGroup01";
        String groupName2="testGroup02";
        
        // 创建policy
        String policyName="Allow_group";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*Group*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 创建policy
        String policyName1="test_GroupALLMethod_Allow_NotAction_group1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/testGroup01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName1,200);
        
        // 验证 除了 上述接口，其他跟group resource相关的接口都允许
        List<String> excludes=new ArrayList<String>();
        excludes.add("AttachGroupPolicy");
        excludes.add("ListAttachedGroupPolicies");
        excludes.add("DetachGroupPolicy");
        
        String policyName2="test_policy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user1accessKey1, user1secretKey1, groupName, userName, accountId, policyName2, policyString2);
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1, groupName2, userName, accountId, policyName2, policyString2);

    }
    
    @Test
    /*
     * Deny NotAction=CreateGroup,GetGroup,DeleteGroup,ListGroups, AddUserToGroup,RemoveUserFromGroup, NotResource=group/*
     */
    public void test_GroupALLMethod_Deny_NotAction_NotgroupALL() {
        String groupName="testGroup01";
        String groupName2="testGroup02";
        
        // 创建policy
        String policyName="Allow_group";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*Group*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 创建policy
        String policyName1="test_GroupALLMethod_Allow_NotAction_group1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName1,200);
        
        String policyName2="test_policy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user1accessKey1, user1secretKey1, groupName, userName, accountId, policyName2, policyString2);
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user1accessKey1, user1secretKey1, groupName2, userName, accountId, policyName2, policyString2);

    }
    
    @Test
    /*
     * Deny NotAction=CreateGroup,GetGroup,DeleteGroup,ListGroups, AddUserToGroup,RemoveUserFromGroup, NotResource=*
     * 
     */
    public void test_GroupALLMethod_Deny_NotAction_NotALL() {
        String groupName="testGroup01";
        String groupName2="testGroup02";
        
        // 创建policy
        String policyName="Allow_group";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*Group*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 创建policy
        String policyName1="test_GroupALLMethod_Allow_NotAction_group1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        
        // 给用户添加policy
        String userName="test_1";
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName1,200);
        
        String policyName2="test_policy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
        
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user1accessKey1, user1secretKey1, groupName, userName, accountId, policyName2, policyString2);
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user1accessKey1, user1secretKey1, groupName2, userName, accountId, policyName2, policyString2);

    }
    
    @Test
    /*
     * 在IP范围的允许访问
     */
    public void test_GroupALLMethod_Condition_sourceIP() {
        String groupName="testGroup01";;
        String userName=user1Name;
        String policyName="allowspecialIP";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("IpAddress","ctyun:SourceIp",Arrays.asList("192.168.1.1/24")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);

        // 在IP范围
        String body1="Action=CreateGroup&Version=2010-05-08&GroupName="+groupName;
        String body2="Action=GetGroup&Version=2010-05-08&GroupName="+groupName;
        String body3="Action=ListGroups&Version=2010-05-08&GroupName="+groupName;
        String body4="Action=AddUserToGroup&Version=2010-05-08&GroupName="+groupName+"&UserName="+user2Name;
        String body5="Action=RemoveUserFromGroup&Version=2010-05-08&GroupName="+groupName+"&UserName="+user2Name;
        String body6="Action=DeleteGroup&Version=2010-05-08&GroupName="+groupName;
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("X-Forwarded-For");
        param1.second("192.168.1.101");
        params.add(param1);
        
        
        Pair<Integer,String> createresult=IAMTestUtils.invokeHttpsRequest2(body1, user1accessKey1, user1secretKey1,params);
        assertEquals(200, createresult.first().intValue());
        
        Pair<Integer,String> getresult=IAMTestUtils.invokeHttpsRequest2(body2, user1accessKey1, user1secretKey1,params);
        assertEquals(200, getresult.first().intValue());
        
        Pair<Integer,String> listresult=IAMTestUtils.invokeHttpsRequest2(body3, user1accessKey1, user1secretKey1,params);
        assertEquals(200, listresult.first().intValue());
        
        Pair<Integer,String> adduser=IAMTestUtils.invokeHttpsRequest2(body4, user1accessKey1, user1secretKey1,params);
        assertEquals(200, adduser.first().intValue());
        
        Pair<Integer,String> removeuser=IAMTestUtils.invokeHttpsRequest2(body5, user1accessKey1, user1secretKey1,params);
        assertEquals(200, removeuser.first().intValue());
        
        Pair<Integer,String> deleteuser=IAMTestUtils.invokeHttpsRequest2(body6, user1accessKey1, user1secretKey1,params);
        assertEquals(200, deleteuser.first().intValue());
        
        // 不在IP范围
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("X-Forwarded-For");
        param2.second("192.168.2.101");
        params2.add(param2);
        
        Pair<Integer,String> createresult2=IAMTestUtils.invokeHttpsRequest2(body1, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, createresult2.first().intValue());
        
        Pair<Integer,String> getresult2=IAMTestUtils.invokeHttpsRequest2(body2, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, getresult2.first().intValue());
        
        Pair<Integer,String> listresult2=IAMTestUtils.invokeHttpsRequest2(body3, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, listresult2.first().intValue());
        
        Pair<Integer,String> adduser2=IAMTestUtils.invokeHttpsRequest2(body4, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, adduser2.first().intValue());
        
        Pair<Integer,String> removeuser2=IAMTestUtils.invokeHttpsRequest2(body5, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, removeuser2.first().intValue());
        
        Pair<Integer,String> deleteuser2=IAMTestUtils.invokeHttpsRequest2(body6, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, deleteuser2.first().intValue());
    }
    
    @Test
    /*
     * username允许访问
     */
    public void test_GroupALLMethod_Condition_username() {
        String groupName="testGroup01";;
        String policyName="allowsuser";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName,200);

        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user2Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user2Name,200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName, 200);
        
        IAMInterfaceTestUtils.CreateGroup(user3accessKey, user3secretKey, groupName, 403);
        IAMInterfaceTestUtils.GetGroup(user3accessKey, user3secretKey, groupName, 403);
        IAMInterfaceTestUtils.ListGroups(user3accessKey, user3secretKey, groupName, 403);
        IAMInterfaceTestUtils.AddUserToGroup(user3accessKey, user3secretKey, groupName, user2Name,403);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user3accessKey, user3secretKey, groupName, user2Name,403);
        IAMInterfaceTestUtils.DeleteGroup(user3accessKey, user3secretKey, groupName, 403);
    }
    
    @Test
    /*
     * 符合时间条件允许访问
     */
    public void test_GroupALLMethod_Condition_CurrentTime() {
        String groupName="testGroup01";
        String policyName="allowDateGreate";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("DateGreaterThan","ctyun:CurrentTime",Arrays.asList("2019-01-01T00:00:00Z")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        // 时间符合条件
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user2Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user2Name,200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName, 200);
        
        
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("DateGreaterThan","ctyun:CurrentTime",Arrays.asList("2050-01-01T00:00:00Z")));
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions2);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
   
        // 时间不符合条件
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 403);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 403);
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user2Name,403);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user2Name,403);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName, 403);
    }
    
    @Test
    /*
     * 允许或者拒绝SSL
     */
    public void test_GroupALLMethod_Condition_SecureTransport() {
        String groupName="testGroup01";
        String policyName="DenySSL";
        
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:DeleteGroup","iam:GetGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        // 允许ssl访问 
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user2Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user2Name,200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName, 200);
        
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("Bool","ctyun:SecureTransport",Arrays.asList("false")));
        policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 不允许ssl访问
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 403);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 403);
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user2Name,403);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user2Name,403);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName, 403);
    }
	
	@Test
    /*
     *一个policy 两个statement
     *allow Action 所有group action方法
     *deny group1 DeleteGroup RemoveUserFromGroup
     */
    public void test_OnePolicyTwoStatement_AllowAndDeny1() {
        String groupName="testGroup01";
        String groupName2="testGroup02";
        // 创建policy
        String policyName="TwoState";
        List<Statement> statements= new ArrayList<Statement>();
        Statement s1=IAMTestUtils.CreateStatement(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:GetGroup","iam:DeleteGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        statements.add(s1);
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test*")));
        Statement s2=IAMTestUtils.CreateStatement(Effect.Deny,null,null,"Action",Arrays.asList("iam:DeleteGroup","iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/"+groupName),conditions);
        statements.add(s2);
        String policyString=IAMTestUtils.CreateMoreStatement(statements);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户组添加policy
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        // user1拒绝删除
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user2Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user2Name,403);
        IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, user2Name,200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName, 403);
        IAMInterfaceTestUtils.DeleteGroup(accessKey, secretKey, groupName, 200);
        
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName2, user2Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName2, user2Name,200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        
        // user3不符合test*,拒绝失效
        IAMInterfaceTestUtils.CreateGroup(user3accessKey, user3secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user3accessKey, user3secretKey, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user3accessKey, user3secretKey, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(user3accessKey, user3secretKey, groupName, user2Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user3accessKey, user3secretKey, groupName, user2Name,200);
        IAMInterfaceTestUtils.DeleteGroup(user3accessKey, user3secretKey, groupName, 200);
    
    }

	@Test
	/*
	 *一个policy 两个statement
	 *allow Action 所有group action方法
	 *deny DeleteGroup RemoveUserFromGroup
	 */
	public void test_OnePolicyTwoStatement_AllowAndDeny2() {
	    String groupName="testGroup01";
	    String groupName2="testGroup02";
	    // 创建policy
        String policyName="TwoState";
        List<Statement> statements= new ArrayList<Statement>();
        Statement s1=IAMTestUtils.CreateStatement(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup","iam:GetGroup","iam:DeleteGroup","iam:ListGroups","iam:AddUserToGroup","iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        statements.add(s1);
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test*")));
        Statement s2=IAMTestUtils.CreateStatement(Effect.Deny,null,null,"Action",Arrays.asList("iam:DeleteGroup","iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        statements.add(s2);
        String policyString=IAMTestUtils.CreateMoreStatement(statements);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户组添加policy
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        // user1拒绝删除
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user2Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user2Name,403);
        IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, user2Name,200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName, 403);
        
        // user3不符合test*,拒绝失效
        IAMInterfaceTestUtils.CreateGroup(user3accessKey, user3secretKey, groupName2, 200);
        IAMInterfaceTestUtils.GetGroup(user3accessKey, user3secretKey, groupName2, 200);
        IAMInterfaceTestUtils.ListGroups(user3accessKey, user3secretKey, groupName2, 200);
        IAMInterfaceTestUtils.AddUserToGroup(user3accessKey, user3secretKey, groupName2, user2Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user3accessKey, user3secretKey, groupName2, user2Name,200);
        IAMInterfaceTestUtils.DeleteGroup(user3accessKey, user3secretKey, groupName2, 200);
	
	}
	
	@Test
	 /*
	 *一个policy 两个statement
    *allow NotAction CreateGroup
    *allow Action CreateGroup group1 匹配test*
    */
	public void test_OnePolicyTwoStatement_AllowAllow1() {
	    String groupName="testGroup01";
        String groupName2="testGroup02";
        // 创建policy
        String policyName="test_AllowAllow1";
        List<Statement> statements= new ArrayList<Statement>();
        Statement s1=IAMTestUtils.CreateStatement(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        statements.add(s1);
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test*")));
        Statement s2=IAMTestUtils.CreateStatement(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/"+groupName),conditions);
        statements.add(s2);
        String policyString=IAMTestUtils.CreateMoreStatement(statements);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        // user1 允许group1
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user2Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user2Name,200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName, 200);
        
        // user1 不允许group2
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 403);
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName2, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName2, user2Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName2, user2Name,200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        
        // user3 不允许group1
        IAMInterfaceTestUtils.CreateGroup(user3accessKey, user3secretKey, groupName, 403);
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user3accessKey, user3secretKey, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user3accessKey, user3secretKey, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(user3accessKey, user3secretKey, groupName, user2Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user3accessKey, user3secretKey, groupName, user2Name,200);
        IAMInterfaceTestUtils.DeleteGroup(user3accessKey, user3secretKey, groupName, 200);
    }
	
	@Test
	 /*
	  *一个policy 两个statement
     *allow NotAction CreateGroup
     *allow Action CreateGroup 匹配test*
     */
    public void test_OnePolicyTwoStatement_AllowAllow2() {
        String groupName="testGroup01";
        String groupName2="testGroup02";
        // 创建policy
        String policyName="test_AllowAllow2";
        List<Statement> statements= new ArrayList<Statement>();
        Statement s1=IAMTestUtils.CreateStatement(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        statements.add(s1);
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test*")));
        Statement s2=IAMTestUtils.CreateStatement(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        statements.add(s2);
        String policyString=IAMTestUtils.CreateMoreStatement(statements);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        // user1 允许group1
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user2Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user2Name,200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName, 200);
        
        // user1 允许group2
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName2, user2Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName2, user2Name,200);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        
        // user3 不允许group1
        IAMInterfaceTestUtils.CreateGroup(user3accessKey, user3secretKey, groupName, 403);
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user3accessKey, user3secretKey, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user3accessKey, user3secretKey, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(user3accessKey, user3secretKey, groupName, user2Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user3accessKey, user3secretKey, groupName, user2Name,200);
        IAMInterfaceTestUtils.DeleteGroup(user3accessKey, user3secretKey, groupName, 200);
    }
	
	@Test
	/*
	 * 两个允许policy
	 */
	public void test_TwoPolicy_AllowAllow1() {
	    String groupName="testGroup01";
        String groupName2="testGroup02";
	    
	    String policyName="test_TwoPolicy_AllowAllow1-1";
	    String policyName2="test_TwoPolicy_AllowAllow1-2";
	    List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/"+groupName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/"+groupName2),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        
        // user1可创建group1 group2
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.DeleteGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.DeleteGroup(accessKey, secretKey, groupName2, 200);
        
        // user3可创建group2 不可创建group1
        IAMInterfaceTestUtils.CreateGroup(user3accessKey, user3secretKey, groupName, 403);
        IAMInterfaceTestUtils.CreateGroup(user3accessKey, user3secretKey, groupName2, 200);
	}
	
	@Test
    /*
             * 两个允许policy
     */
    public void test_TwoPolicy_AllowAllow2() {
	    String groupName="testGroup01";
        String groupName2="testGroup02";
        
        String policyName="test_TwoPolicy_AllowAllow2-1";
        String policyName2="test_TwoPolicy_AllowAllow2-2";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/"+groupName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        
        // user1可创建group1 group2
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200);
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName2, 200);
        IAMInterfaceTestUtils.DeleteGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.DeleteGroup(accessKey, secretKey, groupName2, 200);
        
        // user3可创建group1 group2
        IAMInterfaceTestUtils.CreateGroup(user3accessKey, user3secretKey, groupName, 200);
        IAMInterfaceTestUtils.CreateGroup(user3accessKey, user3secretKey, groupName2, 200);
    }
	
	@Test
    /*
             * 两个允许policy
     */
    public void test_TwoPolicy_AllowAllow3() {
        String groupName="testGroup01";
        String groupName2="testGroup02";
        
        String policyName1="test_TwoPolicy_AllowAllow2-1";
        String policyName2="test_TwoPolicy_AllowAllow2-2";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test*")));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName1, 200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        
        // user1可用所有方法
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag= new Pair<String, String>();
        tag.first("key1");
        tag.second("value1");
        String policyName="test_TwoPolicy_AllowAllow2";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey, null,user1accessKey1, user1secretKey1, "haha-1", tags, policyName, policyString, accountId,groupName,"mfa4");
        
        
        // user3仅创建group
        IAMInterfaceTestUtils.CreateGroup(user3accessKey, user3secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetAccountSummary(user3accessKey, user3secretKey, 403);
    }
	
	@Test
	public void test_Condition_UserAgent_StringEquals_Allow() {
	    String policyName="UserAgent_StringEquals_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:UserAgent",Arrays.asList("Java/1.8.0")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        // 携带参数不匹配
        String groupName="testGroup01";
        String body="Action=CreateGroup&Version=2010-05-08&GroupName="+groupName;
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("User-Agent");
        param1.second("Java/1.8.0_91");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(403, result.first().intValue());
        
        // 不携带该参数
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(403, result2.first().intValue());
        
        // 大小写不匹配
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("User-Agent");
        param2.second("java/1.8.0");
        params2.add(param2);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result3.first().intValue());
        
        // 携带参数匹配
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("User-Agent");
        param3.second("Java/1.8.0");
        params3.add(param3);
        Pair<Integer,String> result4=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(200, result4.first().intValue());
        
    }
	
	@Test
	public void test_Condition_UserAgent_StringEquals_Deny() {
	    
	    String policyName="UserAgent_StringEquals_Deny_1";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:UserAgent",Arrays.asList("Java/1.8.0_92")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String policyName2="UserAgent_StringEquals_Deny_2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        
        
        // 携带参数匹配
        String groupName="testGroup01";
        
        String body="Action=CreateGroup&Version=2010-05-08&GroupName="+groupName;
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("User-Agent");
        param1.second("Java/1.8.0_92");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(403, result.first().intValue());
        
        // 不携带该参数,但java版本和拒绝的一致
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(403, result2.first().intValue());
        
        // 携带参数匹配
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("User-Agent");
        param2.second("Java/1.8.0_91");
        params2.add(param2);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(200, result3.first().intValue());
    }
	
	@Test
	public void test_Condition_UserAgent_StringNotEquals_Allow() {
	    String policyName="UserAgent_StringNotEquals_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","ctyun:UserAgent",Arrays.asList("Java/1.8.0")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName;
        
        // 不携带该参数本地为Java/1.8.0_92
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, result2.first().intValue());
        
        // 携带参数不匹配
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("User-Agent");
        param2.second("Java/1.8.0_91");
        params2.add(param2);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(200, result3.first().intValue());
        
        // 携带参数匹配
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("User-Agent");
        param1.second("Java/1.8.0");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(403, result.first().intValue());
    }
	
	@Test
	public void test_Condition_UserAgent_StringNotEquals_Deny() {
	    String policyName="UserAgent_StringNotEquals_Deny_1";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","ctyun:UserAgent",Arrays.asList("Java/1.8.0")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String policyName2="UserAgent_StringEquals_Deny_2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName;
        
        // 不携带该参数本地为Java/1.8.0_92
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(403, result2.first().intValue());
        
        // 携带参数不匹配
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("User-Agent");
        param2.second("Java/1.8.0_91");
        params2.add(param2);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result3.first().intValue());
        
        // 携带参数匹配
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("User-Agent");
        param1.second("Java/1.8.0");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(200, result.first().intValue());
    }
	
	@Test
	public void test_Condition_UserAgent_StringEqualsIgnoreCase_Allow() {
	    String policyName="UserAgent_StringEqualsIgnoreCase_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","ctyun:UserAgent",Arrays.asList("Java/1.8.0")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        
        // 携带参数不匹配
        String body="Action=ListGroups&Version=2010-05-08";
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("User-Agent");
        param1.second("Java/1.8.0_91");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(403, result.first().intValue());
        
        // 不携带该参数 本地版本 Java/1.8.0_92
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(403, result2.first().intValue());
        
        // 大小写不匹配
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("User-Agent");
        param2.second("java/1.8.0");
        params2.add(param2);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(200, result3.first().intValue());
        
        // 携带参数匹配
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("User-Agent");
        param3.second("Java/1.8.0");
        params3.add(param3);
        Pair<Integer,String> result4=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(200, result4.first().intValue());
    }
	
	@Test
	public void test_Condition_UserAgent_StringEqualsIgnoreCase_Deny() {
	    
        String policyName="UserAgent_StringEqualsIgnoreCase_Deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","ctyun:UserAgent",Arrays.asList("Java/1.8.0")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String policyName2="UserAgent_StringEqualsIgnoreCase_Deny_2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        
        // 携带参数不匹配
        String body="Action=ListGroups&Version=2010-05-08";
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("User-Agent");
        param1.second("Java/1.8.0_91");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(200, result.first().intValue());
        
        // 不携带该参数 本地版本 Java/1.8.0_92
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, result2.first().intValue());
        
        // 大小写不匹配
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("User-Agent");
        param2.second("java/1.8.0");
        params2.add(param2);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result3.first().intValue());
        
        // 携带参数匹配
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("User-Agent");
        param3.second("Java/1.8.0");
        params3.add(param3);
        Pair<Integer,String> result4=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(403, result4.first().intValue());
        
    }
	
	@Test
	public void test_Condition_UserAgent_StringNotEqualsIgnoreCase_Allow() {
	    String policyName="UserAgent_StringEqualsNotIgnoreCase_Allow";
	    List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","ctyun:UserAgent",Arrays.asList("Java/1.8.0")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        
        String body="Action=DeleteGroup&Version=2010-05-08&GroupName="+groupName;
        
        // 携带参数不匹配
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("User-Agent");
        param1.second("java/1.8.0_91");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(200, result.first().intValue());
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        
        // 不携带该参数 本地版本 Java/1.8.0_92
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, result2.first().intValue());
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        
        // 大小写不匹配
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("User-Agent");
        param2.second("java/1.8.0");
        params2.add(param2);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result3.first().intValue());
        
        // 携带参数匹配
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("User-Agent");
        param3.second("Java/1.8.0");
        params3.add(param3);
        Pair<Integer,String> result4=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(403, result4.first().intValue());
        
       
    }
	
	@Test
	public void test_Condition_UserAgent_StringNotEqualsIgnoreCase_Deny() {
	    String policyName="UserAgent_StringNotEqualsIgnoreCase_Deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","ctyun:UserAgent",Arrays.asList("Java/1.8.0")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:DeleteGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String policyName2="UserAgent_StringNotEqualsIgnoreCase_Deny_2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        
        // 携带参数不匹配
        String body="Action=DeleteGroup&Version=2010-05-08&GroupName="+groupName;
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("User-Agent");
        param1.second("Java/1.8.0_91");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(403, result.first().intValue());
        
        // 不携带该参数 本地版本 Java/1.8.0_92
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(403, result2.first().intValue());
        
        // 大小写不匹配
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("User-Agent");
        param2.second("java/1.8.0");
        params2.add(param2);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(200, result3.first().intValue());
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        
        // 携带参数匹配
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("User-Agent");
        param3.second("Java/1.8.0");
        params3.add(param3);
        Pair<Integer,String> result4=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(200, result4.first().intValue());
    }
	
	@Test
	public void test_Condition_UserAgent_StringLike_Allow() {
	    String policyName="UserAgent_StringLike_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:UserAgent",Arrays.asList("Java/1.8.0*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:AddUserToGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        
        String body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+groupName+"&UserName="+user1Name;
        
        // 携带参数不匹配
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("User-Agent");
        param1.second("java/1.8.0_91");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(403, result.first().intValue());
        
        // 大小写不匹配
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("User-Agent");
        param2.second("java/1.8.0");
        params2.add(param2);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result3.first().intValue());
        
        // 携带参数匹配
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("User-Agent");
        param3.second("Java/1.8.0");
        params3.add(param3);
        Pair<Integer,String> result4=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(200, result4.first().intValue());
        
        body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+groupName+"&UserName="+user2Name;
        
        // 不携带该参数 本地版本 Java/1.8.0_92
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, result2.first().intValue());
        
    }
	
	@Test
    public void test_Condition_UserAgent_StringLike_Allow2() {
        String policyName="UserAgent_StringLike_Allow2";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:UserAgent",Arrays.asList("Java/1.8.0_9?")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:AddUserToGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        
        String body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+groupName+"&UserName="+user1Name;
        
        // 大小写不匹配
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("User-Agent");
        param2.second("java/1.8.0_91");
        params2.add(param2);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result3.first().intValue());
        
        // 携带参数不匹配
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("User-Agent");
        param3.second("Java/1.8.0");
        params3.add(param3);
        Pair<Integer,String> result4=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(403, result4.first().intValue());
        
        // 携带参数匹配
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("User-Agent");
        param1.second("Java/1.8.0_91");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(200, result.first().intValue());
        
        body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+groupName+"&UserName="+user2Name;
        
        // 不携带该参数 本地版本 Java/1.8.0_92
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, result2.first().intValue());
        
    } 
	
	@Test
	public void test_Condition_UserAgent_StringLike_Deny() {
	    String policyName="UserAgent_StringLike_Deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:UserAgent",Arrays.asList("Java/1.8.0*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:AddUserToGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String policyName2="UserAgent_StringNotEqualsIgnoreCase_Deny_2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:AddUserToGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        
        // 携带参数不匹配
        String body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+groupName+"&UserName="+user1Name;
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("User-Agent");
        param1.second("Java/1.8.0_91");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(403, result.first().intValue());
        
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("User-Agent");
        param3.second("Java/1.8.0");
        params3.add(param3);
        Pair<Integer,String> result4=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(403, result4.first().intValue());
        
        // 不携带该参数 本地版本 Java/1.8.0_92
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(403, result2.first().intValue());
        
        // 携带参数匹配
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("User-Agent");
        param2.second("Java/1.7.0_91");
        params2.add(param2);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(200, result3.first().intValue());
    }
	
	@Test
    public void test_Condition_UserAgent_StringLike_Deny2() {
        String policyName="UserAgent_StringLike_Deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:UserAgent",Arrays.asList("Java/1.8.0?")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:AddUserToGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String policyName2="UserAgent_StringNotEqualsIgnoreCase_Deny_2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:AddUserToGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        
        // 携带参数匹配
        String body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+groupName+"&UserName="+user1Name;
        
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("User-Agent");
        param3.second("Java/1.8.01");
        params3.add(param3);
        Pair<Integer,String> result4=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(403, result4.first().intValue());
        
        // 不携带该参数 本地版本 Java/1.8.0_92
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, result2.first().intValue());
        
        body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+groupName+"&UserName="+user2Name;
        
        // 携带参数匹配
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("User-Agent");
        param1.second("Java/1.8.0");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(200, result.first().intValue());
    }
	
	@Test
	public void test_Condition_UserAgent_StringNotLike_Allow1() {
	    String policyName="UserAgent_StringLike_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:UserAgent",Arrays.asList("Java/*_91")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName,user1Name, 200);
        
        String body="Action=RemoveUserFromGroup&Version=2010-05-08&GroupName="+groupName+"&UserName="+user1Name;
        
        // 携带参数不匹配
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("User-Agent");
        param3.second("Java/1.8.0");
        params3.add(param3);
        Pair<Integer,String> result4=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(403, result4.first().intValue());
        
        // 不携带该参数 本地版本 Java/1.8.0_92
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(403, result2.first().intValue());
        
        // 大小写不匹配
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("User-Agent");
        param2.second("java/1.8.0_91");
        params2.add(param2);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result3.first().intValue());
        
        // 携带参数匹配
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("User-Agent");
        param1.second("Java/1.8.0_91");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(200, result.first().intValue());
        
    }
	
	@Test
    public void test_Condition_UserAgent_StringNotLike_Allow2() {
	    String policyName="UserAgent_StringLike_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:UserAgent",Arrays.asList("Java/1.8.?_91")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName,user1Name, 200);
        
        String body="Action=RemoveUserFromGroup&Version=2010-05-08&GroupName="+groupName+"&UserName="+user1Name;
        
        // 携带参数不匹配
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("User-Agent");
        param3.second("Java/1.7.0_91");
        params3.add(param3);
        Pair<Integer,String> result4=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(403, result4.first().intValue());
        
        // 不携带该参数 本地版本 Java/1.8.0_92
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(403, result2.first().intValue());
        
        // 大小写不匹配
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("User-Agent");
        param2.second("java/1.8.0_91");
        params2.add(param2);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result3.first().intValue());
        
        // 携带参数匹配
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("User-Agent");
        param1.second("Java/1.8.0_91");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(200, result.first().intValue());
    }
	
	@Test
	public void test_Condition_UserAgent_StringNotLike_Deny1() {
	    String policyName="UserAgent_StringNotLike_Deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotLike","ctyun:UserAgent",Arrays.asList("Java/*_91")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String policyName2="UserAgent_StringNotEqualsIgnoreCase_Deny_2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName,user1Name, 200);
        
        String body="Action=RemoveUserFromGroup&Version=2010-05-08&GroupName="+groupName+"&UserName="+user1Name;
        
        // 携带参数不匹配
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("User-Agent");
        param3.second("Java/1.8.0");
        params3.add(param3);
        Pair<Integer,String> result4=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(403, result4.first().intValue());
        
        // 不携带该参数 本地版本 Java/1.8.0_92
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(403, result2.first().intValue());
        
        // 大小写不匹配
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("User-Agent");
        param2.second("java/1.8.0_91");
        params2.add(param2);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result3.first().intValue());
        
        // 携带参数匹配
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("User-Agent");
        param1.second("Java/1.8.0_91");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(200, result.first().intValue());
    }
	
	@Test
	public void test_Condition_UserAgent_StringNotLike_Deny2() {
	    String policyName="UserAgent_StringNotLike_Deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotLike","ctyun:UserAgent",Arrays.asList("Java/1.8.?_91")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String policyName2="UserAgent_StringNotEqualsIgnoreCase_Deny_2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName,user1Name, 200);
        
        String body="Action=RemoveUserFromGroup&Version=2010-05-08&GroupName="+groupName+"&UserName="+user1Name;
        
        // 携带参数不匹配
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("User-Agent");
        param3.second("Java/1.7.0_91");
        params3.add(param3);
        Pair<Integer,String> result4=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(403, result4.first().intValue());
        
        // 不携带该参数 本地版本 Java/1.8.0_92
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(403, result2.first().intValue());
        
        // 大小写不匹配
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("User-Agent");
        param2.second("java/1.8.0_91");
        params2.add(param2);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result3.first().intValue());
        
        // 携带参数匹配
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("User-Agent");
        param1.second("Java/1.8.0_91");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(200, result.first().intValue());
    }
	
	@Test
	public void test_Condition_Referer_StringEquals_Allow() {
	    String policyName="Referer_StringEquals_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:Referer",Arrays.asList("http://www.yourwebsitename.com/login.html")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String groupName="testGroup01";
        String body="Action=CreateGroup&Version=2010-05-08&GroupName="+groupName;
        
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("Referer");
        param1.second("http://www.yourwebsitename.com/console.html");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(403, result.first().intValue());
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("Referer");
        param2.second("http://www.yourwebsitename.com/Login.html");
        params2.add(param2);
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result2.first().intValue());
        
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("Referer");
        param3.second("http://www.yourwebsitename.com/login.html");
        params3.add(param3);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(200, result3.first().intValue());
    }
    
	@Test
    public void test_Condition_Referer_StringEquals_Deny() {
        String policyName="Referer_StringEquals_Deny1";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:Referer",Arrays.asList("http://www.yourwebsitename.com/login.html")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        String policyName2="Referer_StringEquals_Deny2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        
        
        String groupName="testGroup01";
        String body="Action=CreateGroup&Version=2010-05-08&GroupName="+groupName;
        
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("Referer");
        param1.second("http://www.yourwebsitename.com/login.html");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(403, result.first().intValue());
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("Referer");
        param2.second("http://www.yourwebsitename.com/console.html");
        params2.add(param2);
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(200, result2.first().intValue());
        
        IAMInterfaceTestUtils.DeleteGroup(accessKey, secretKey, groupName, 200);
        
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("Referer");
        param3.second("http://www.yourwebsitename.com/Login.html");
        params.add(param3);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(200, result3.first().intValue());
    }
    
	@Test
    public void test_Condition_Referer_StringNotEquals_Allow() {
	    String policyName="Referer_StringNotEquals_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","ctyun:Referer",Arrays.asList("http://www.yourwebsitename.com/login.html")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);

        String body="Action=DeleteGroup&Version=2010-05-08&GroupName="+groupName;
        
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("Referer");
        param1.second("http://www.yourwebsitename.com/login.html");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(403, result.first().intValue());
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("Referer");
        param2.second("http://www.yourwebsitename.com/console.html");
        params2.add(param2);
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(200, result2.first().intValue());
    }
    
	@Test
    public void test_Condition_Referer_StringNotEquals_Deny() {
	    String policyName="Referer_StringNotEquals_Deny1";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","ctyun:Referer",Arrays.asList("http://www.yourwebsitename.com/login.html")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:DeleteGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String policyName2="Referer_StringNotEquals_Deny2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        String body="Action=DeleteGroup&Version=2010-05-08&GroupName="+groupName;
        
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("Referer");
        param1.second("http://www.yourwebsitename.com/console.html");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(403, result.first().intValue());
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("Referer");
        param2.second("http://www.yourwebsitename.com/login.html");
        params2.add(param2);
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(200, result2.first().intValue());
    }
    
	@Test
    public void test_Condition_Referer_StringEqualsIgnoreCase_Allow() {
	    String policyName="Referer_StringEqualsIgnoreCase_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","ctyun:Referer",Arrays.asList("http://www.yourwebsitename.com/login.html")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName;
        
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("Referer");
        param1.second("http://www.yourwebsitename.com/console.html");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(403, result.first().intValue());
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("Referer");
        param2.second("http://www.yourwebsitename.com/LOGIN.HTML");
        params2.add(param2);
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(200, result2.first().intValue());
        
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("Referer");
        param3.second("http://www.yourwebsitename.com/login.html");
        params3.add(param3);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(200, result3.first().intValue());
    }
    
	@Test
    public void test_Condition_Referer_StringEqualsIgnoreCase_Deny() {
	    String policyName="Referer_StringEqualsIgnoreCase_Deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","ctyun:Referer",Arrays.asList("http://www.yourwebsitename.com/login.html")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String policyName2="Referer_StringEquals_Deny";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName;
        
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("Referer");
        param1.second("http://www.yourwebsitename.com/login.html");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(403, result.first().intValue());
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("Referer");
        param2.second("http://www.yourwebsitename.com/LOGIN.html");
        params2.add(param2);
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result2.first().intValue());
        
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("Referer");
        param3.second("http://www.yourwebsitename.com/hello.html");
        params3.add(param3);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(200, result3.first().intValue());
    }
    
	@Test
    public void test_Condition_Referer_StringNotEqualsIgnoreCase_Allow() {
	    String policyName="Referer_StringNotEqualsIgnoreCase_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","ctyun:Referer",Arrays.asList("http://www.yourwebsitename.com/login.html")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        String body="Action=ListGroups&Version=2010-05-08&GroupName="+groupName;
        
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("Referer");
        param1.second("http://www.yourwebsitename.com/login.html");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(403, result.first().intValue());
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("Referer");
        param2.second("http://www.yourwebsitename.com/LOGIN.HTML");
        params2.add(param2);
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result2.first().intValue());
        
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("Referer");
        param3.second("http://www.yourwebsitename.com/console.html");
        params3.add(param3);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(200, result3.first().intValue());
    }
    
	@Test
    public void test_Condition_Referer_StringEqualsNotIgnoreCase_Deny() {
        String policyName="Referer_StringEqualsNotIgnoreCase_Deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","ctyun:Referer",Arrays.asList("http://www.yourwebsitename.com/login.html")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String policyName2="Referer_StringEqualsNotIgnoreCase_Deny2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        String body="Action=ListGroups&Version=2010-05-08&GroupName="+groupName;
        
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("Referer");
        param1.second("http://www.yourwebsitename.com/login.html");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(200, result.first().intValue());
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("Referer");
        param2.second("http://www.yourwebsitename.com/LOGIN.HTML");
        params2.add(param2);
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(200, result2.first().intValue());
        
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("Referer");
        param3.second("http://www.yourwebsitename.com/console.html");
        params3.add(param3);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(403, result3.first().intValue());
        
    }
    
	@Test
    public void test_Condition_Referer_StringLike_Allow() {
	    String policyName="Referer_StringLike_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:Referer",Arrays.asList("http://www.yourwebsitename.com/*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:AddUserToGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        String body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+groupName+"&UserName="+user1Name;
        
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("Referer");
        param1.second("http://www.yourwebsitename.com");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(403, result.first().intValue());
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("Referer");
        param2.second("http://www.yourwebsitename.com/consode.html");
        params2.add(param2);
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(200, result2.first().intValue());
        IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, user1Name, 200);
        
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("Referer");
        param3.second("http://www.yourwebsitename.com/login.html");
        params3.add(param3);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(200, result3.first().intValue());
    }
    
	@Test
    public void test_Condition_Referer_StringLike_Deny() {
	    String policyName="Referer_StringLike_Deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:Referer",Arrays.asList("http://www.*.com/login.html")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:AddUserToGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String policyName2="Referer_StringLike_Deny2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:AddUserToGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        String body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+groupName+"&UserName="+user1Name;
        
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("Referer");
        param1.second("http://www.yourwebsitename.com/login.html");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(403, result.first().intValue());
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("Referer");
        param2.second("http://www.oos.ctyun.com/login.html");
        params2.add(param2);
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result2.first().intValue());
        IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, user1Name, 200);
        
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("Referer");
        param3.second("http://www.yourwebsitename.com/console.html");
        params3.add(param3);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(200, result3.first().intValue());
    }
    
	@Test
    public void test_Condition_Referer_StringNotLike_Allow() {
	    String policyName="Referer_StringNotLike_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotLike","ctyun:Referer",Arrays.asList("http://www.yourwebsitename.com/*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        String body="Action=RemoveUserFromGroup&Version=2010-05-08&GroupName="+groupName+"&UserName="+user1Name;
        
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("Referer");
        param1.second("http://www.yourwebsitename.com/");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(403, result.first().intValue());
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("Referer");
        param2.second("http://www.yourwebsitename.com/console.html");
        params2.add(param2);
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result2.first().intValue());
        
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("Referer");
        param3.second("http://www.ctyun.com/login.html");
        params3.add(param3);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(200, result3.first().intValue());
    }
    
	@Test
    public void test_Condition_Referer_StringNotLike_Deny() {
        String policyName="Referer_StringNotLike_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotLike","ctyun:Referer",Arrays.asList("http://www.yourwebsitename.com/*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String policyName2="Referer_StringEqualsNotIgnoreCase_Deny2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, user1Name, 200);
        
        String body="Action=RemoveUserFromGroup&Version=2010-05-08&GroupName="+groupName+"&UserName="+user1Name;
        
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("Referer");
        param1.second("http://www.ctyun.com/login.html");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(403, result.first().intValue());
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("Referer");
        param2.second("http://www.yourwebsitename.com/console.html");
        params2.add(param2);
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(200, result2.first().intValue());
        
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, user1Name, 200);
        
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("Referer");
        param3.second("http://www.yourwebsitename.com/");
        params3.add(param3);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(200, result3.first().intValue());
    }
	
	@Test
    public void test_Condition_userid_StringEquals_Allow() {
	    String policyName="userid_StringEquals_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:userid",Arrays.asList("test1abc")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(user3accessKey, user3secretKey, groupName, 403);
        IAMInterfaceTestUtils.CreateGroup(user2accessKey, user2secretKey, groupName, 403);
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200); 
    }
    
	@Test
    public void test_Condition_userid_StringEquals_Deny() {
	    String policyName="userid_StringEquals_Deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:userid",Arrays.asList("test1abc")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String policyName2="userid_StringEquals_Deny2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403); 
        IAMInterfaceTestUtils.CreateGroup(user3accessKey, user3secretKey, groupName, 200);
        IAMInterfaceTestUtils.DeleteGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.CreateGroup(user2accessKey, user2secretKey, groupName, 200);
        
    }
    
	@Test
    public void test_Condition_userid_StringNotEquals_Allow() {
	    String policyName="userid_StringNotEquals_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","ctyun:userid",Arrays.asList("test1abc")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName, 403);
        IAMInterfaceTestUtils.DeleteGroup(user3accessKey, user3secretKey, groupName, 200);
         
    }
    
	@Test
    public void test_Condition_userid_StringNotEquals_Deny() {
        String policyName="userid_StringNotEquals_Deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","ctyun:userid",Arrays.asList("test1abc")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:DeleteGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String policyName2="userid_StringNotEquals_Deny2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);

        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        
        IAMInterfaceTestUtils.DeleteGroup(user3accessKey, user3secretKey, groupName, 403);
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName, 200); 
    }
    
	@Test
    public void test_Condition_userid_StringEqualsIgnoreCase_Allow() {
	    String policyName="userid_StringEqualsIgnoreCase_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","ctyun:userid",Arrays.asList("test1abc")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:AddUserToGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user1Name,200);
        IAMInterfaceTestUtils.AddUserToGroup(user3accessKey, user3secretKey, groupName,user3Name, 403);
        IAMInterfaceTestUtils.AddUserToGroup(user2accessKey, user2secretKey, groupName,user3Name, 200);
        
    }
    
	@Test
    public void test_Condition_userid_StringEqualsIgnoreCase_Deny() {
        String policyName="userid_StringEqualsIgnoreCase_Deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","ctyun:userid",Arrays.asList("test1abc")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:AddUserToGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String policyName2="userid_StringEqualsIgnoreCase_Deny2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:AddUserToGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName, user1Name,403);
        IAMInterfaceTestUtils.AddUserToGroup(user2accessKey, user2secretKey, groupName, user1Name,403);
        IAMInterfaceTestUtils.AddUserToGroup(user3accessKey, user3secretKey, groupName, user1Name,200);
    }
    
	@Test
    public void test_Condition_userid_StringNotEqualsIgnoreCase_Allow() {
	    String policyName="userid_StringNotEqualsIgnoreCase_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","ctyun:userid",Arrays.asList("test1abc")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, user1Name, 200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user1Name,403);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user2accessKey, user2secretKey, groupName,user1Name, 403);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user3accessKey, user3secretKey, groupName,user1Name, 200);
    }
    
	@Test
    public void test_Condition_userid_StringEqualsNotIgnoreCase_Deny() {
	    String policyName="userid_StringNotEqualsIgnoreCase_Deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","ctyun:userid",Arrays.asList("test1abc")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String policyName2="userid_StringNotEqualsIgnoreCase_Deny2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, user1Name, 200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user3accessKey, user3secretKey, groupName,user1Name, 403);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName, user1Name,200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, user1Name, 200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user2accessKey, user2secretKey, groupName,user1Name, 200);
        
    }
    
	@Test
    public void test_Condition_userid_StringLike_Allow() {
	    String policyName="userid_StringLike_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:userid",Arrays.asList("*1")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName,403);
        IAMInterfaceTestUtils.GetGroup(user2accessKey, user2secretKey, groupName, 403);
        IAMInterfaceTestUtils.GetGroup(user3accessKey, user3secretKey, groupName, 200);
    }
    
	@Test
    public void test_Condition_userid_StringLike_Deny() {
        String policyName="userid_SStringLike_Deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:userid",Arrays.asList("*1")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String policyName2="userid_SStringLike_Deny2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName,200);
        IAMInterfaceTestUtils.GetGroup(user2accessKey, user2secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user3accessKey, user3secretKey, groupName, 403);
    }
    
	@Test
    public void test_Condition_userid_StringNotLike_Allow() {
	    String policyName="userid_StringNotLike_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotLike","ctyun:userid",Arrays.asList("test*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName,403);
        IAMInterfaceTestUtils.ListGroups(user2accessKey, user2secretKey, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user3accessKey, user3secretKey, groupName, 200);
    }
    
	@Test
    public void test_Condition_userid_StringNotLike_Deny() {
	    String policyName="userid_StringNotLike_Deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotLike","ctyun:userid",Arrays.asList("test*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String policyName2="userid_StringNotLike_Deny2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName,200);
        IAMInterfaceTestUtils.ListGroups(user2accessKey, user2secretKey, groupName, 403);
        IAMInterfaceTestUtils.ListGroups(user3accessKey, user3secretKey, groupName, 403);
    }
    
	@Test
    public void test_Condition_username_StringEquals_Allow() {
	    String policyName="userid_username_StringEquals_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList("test_1")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(user2accessKey, user2secretKey, groupName, 403);
        IAMInterfaceTestUtils.CreateGroup(user3accessKey, user3secretKey, groupName, 403);
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName,200);
    }
    
	@Test
    public void test_Condition_username_StringEquals_Deny() {
	    String policyName="username_StringEquals_Deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList("test_1")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String policyName2="username_StringEquals_Deny2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName,403); 
        IAMInterfaceTestUtils.CreateGroup(user2accessKey, user2secretKey, groupName, 200);
        IAMInterfaceTestUtils.DeleteGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.CreateGroup(user3accessKey, user3secretKey, groupName, 200);
        
    }
    
	@Test
    public void test_Condition_username_StringNotEquals_Allow() {
	    String policyName="username_StringNotEquals_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","ctyun:username",Arrays.asList("test_1")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName,403);
        IAMInterfaceTestUtils.DeleteGroup(user2accessKey, user2secretKey, groupName, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.DeleteGroup(user3accessKey, user3secretKey, groupName, 200);
        
    }
    
	@Test
    public void test_Condition_username_StringNotEquals_Deny() {
	    String policyName="username_StringNotEquals_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","ctyun:username",Arrays.asList("test_1")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:DeleteGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String policyName2="username_StringEquals_Deny2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeleteGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.DeleteGroup(user2accessKey, user2secretKey, groupName, 403);
        IAMInterfaceTestUtils.DeleteGroup(user3accessKey, user3secretKey, groupName, 403);
        
        IAMInterfaceTestUtils.DeleteGroup(user1accessKey1, user1secretKey1, groupName,200);
    }
    
	@Test
    public void test_Condition_username_StringEqualsIgnoreCase_Allow() {
	    String policyName="username_StringEqualsIgnoreCase_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","ctyun:username",Arrays.asList("abc1")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:AddUserToGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName,user1Name,403);
        IAMInterfaceTestUtils.AddUserToGroup(user2accessKey, user2secretKey, groupName, user1Name,403);
        IAMInterfaceTestUtils.AddUserToGroup(user3accessKey, user3secretKey, groupName,user1Name, 200);
    }
    
	@Test
    public void test_Condition_username_StringEqualsIgnoreCase_Deny() {
	    String policyName="username_StringEqualsIgnoreCase_Deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","ctyun:username",Arrays.asList("abc1")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:AddUserToGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String policyName2="username_StringEqualsIgnoreCase_Deny2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:AddUserToGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        
        IAMInterfaceTestUtils.AddUserToGroup(user3accessKey, user3secretKey, groupName,user3Name, 403);
        IAMInterfaceTestUtils.AddUserToGroup(user1accessKey1, user1secretKey1, groupName,user3Name,200);
        IAMInterfaceTestUtils.AddUserToGroup(user2accessKey, user2secretKey, groupName, user1Name,200);
        
    }
    
	@Test
    public void test_Condition_username_StringNotEqualsIgnoreCase_Allow() {
	    String policyName="username_StringNotEqualsIgnoreCase_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","ctyun:username",Arrays.asList("abc1")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName,user1Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user3accessKey, user3secretKey, groupName,user1Name, 403);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName,user1Name,200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName,user1Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user2accessKey, user2secretKey, groupName, user1Name,200);
        
    }
    
	@Test
    public void test_Condition_username_StringEqualsNotIgnoreCase_Deny() {
	    String policyName="username_StringNotEqualsIgnoreCase_Deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","ctyun:username",Arrays.asList("abc1")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String policyName2="username_StringNotEqualsIgnoreCase_Deny2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:RemoveUserFromGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
        
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName,user1Name,200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user1accessKey1, user1secretKey1, groupName,user1Name,403);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user2accessKey, user2secretKey, groupName, user1Name,403);
        IAMInterfaceTestUtils.RemoveUserFromGroup(user3accessKey, user3secretKey, groupName,user1Name, 200);
    }
    
	@Test
    public void test_Condition_username_StringLike_Allow() {
	    String policyName="username_StringLike_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("*1*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName,200);
        IAMInterfaceTestUtils.GetGroup(user2accessKey, user2secretKey, groupName, 403);
        IAMInterfaceTestUtils.GetGroup(user3accessKey, user3secretKey, groupName,200);
    }
    
	@Test
    public void test_Condition_username_StringLike_Deny() {
	    String policyName="username_StringLike_Deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("*1*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String policyName2="username_StringLike_Deny2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName,403);
        IAMInterfaceTestUtils.GetGroup(user3accessKey, user3secretKey, groupName,403);
        IAMInterfaceTestUtils.GetGroup(user2accessKey, user2secretKey, groupName, 200);
        
    }
    
	@Test
    public void test_Condition_username_StringNotLike_Allow() {
	    String policyName="username_StringNotLike_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("*1*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName,200);
        IAMInterfaceTestUtils.ListGroups(user2accessKey, user2secretKey, groupName, 403);
        IAMInterfaceTestUtils.ListGroups(user3accessKey, user3secretKey, groupName,200);
    }
    
	@Test
    public void test_Condition_username_StringNotLike_Deny() {
	    String policyName="username_StringNotLike_Deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("*1*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String policyName2="username_StringNotLike_Deny2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
        
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName,403);
        IAMInterfaceTestUtils.ListGroups(user2accessKey, user2secretKey, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user3accessKey, user3secretKey, groupName,403);
    }
	
	@Test
    public void test_Condition_CurrentTime_DateEquals_Allow() {
	    
	    String yesterdayString=OneDay0UTCTimeString(-1);
	    String todyString=OneDay0UTCTimeString(0);
	    
	    String policyName="username_CurrentTime_DateEquals_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("DateEquals","ctyun:CurrentTime",Arrays.asList(yesterdayString)));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName,403);

        String policyName2="username_CurrentTime_DateEquals_Allow2";
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("DateEquals","ctyun:CurrentTime",Arrays.asList(todyString)));
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions2);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);

        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName,200);
        IAMInterfaceTestUtils.ListGroups(user3accessKey, user3secretKey, groupName,200);
    }
	
	@Test
	/*
	 * 日期使用equal的时候，紧日期有效果，后面的时间不起作用
	 */
    public void test_Condition_CurrentTime_DateEquals_Allow2() {
        
	    String yesterdayString=OneDay0UTCTimeString(-1);
        String todyString=OneDay0UTCTimeString(0);
        
        String policyName="username_CurrentTime_DateEquals_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("DateEquals","ctyun:CurrentTime",Arrays.asList(yesterdayString)));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName,403);

        String policyName2="username_CurrentTime_DateEquals_Allow2";
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("DateEquals","ctyun:CurrentTime",Arrays.asList(todyString)));
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions2);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);

        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName,200);
        IAMInterfaceTestUtils.ListGroups(user3accessKey, user3secretKey, groupName,200);
    }
    
	@Test
    public void test_Condition_CurrentTime_DateEquals_Deny() {
	    
	    String policyName="username_CurrentTime_DateEquals_Deny2";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
       
        String yesterdayString=OneDay0UTCTimeString(-1);
        String todyString=OneDay0UTCTimeString(0);
        
        String policyName2="username_CurrentTime_DateEquals_Allow";
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("DateEquals","ctyun:CurrentTime",Arrays.asList(yesterdayString)));
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions2);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user2accessKey, user2secretKey, groupName,200);
        
        String policyName3="username_CurrentTime_DateEquals_Deny";
        List<Condition> conditions3 = new ArrayList<Condition>();
        conditions3.add(IAMTestUtils.CreateCondition("DateEquals","ctyun:CurrentTime",Arrays.asList(todyString)));
        String policyString3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions3);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName3, policyString3,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName3, 200);
       
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName,403);
        IAMInterfaceTestUtils.ListGroups(user3accessKey, user3secretKey, groupName,403);
    }
    
	@Test
    public void test_Condition_CurrentTime_DateNotEquals_Allow() {
	    String yesterdayString=OneDay0UTCTimeString(-1);
        String todyString=OneDay0UTCTimeString(0);
        
        String policyName1="username_CurrentTime_DateNotEquals_Allow";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("DateNotEquals","ctyun:CurrentTime",Arrays.asList(todyString)));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName1, 200);
        
        String policyName2="username_CurrentTime_DateNotEquals_Allow2";
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("DateNotEquals","ctyun:CurrentTime",Arrays.asList(yesterdayString)));
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions2);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName,403);
        IAMInterfaceTestUtils.ListGroups(user3accessKey, user3secretKey, groupName,403);
        IAMInterfaceTestUtils.ListGroups(user2accessKey, user2secretKey, groupName,200);
    }
    
	@Test
    public void test_Condition_CurrentTime_DateNotEquals_Deny() {
	    String yesterdayString=OneDay0UTCTimeString(-1);
        String todyString=OneDay0UTCTimeString(0);
        
        String policyName="CurrentTime_Allow";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String policyName1="CurrentTime_CurrentTime_DateNotEquals_Deny";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("DateNotEquals","ctyun:CurrentTime",Arrays.asList(todyString)));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName1, 200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName,200);
        IAMInterfaceTestUtils.ListGroups(user3accessKey, user3secretKey, groupName,200);
        
        String policyName2="CurrentTime_CurrentTime_DateNotEquals_Deny2";
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("DateNotEquals","ctyun:CurrentTime",Arrays.asList(yesterdayString)));
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions2);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

        IAMInterfaceTestUtils.ListGroups(user2accessKey, user2secretKey, groupName,403);
        
    }
    
	@Test
    public void test_Condition_CurrentTime_DateLessThan_Allow() {;
        String yesterdayString=OneDay0UTCTimeString(-1);
        String todyString=OneDay0UTCTimeString(0);
        String tomorrowString=OneDay0UTCTimeString(1);
        
        String policyName1="CurrentTime_DateLessThan_Allow";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("DateLessThan","ctyun:CurrentTime",Arrays.asList(tomorrowString)));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        
        String policyName2="CurrentTime_DateLessThan_Allow2";
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("DateLessThan","ctyun:CurrentTime",Arrays.asList(todyString)));
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions2);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
        
        String policyName3="CurrentTime_DateLessThan_Allow3";
        List<Condition> conditions3 = new ArrayList<Condition>();
        conditions3.add(IAMTestUtils.CreateCondition("DateLessThan","ctyun:CurrentTime",Arrays.asList(yesterdayString)));
        String policyString3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions3);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName3, policyString3,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName3, 200);
        

        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName,200);
        IAMInterfaceTestUtils.GetGroup(user2accessKey, user2secretKey, groupName,403);
        IAMInterfaceTestUtils.GetGroup(user3accessKey, user3secretKey, groupName,403);
        
    }
    
	@Test
    public void test_Condition_CurrentTime_DateLessThan_Deny() {
	    String yesterdayString=OneDay0UTCTimeString(-1);
        String todyString=OneDay0UTCTimeString(0);
        String tomorrowString=OneDay0UTCTimeString(1);
        
        String policyName="CurrentTime_Allow";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String policyName1="CurrentTime_DateLessThan_Allow";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("DateLessThan","ctyun:CurrentTime",Arrays.asList(tomorrowString)));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        
        String policyName2="CurrentTime_DateLessThan_Allow2";
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("DateLessThan","ctyun:CurrentTime",Arrays.asList(todyString)));
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions2);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
        
        String policyName3="CurrentTime_DateLessThan_Allow3";
        List<Condition> conditions3 = new ArrayList<Condition>();
        conditions3.add(IAMTestUtils.CreateCondition("DateLessThan","ctyun:CurrentTime",Arrays.asList(yesterdayString)));
        String policyString3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions3);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName3, policyString3,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName3, 200);
        

        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName,403);
        IAMInterfaceTestUtils.GetGroup(user2accessKey, user2secretKey, groupName,200);
        IAMInterfaceTestUtils.GetGroup(user3accessKey, user3secretKey, groupName,200);
    }
    
	@Test
    public void test_Condition_CurrentTime_DateLessThanEquals_Allow() {
        String yesterdayString=OneDay0UTCTimeString(-1);
        String todyString=OneDay0UTCTimeString(0);
        String tomorrowString=OneDay0UTCTimeString(1);
        
        String policyName1="CurrentTime_DateLessThanEquals_Allow";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("DateLessThanEquals","ctyun:CurrentTime",Arrays.asList(tomorrowString)));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        
        String policyName2="CurrentTime_DateLessThanEquals_Allow2";
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("DateLessThanEquals","ctyun:CurrentTime",Arrays.asList(todyString)));
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions2);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
        
        String policyName3="CurrentTime_DateLessThanEquals_Allow3";
        List<Condition> conditions3 = new ArrayList<Condition>();
        conditions3.add(IAMTestUtils.CreateCondition("DateLessThanEquals","ctyun:CurrentTime",Arrays.asList(yesterdayString)));
        String policyString3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions3);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName3, policyString3,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName3, 200);
        

        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName,200);
        IAMInterfaceTestUtils.GetGroup(user2accessKey, user2secretKey, groupName,403);
        IAMInterfaceTestUtils.GetGroup(user3accessKey, user3secretKey, groupName,403);
    }
    
	@Test
    public void test_Condition_CurrentTime_DateLessThanEquals_Deny() {
	    String yesterdayString=OneDay0UTCTimeString(-1);
        String todyString=OneDay0UTCTimeString(0);
        String tomorrowString=OneDay0UTCTimeString(1);
        
        String policyName="CurrentTime_Allow";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String policyName1="CurrentTime_DateLessThanEquals_Allow";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("DateLessThanEquals","ctyun:CurrentTime",Arrays.asList(tomorrowString)));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        
        String policyName2="CurrentTime_DateLessThanEquals_Allow2";
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("DateLessThanEquals","ctyun:CurrentTime",Arrays.asList(todyString)));
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions2);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
        
        String policyName3="CurrentTime_DateLessThanEquals_Allow3";
        List<Condition> conditions3 = new ArrayList<Condition>();
        conditions3.add(IAMTestUtils.CreateCondition("DateLessThanEquals","ctyun:CurrentTime",Arrays.asList(yesterdayString)));
        String policyString3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions3);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName3, policyString3,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName3, 200);
        

        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName,403);
        IAMInterfaceTestUtils.GetGroup(user2accessKey, user2secretKey, groupName,200);
        IAMInterfaceTestUtils.GetGroup(user3accessKey, user3secretKey, groupName,200);
    }
    
	@Test
    public void test_Condition_CurrentTime_DateGreaterThan_Allow() {
	    String yesterdayString=OneDay0UTCTimeString(-1);
        String todyString=OneDay0UTCTimeString(0);
        String tomorrowString=OneDay0UTCTimeString(1);
        
        String policyName1="CurrentTime_DateGreaterThan_Allow";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("DateGreaterThan","ctyun:CurrentTime",Arrays.asList(tomorrowString)));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        
        String policyName2="CurrentTime_DateGreaterThan_Allow2";
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("DateGreaterThan","ctyun:CurrentTime",Arrays.asList(todyString)));
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions2);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
        
        String policyName3="CurrentTime_DateGreaterThan_Allow3";
        List<Condition> conditions3 = new ArrayList<Condition>();
        conditions3.add(IAMTestUtils.CreateCondition("DateGreaterThan","ctyun:CurrentTime",Arrays.asList(yesterdayString)));
        String policyString3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions3);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName3, policyString3,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName3, 200);
        

        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName,403);
        IAMInterfaceTestUtils.GetGroup(user2accessKey, user2secretKey, groupName,200);
        IAMInterfaceTestUtils.GetGroup(user3accessKey, user3secretKey, groupName,200);
    }
    
	@Test
    public void test_Condition_CurrentTime_DateGreaterThan_Deny() {
	    String yesterdayString=OneDay0UTCTimeString(-1);
        String todyString=OneDay0UTCTimeString(0);
        String tomorrowString=OneDay0UTCTimeString(1);
        
        String policyName="CurrentTime_Allow";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String policyName1="CurrentTime_DateGreaterThan_Allow";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("DateGreaterThan","ctyun:CurrentTime",Arrays.asList(tomorrowString)));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        
        String policyName2="CurrentTime_DateGreaterThan_Allow2";
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("DateGreaterThan","ctyun:CurrentTime",Arrays.asList(todyString)));
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions2);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
        
        String policyName3="CurrentTime_DateGreaterThan_Allow3";
        List<Condition> conditions3 = new ArrayList<Condition>();
        conditions3.add(IAMTestUtils.CreateCondition("DateGreaterThan","ctyun:CurrentTime",Arrays.asList(yesterdayString)));
        String policyString3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions3);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName3, policyString3,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName3, 200);
        

        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName,200);
        IAMInterfaceTestUtils.GetGroup(user2accessKey, user2secretKey, groupName,403);
        IAMInterfaceTestUtils.GetGroup(user3accessKey, user3secretKey, groupName,403);
    }
    
	@Test
    public void test_Condition_CurrentTime_DateGreaterThanEquals_Allow() {
	    String yesterdayString=OneDay0UTCTimeString(-1);
        String todyString=OneDay0UTCTimeString(0);
        String tomorrowString=OneDay0UTCTimeString(1);
        
        String policyName1="CurrentTime_DateGreaterThanEquals_Allow";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("DateGreaterThanEquals","ctyun:CurrentTime",Arrays.asList(tomorrowString)));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        
        String policyName2="CurrentTime_DateGreaterThanEquals_Allow2";
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("DateGreaterThanEquals","ctyun:CurrentTime",Arrays.asList(todyString)));
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions2);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
        
        String policyName3="CurrentTime_DateGreaterThanEquals_Allow3";
        List<Condition> conditions3 = new ArrayList<Condition>();
        conditions3.add(IAMTestUtils.CreateCondition("DateGreaterThanEquals","ctyun:CurrentTime",Arrays.asList(yesterdayString)));
        String policyString3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions3);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName3, policyString3,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName3, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName,403);
        IAMInterfaceTestUtils.GetGroup(user2accessKey, user2secretKey, groupName,200);
        IAMInterfaceTestUtils.GetGroup(user3accessKey, user3secretKey, groupName,200);
    }
    
	@Test
    public void test_Condition_CurrentTime_DateGreaterThanEquals_Deny() {
	    String yesterdayString=OneDay0UTCTimeString(-1);
        String todyString=OneDay0UTCTimeString(0);
        String tomorrowString=OneDay0UTCTimeString(1);
        
        String policyName="CurrentTime_Allow";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String policyName1="CurrentTime_DateGreaterThanEquals_Allow";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("DateGreaterThanEquals","ctyun:CurrentTime",Arrays.asList(tomorrowString)));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        
        String policyName2="CurrentTime_DateGreaterThanEquals_Allow2";
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("DateGreaterThanEquals","ctyun:CurrentTime",Arrays.asList(todyString)));
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions2);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
        
        String policyName3="CurrentTime_DateGreaterThanEquals_Allow3";
        List<Condition> conditions3 = new ArrayList<Condition>();
        conditions3.add(IAMTestUtils.CreateCondition("DateGreaterThanEquals","ctyun:CurrentTime",Arrays.asList(yesterdayString)));
        String policyString3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions3);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName3, policyString3,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName3, 200);
        

        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName,200);
        IAMInterfaceTestUtils.GetGroup(user2accessKey, user2secretKey, groupName,403);
        IAMInterfaceTestUtils.GetGroup(user3accessKey, user3secretKey, groupName,403);
    }
    
	@Test
    public void test_Condition_SecureTransport_true_Allow() {
	    String policyName="SecureTransport_true_Allow";
	    String groupName="testGroup01";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("Bool","ctyun:SecureTransport",Arrays.asList("true")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // 允许ssl访问 
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);

    }
    
	@Test
    public void test_Condition_SecureTransport_true_Deny() {
        String groupName="testGroup01";
        
        String policyName="Allow";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        
        String policyName1="SecureTransport_true_Deny"; 
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("Bool","ctyun:SecureTransport",Arrays.asList("true")));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 403);
        
    }
    
	@Test
    public void test_Condition_SecureTransport_false_Allow() {
        String groupName="testGroup01";
        String policyName="Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("Bool","ctyun:SecureTransport",Arrays.asList("false")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName, 403);
        
    }
    
	@Test
    public void test_Condition_SecureTransport_false_Deny() {
	    String groupName="testGroup01";
        
        String policyName="Allow";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        
        String policyName1="SecureTransport_true_Deny"; 
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("Bool","ctyun:SecureTransport",Arrays.asList("false")));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        
    }
    
	@Test
    public void test_Condition_SourceIp_IpAddress_Allow() {
	    String groupName="testGroup01";;
        String userName=user1Name;
        String policyName="allowspecialIP";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("IpAddress","ctyun:SourceIp",Arrays.asList("192.168.1.1/24","192.168.3.1")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);

        // 在IP范围
        String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName;
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("X-Forwarded-For");
        param1.second("192.168.1.101");
        params.add(param1);
        
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(200, result.first().intValue());
        
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("Proxy-Client-IP");
        param2.second("192.168.3.1");
        params2.add(param2);
        
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(200, result2.first().intValue());
        
        // 不在IP范围
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("X-Forwarded-For");
        param3.second("192.168.2.101");
        params3.add(param3);
        
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(403, result3.first().intValue());
    }
    
	@Test
    public void test_Condition_SourceIpt_IpAddress_Deny() {
	    String groupName="testGroup01";;
        String userName=user1Name;
        
        String policyName="Allow";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String policyName1="allowspecialIP";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("IpAddress","ctyun:SourceIp",Arrays.asList("192.168.1.1/24","192.168.3.1")));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName1,200);
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);

        // 在IP范围
        String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName;
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("X-Forwarded-For");
        param1.second("192.168.1.101");
        params.add(param1);
        
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(403, result.first().intValue());
        
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("WL-Proxy-Client-IP");
        param2.second("192.168.3.1");
        params2.add(param2);
        
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result2.first().intValue());
        
        // 不在IP范围
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("X-Forwarded-For");
        param3.second("192.168.2.101");
        params3.add(param3);
        
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(200, result3.first().intValue());
    }
    
	@Test
    public void test_Condition_SourceIp_NotIpAddress_Allow() {
	    String groupName="testGroup01";;
        String userName=user1Name;
        String policyName="allowspecialIP";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("NotIpAddress","ctyun:SourceIp",Arrays.asList("192.168.1.1/24","192.168.3.1")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);

        // 在IP范围
        String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName;
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("X-Forwarded-For");
        param1.second("192.168.1.101");
        params.add(param1);
        
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(403, result.first().intValue());
        
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("HTTP_CLIENT_IP");
        param2.second("192.168.3.1");
        params2.add(param2);
        
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result2.first().intValue());
        
        // 不在IP范围
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("X-Forwarded-For");
        param3.second("192.168.2.101");
        params3.add(param3);
        
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(200, result3.first().intValue());
    }
    
	@Test
    public void test_Condition_SourceIpt_NotIpAddress_Deny() {
	    String groupName="testGroup01";
        String userName=user1Name;
        
        String policyName="Allow";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String policyName1="allowspecialIP";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("NotIpAddress","ctyun:SourceIp",Arrays.asList("192.168.1.1/24","192.168.3.1")));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName1,200);
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);

        // 在IP范围
        String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName;
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("X-Forwarded-For");
        param1.second("192.168.1.101");
        params.add(param1);
        
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(200, result.first().intValue());
        
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("HTTP_X_FORWARDED_FOR");
        param2.second("192.168.3.1");
        params2.add(param2);
        
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(200, result2.first().intValue());
        
        // 不在IP范围
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("X-Forwarded-For");
        param3.second("192.168.2.101");
        params3.add(param3);
        
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(403, result3.first().intValue());
    }
	
	@Test
	/*
	 * 四个condition在一个statement中
	 */
	public void test_Condition_StringOperator_OneStatement() {
	    String policyName1="Allow_all_username";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test*")));
        conditions1.add(IAMTestUtils.CreateCondition("StringNotEquals","ctyun:username",Arrays.asList("test_2")));
        conditions1.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","ctyun:Referer",Arrays.asList("http://www.yourwebsitename.com/login.html")));
        conditions1.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:UserAgent",Arrays.asList("Java/1.8.0_91")));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("*"),"Resource",Arrays.asList("*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName1,200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        
        String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName;
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("User-Agent");
        param1.second("Java/1.8.0_91");
        params.add(param1);
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("Referer");
        param2.second("http://www.yourwebsitename.com/Login.html");
        params.add(param2);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(200, result.first().intValue());
        
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user2accessKey, user2secretKey,params);
        assertEquals(403, result2.first().intValue());
        
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user3accessKey, user3secretKey,params);
        assertEquals(403, result3.first().intValue());
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("User-Agent");
        param3.second("Java/1.8.0_92");
        params2.add(param3);
        Pair<String, String>  param4= new Pair<String, String>();
        param4.first("Referer");
        param4.second("http://www.yourwebsitename.com/console.html");
        params2.add(param4);
        Pair<Integer,String> result4=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result4.first().intValue());
        
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        params3.add(param1);
        params3.add(param4);
        Pair<Integer,String> result5=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(403, result5.first().intValue());
        
        List<Pair<String, String>> params4=new ArrayList<Pair<String,String>>();
        params3.add(param2);
        params3.add(param3);
        Pair<Integer,String> result6=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params4);
        assertEquals(403, result6.first().intValue());
        
    }
	
	@Test
    public void test_Condition_StringOperator_TwoStatements() {
	    
	    String policyName="test_AllowAllow1";
        List<Statement> statements= new ArrayList<Statement>();
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test*")));
        conditions1.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","ctyun:Referer",Arrays.asList("http://www.yourwebsitename.com/login.html")));
        Statement s1=IAMTestUtils.CreateStatement(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+"*"),conditions1);
        statements.add(s1);
        
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("StringNotEquals","ctyun:username",Arrays.asList("test_2")));
        conditions2.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:UserAgent",Arrays.asList("Java/1.8.0_91")));
        Statement s2=IAMTestUtils.CreateStatement(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+"*"),conditions2);
        statements.add(s2);
        String policyString=IAMTestUtils.CreateMoreStatement(statements);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName,200);

        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("User-Agent");
        param1.second("Java/1.8.0_91");
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("Referer");
        param2.second("http://www.yourwebsitename.com/Login.html");
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("User-Agent");
        param3.second("Java/1.8.0_92");
        Pair<String, String>  param4= new Pair<String, String>();
        param4.first("Referer");
        param4.second("http://www.yourwebsitename.com/console.html");
       
        
        String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName;
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        params.add(param1);
        params.add(param2);

        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(200, result.first().intValue());
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user2accessKey, user2secretKey,params);
        assertEquals(200, result2.first().intValue());
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user3accessKey, user3secretKey,params);
        assertEquals(200, result3.first().intValue());
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        params2.add(param3);
        params2.add(param4);
        Pair<Integer,String> result4=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result4.first().intValue());
        Pair<Integer,String> result5=IAMTestUtils.invokeHttpsRequest2(body, user2accessKey, user2secretKey,params2);
        assertEquals(403, result5.first().intValue());
        Pair<Integer,String> result6=IAMTestUtils.invokeHttpsRequest2(body, user3accessKey, user3secretKey,params2);
        assertEquals(403, result6.first().intValue());
        
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        params3.add(param1);
        params3.add(param4);
        Pair<Integer,String> result7=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(200, result7.first().intValue());
        Pair<Integer,String> result8=IAMTestUtils.invokeHttpsRequest2(body, user2accessKey, user2secretKey,params3);
        assertEquals(403, result8.first().intValue());
        Pair<Integer,String> result9=IAMTestUtils.invokeHttpsRequest2(body, user3accessKey, user3secretKey,params3);
        assertEquals(200, result9.first().intValue());
        
        List<Pair<String, String>> params4=new ArrayList<Pair<String,String>>();
        params3.add(param2);
        params3.add(param3);
        Pair<Integer,String> result10=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params4);
        assertEquals(403, result10.first().intValue());
        Pair<Integer,String> result11=IAMTestUtils.invokeHttpsRequest2(body, user2accessKey, user2secretKey,params4);
        assertEquals(403, result11.first().intValue());
        Pair<Integer,String> result12=IAMTestUtils.invokeHttpsRequest2(body, user3accessKey, user3secretKey,params4);
        assertEquals(403, result12.first().intValue());
        
    }
	
	@Test
	public void test_Condition_StringOperator_TwoPolicy() {
	    String policyName1="Allow_TwoPolicy1";
        String policyName2="Allow_TwoPolicy2";
        
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test*")));
        conditions1.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","ctyun:Referer",Arrays.asList("http://www.yourwebsitename.com/login.html")));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+"*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("StringNotEquals","ctyun:username",Arrays.asList("test_2")));
        conditions2.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:UserAgent",Arrays.asList("Java/1.8.0_91")));
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+"*"),conditions2);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
         
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName2,200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("User-Agent");
        param1.second("Java/1.8.0_91");
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("Referer");
        param2.second("http://www.yourwebsitename.com/Login.html");
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("User-Agent");
        param3.second("Java/1.8.0_92");
        Pair<String, String>  param4= new Pair<String, String>();
        param4.first("Referer");
        param4.second("http://www.yourwebsitename.com/console.html");
       
        
        String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName;
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        params.add(param1);
        params.add(param2);

        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(200, result.first().intValue());
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user2accessKey, user2secretKey,params);
        assertEquals(200, result2.first().intValue());
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user3accessKey, user3secretKey,params);
        assertEquals(200, result3.first().intValue());
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        params2.add(param3);
        params2.add(param4);
        Pair<Integer,String> result4=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result4.first().intValue());
        Pair<Integer,String> result5=IAMTestUtils.invokeHttpsRequest2(body, user2accessKey, user2secretKey,params2);
        assertEquals(403, result5.first().intValue());
        Pair<Integer,String> result6=IAMTestUtils.invokeHttpsRequest2(body, user3accessKey, user3secretKey,params2);
        assertEquals(403, result6.first().intValue());
        
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        params3.add(param1);
        params3.add(param4);
        Pair<Integer,String> result7=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(200, result7.first().intValue());
        Pair<Integer,String> result8=IAMTestUtils.invokeHttpsRequest2(body, user2accessKey, user2secretKey,params3);
        assertEquals(403, result8.first().intValue());
        Pair<Integer,String> result9=IAMTestUtils.invokeHttpsRequest2(body, user3accessKey, user3secretKey,params3);
        assertEquals(200, result9.first().intValue());
        
        List<Pair<String, String>> params4=new ArrayList<Pair<String,String>>();
        params3.add(param2);
        params3.add(param3);
        Pair<Integer,String> result10=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params4);
        assertEquals(403, result10.first().intValue());
        Pair<Integer,String> result11=IAMTestUtils.invokeHttpsRequest2(body, user2accessKey, user2secretKey,params4);
        assertEquals(403, result11.first().intValue());
        Pair<Integer,String> result12=IAMTestUtils.invokeHttpsRequest2(body, user3accessKey, user3secretKey,params4);
        assertEquals(403, result12.first().intValue());
    }
	
	@Test
    public void test_Condition_TimeOperatorOneStatement() {
	    String groupName="testGroup01";
	    
	    String policyName1="Allow_all_username";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("DateGreaterThan","ctyun:CurrentTime",Arrays.asList("2019-01-01T00:00:00Z")));
        conditions1.add(IAMTestUtils.CreateCondition("DateLessThan","ctyun:CurrentTime",Arrays.asList("2050-01-01T00:00:00Z")));
        conditions1.add(IAMTestUtils.CreateCondition("DateNotEquals","ctyun:CurrentTime",Arrays.asList("2019-05-01T00:00:00Z")));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("*"),"Resource",Arrays.asList("*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1,200);
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        
        String todayString=OneDay0UTCTimeString(0);
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("DateGreaterThan","ctyun:CurrentTime",Arrays.asList("2019-01-01T00:00:00Z")));
        conditions2.add(IAMTestUtils.CreateCondition("DateLessThan","ctyun:CurrentTime",Arrays.asList("2050-01-01T00:00:00Z")));
        conditions2.add(IAMTestUtils.CreateCondition("DateNotEquals","ctyun:CurrentTime",Arrays.asList(todayString)));
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("*"),"Resource",Arrays.asList("*"),conditions2);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1,200);
        
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 403);
        
        
        List<Condition> conditions3 = new ArrayList<Condition>();
        conditions3.add(IAMTestUtils.CreateCondition("DateGreaterThan","ctyun:CurrentTime",Arrays.asList("2025-01-01T00:00:00Z")));
        conditions3.add(IAMTestUtils.CreateCondition("DateLessThan","ctyun:CurrentTime",Arrays.asList("2050-01-01T00:00:00Z")));
        conditions3.add(IAMTestUtils.CreateCondition("DateNotEquals","ctyun:CurrentTime",Arrays.asList("2019-05-01T00:00:00Z")));
        String policyString3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("*"),"Resource",Arrays.asList("*"),conditions3);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString3,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1,200);
        
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 403);
        
    }
	
	@Test
    public void test_Condition_TimeOperatorTwoStatements() {
	    String policyName="test_AllowAllow1";
        List<Statement> statements= new ArrayList<Statement>();
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("DateLessThan","ctyun:CurrentTime",Arrays.asList("2050-01-01T00:00:00Z")));
        conditions1.add(IAMTestUtils.CreateCondition("DateNotEquals","ctyun:CurrentTime",Arrays.asList("2019-05-01T00:00:00Z")));
        Statement s1=IAMTestUtils.CreateStatement(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+"*"),conditions1);
        statements.add(s1);
        
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("DateGreaterThan","ctyun:CurrentTime",Arrays.asList("2025-01-01T00:00:00Z")));
        Statement s2=IAMTestUtils.CreateStatement(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+"*"),conditions2);
        statements.add(s2);
        String policyString=IAMTestUtils.CreateMoreStatement(statements);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
    }
	
	@Test
    public void test_Condition_TimeOperatorTwoPolicy() {
	    String policyName1="Allow_TwoPolicy1";
        String policyName2="Allow_TwoPolicy2";
        
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("DateLessThan","ctyun:CurrentTime",Arrays.asList("2050-01-01T00:00:00Z")));
        conditions1.add(IAMTestUtils.CreateCondition("DateNotEquals","ctyun:CurrentTime",Arrays.asList("2019-05-01T00:00:00Z")));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+"*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("DateGreaterThan","ctyun:CurrentTime",Arrays.asList("2025-01-01T00:00:00Z")));
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+"*"),conditions2);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2,200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        
    }
	
	@Test
    public void test_Condition_AddessOperatorOneStatement() {
	    String groupName="testGroup01";
        
        String policyName1="Allow_all_username";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("IpAddress","ctyun:SourceIp",Arrays.asList("192.168.1.1/24")));
        conditions1.add(IAMTestUtils.CreateCondition("NotIpAddress","ctyun:SourceIp",Arrays.asList("192.168.1.255")));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("*"),"Resource",Arrays.asList("*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1,200);
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName;
        
        // 在IP范围
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
        param2.second("192.168.2.255");
        params2.add(param2);
        
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result2.first().intValue());
        
        
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("X-Forwarded-For");
        param3.second("192.168.2.101");
        params3.add(param3);
        
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(403, result3.first().intValue());
        
    }
	
	@Test
    public void test_Condition_AddessOperatorTwoStatements() {
	    String groupName="testGroup01";
	    String policyName="test_AllowAllow1";
        List<Statement> statements= new ArrayList<Statement>();
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("IpAddress","ctyun:SourceIp",Arrays.asList("192.168.1.1/24")));
        Statement s1=IAMTestUtils.CreateStatement(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+"*"),conditions1);
        statements.add(s1);
        
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("NotIpAddress","ctyun:SourceIp",Arrays.asList("192.168.1.255")));
        Statement s2=IAMTestUtils.CreateStatement(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+"*"),conditions2);
        statements.add(s2);
        String policyString=IAMTestUtils.CreateMoreStatement(statements);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName;
        
        // 在IP范围
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("X-Forwarded-For");
        param1.second("192.168.1.101");
        params.add(param1);
        
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(200, result.first().intValue());
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("X-Forwarded-For");
        param2.second("192.168.2.255");
        params2.add(param2);
        
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(200, result2.first().intValue());
        
        
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("X-Forwarded-For");
        param3.second("192.168.2.101");
        params3.add(param3);
        
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(200, result3.first().intValue());
        
    }
	
	@Test
    public void test_Condition_AddessOperatorTwoPolicy() {
	    String policyName1="Allow_TwoPolicy1";
        String policyName2="Allow_TwoPolicy2";
        
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("IpAddress","ctyun:SourceIp",Arrays.asList("192.168.1.1/24")));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+"*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("NotIpAddress","ctyun:SourceIp",Arrays.asList("192.168.1.255")));
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+"*"),conditions2);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2,200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName;
        
        // 在IP范围
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("X-Forwarded-For");
        param1.second("192.168.1.101");
        params.add(param1);
        
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(200, result.first().intValue());
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("X-Forwarded-For");
        param2.second("192.168.2.255");
        params2.add(param2);
        
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(200, result2.first().intValue());
        
        
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("X-Forwarded-For");
        param3.second("192.168.2.101");
        params3.add(param3);
        
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(200, result3.first().intValue());
    }
	
	@Test
    public void test_Condition_StringAndTimeOperator() {
	    String policyName1="Allow_all_username";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test*")));
        conditions1.add(IAMTestUtils.CreateCondition("DateGreaterThan","ctyun:CurrentTime",Arrays.asList("2019-01-01T00:00:00Z")));
        conditions1.add(IAMTestUtils.CreateCondition("DateLessThan","ctyun:CurrentTime",Arrays.asList("2050-01-01T00:00:00Z")));
        conditions1.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","ctyun:Referer",Arrays.asList("http://www.yourwebsitename.com/login.html")));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("*"),"Resource",Arrays.asList("*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName1,200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName;
        
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("Referer");
        param1.second("http://www.yourwebsitename.com/Login.html");
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("Referer");
        param2.second("http://www.yourwebsitename.com/console.html");
        
        
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        params.add(param1);
        
        Pair<Integer,String> result1=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(200, result1.first().intValue());
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user2accessKey, user2secretKey,params);
        assertEquals(200, result2.first().intValue());
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user3accessKey, user3secretKey,params);
        assertEquals(403, result3.first().intValue());
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        params2.add(param2);
        Pair<Integer,String> result4=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result4.first().intValue());
        Pair<Integer,String> result5=IAMTestUtils.invokeHttpsRequest2(body, user2accessKey, user2secretKey,params2);
        assertEquals(403, result5.first().intValue());
        Pair<Integer,String> result6=IAMTestUtils.invokeHttpsRequest2(body, user3accessKey, user3secretKey,params2);
        assertEquals(403, result6.first().intValue());

    }
	
	@Test
    public void test_Condition_StringAndBoolOperator() {
	    String policyName1="Allow_all_username";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test*")));
        conditions1.add(IAMTestUtils.CreateCondition("Bool","ctyun:SecureTransport",Arrays.asList("true")));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("*"),"Resource",Arrays.asList("*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName1,200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName,200);
        IAMInterfaceTestUtils.GetGroup(user2accessKey, user2secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user3accessKey, user3secretKey, groupName,403);
        
        
    }
	
	@Test
    public void test_Condition_StringAndAddessOperator() {
	    String policyName1="StringAndAddessOperator";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","ctyun:Referer",Arrays.asList("http://www.yourwebsitename.com/login.html")));
        conditions1.add(IAMTestUtils.CreateCondition("NotIpAddress","ctyun:SourceIp",Arrays.asList("192.168.1.1/24")));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("*"),"Resource",Arrays.asList("*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1,200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        String body="Action=ListGroups&Version=2010-05-08&GroupName="+groupName;
        
        
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("X-Forwarded-For");
        param1.second("192.168.2.101");
        
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("X-Forwarded-For");
        param2.second("192.168.1.101");
        
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("Referer");
        param3.second("http://www.yourwebsitename.com/Login.html");
        
        Pair<String, String>  param4= new Pair<String, String>();
        param4.first("Referer");
        param4.second("http://www.yourwebsitename.com/register.html");
        
        
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        params.add(param1);
        params.add(param3);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(200, result.first().intValue());
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        params2.add(param1);
        params2.add(param4);
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result2.first().intValue());
        
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        params3.add(param2);
        params3.add(param3);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(403, result3.first().intValue());
        
        List<Pair<String, String>> params4=new ArrayList<Pair<String,String>>();
        params4.add(param2);
        params4.add(param4);
        Pair<Integer,String> result4=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params4);
        assertEquals(403, result4.first().intValue());
        
    }
	
	@Test
    public void test_Condition_TimeAndBoolOperator() {
	    String policyName1="TimeAndBoolOperator";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("DateGreaterThan","ctyun:CurrentTime",Arrays.asList("2019-01-01T00:00:00Z")));
        conditions1.add(IAMTestUtils.CreateCondition("Bool","ctyun:SecureTransport",Arrays.asList("192.168.1.1/24")));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("*"),"Resource",Arrays.asList("*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1,200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403);
        
    }
    
    @Test
    public void test_Condition_TimeAndAddessOperator() {
        String policyName1="StringAndAddessOperator";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("DateGreaterThan","ctyun:CurrentTime",Arrays.asList("2019-01-01T00:00:00Z")));
        conditions1.add(IAMTestUtils.CreateCondition("NotIpAddress","ctyun:SourceIp",Arrays.asList("192.168.1.1/24")));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("*"),"Resource",Arrays.asList("*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1,200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        String body="Action=ListGroups&Version=2010-05-08&GroupName="+groupName;
        
        
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("X-Forwarded-For");
        param1.second("192.168.2.101");
        
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("X-Forwarded-For");
        param2.second("192.168.1.101");
        
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(200, result.first().intValue());
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        params2.add(param2);
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result2.first().intValue());
        
    }
    
    @Test
    public void test_Condition_BoolAndAddessOperator() {
        String policyName1="StringAndAddessOperator";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("Bool","ctyun:SecureTransport",Arrays.asList("false")));
        conditions1.add(IAMTestUtils.CreateCondition("NotIpAddress","ctyun:SourceIp",Arrays.asList("192.168.1.1/24")));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("*"),"Resource",Arrays.asList("*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1,200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        String body="Action=ListGroups&Version=2010-05-08&GroupName="+groupName;
        
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("X-Forwarded-For");
        param1.second("192.168.2.101");
        
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("X-Forwarded-For");
        param2.second("192.168.1.101");
        
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(403, result.first().intValue());
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        params2.add(param2);
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result2.first().intValue());
    }
	
	@Test
    public void test_Condition_composite() {
	    String policyName1="StringAndAddessOperator";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("Bool","ctyun:SecureTransport",Arrays.asList("true")));
        conditions1.add(IAMTestUtils.CreateCondition("NotIpAddress","ctyun:SourceIp",Arrays.asList("192.168.1.1/24")));
        conditions1.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test*")));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("*"),"Resource",Arrays.asList("*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName1,200);
        
        String policyName2="Allow_all";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        String body="Action=ListGroups&Version=2010-05-08&GroupName="+groupName;
        
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("X-Forwarded-For");
        param1.second("192.168.1.101");
        
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("X-Forwarded-For");
        param2.second("192.168.2.101");
        
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        params.add(param2);
        Pair<Integer,String> result1=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(403, result1.first().intValue());
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user2accessKey, user2secretKey,params);
        assertEquals(403, result2.first().intValue());
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user3accessKey, user3secretKey,params);
        assertEquals(200, result3.first().intValue());
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        params2.add(param1);
        Pair<Integer,String> result4=IAMTestUtils.invokeHttpsRequest2(body, user3accessKey, user3secretKey,params2);
        assertEquals(200, result4.first().intValue());

    }
	
	@Test
	public void test_compatibleAWS_UserAgent_StringEquals_Allow() {
	    String policyName="UserAgent_StringEquals_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","aws:UserAgent",Arrays.asList("Java/1.8.0")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        // 携带参数不匹配
        String groupName="testGroup01";
        String body="Action=CreateGroup&Version=2010-05-08&GroupName="+groupName;
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("User-Agent");
        param1.second("Java/1.8.0_91");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(403, result.first().intValue());
        
        // 不携带该参数
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(403, result2.first().intValue());
        
        // 大小写不匹配
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("User-Agent");
        param2.second("java/1.8.0");
        params2.add(param2);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result3.first().intValue());
        
        // 携带参数匹配
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("User-Agent");
        param3.second("Java/1.8.0");
        params3.add(param3);
        Pair<Integer,String> result4=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(200, result4.first().intValue());
    }
	
	@Test
    public void test_compatibleAWS_UserAgent_StringEquals_Deny() {
	    String policyName="UserAgent_StringEquals_Deny_1";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","aws:UserAgent",Arrays.asList("Java/1.8.0_92")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String policyName2="UserAgent_StringEquals_Deny_2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        
        
        // 携带参数匹配
        String groupName="testGroup01";
        
        String body="Action=CreateGroup&Version=2010-05-08&GroupName="+groupName;
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("User-Agent");
        param1.second("Java/1.8.0_92");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(403, result.first().intValue());
        
        // 不携带该参数,但java版本和拒绝的一致
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(403, result2.first().intValue());
        
        // 携带参数匹配
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("User-Agent");
        param2.second("Java/1.8.0_91");
        params2.add(param2);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(200, result3.first().intValue());
    }

    @Test
    public void test_compatibleAWS_Referer_StringEqualsIgnoreCase_Allow() {
        String policyName="Referer_StringEqualsIgnoreCase_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","aws:Referer",Arrays.asList("http://www.yourwebsitename.com/login.html")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName;
        
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("Referer");
        param1.second("http://www.yourwebsitename.com/console.html");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(403, result.first().intValue());
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("Referer");
        param2.second("http://www.yourwebsitename.com/LOGIN.HTML");
        params2.add(param2);
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(200, result2.first().intValue());
        
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("Referer");
        param3.second("http://www.yourwebsitename.com/login.html");
        params3.add(param3);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(200, result3.first().intValue());
    }
    
    @Test
    public void test_compatibleAWS_Referer_StringEqualsIgnoreCase_Deny() {
        String policyName="Referer_StringEqualsIgnoreCase_Deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","aws:Referer",Arrays.asList("http://www.yourwebsitename.com/login.html")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        
        String policyName2="Referer_StringEquals_Deny";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName;
        
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("Referer");
        param1.second("http://www.yourwebsitename.com/login.html");
        params.add(param1);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(403, result.first().intValue());
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("Referer");
        param2.second("http://www.yourwebsitename.com/LOGIN.html");
        params2.add(param2);
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result2.first().intValue());
        
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("Referer");
        param3.second("http://www.yourwebsitename.com/hello.html");
        params3.add(param3);
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(200, result3.first().intValue());
    }
	
	@Test
    public void test_compatibleAWS_userid_StringEquals_Allow() {
	    String policyName="userid_StringEquals_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","aws:userid",Arrays.asList("test1abc")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(user3accessKey, user3secretKey, groupName, 403);
        IAMInterfaceTestUtils.CreateGroup(user2accessKey, user2secretKey, groupName, 403);
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 200);
    }
	
	@Test
    public void test_compatibleAWS_userid_StringEquals_Deny() {
	    String policyName="userid_StringEquals_Deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","aws:userid",Arrays.asList("test1abc")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String policyName2="userid_StringEquals_Deny2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(user1accessKey1, user1secretKey1, groupName, 403); 
        IAMInterfaceTestUtils.CreateGroup(user3accessKey, user3secretKey, groupName, 200);
        IAMInterfaceTestUtils.DeleteGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.CreateGroup(user2accessKey, user2secretKey, groupName, 200);
    }
	
	@Test
    public void test_compatibleAWS_username_StringLike_Allow() {
	    String policyName="username_StringLike_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","aws:username",Arrays.asList("*1*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName,200);
        IAMInterfaceTestUtils.GetGroup(user2accessKey, user2secretKey, groupName, 403);
        IAMInterfaceTestUtils.GetGroup(user3accessKey, user3secretKey, groupName,200);
    }
	
	@Test
    public void test_compatibleAWS_username_StringLike_Deny() {
	    String policyName="username_StringLike_Deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","aws:username",Arrays.asList("*1*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String policyName2="username_StringLike_Deny2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName,403);
        IAMInterfaceTestUtils.GetGroup(user3accessKey, user3secretKey, groupName,403);
        IAMInterfaceTestUtils.GetGroup(user2accessKey, user2secretKey, groupName, 200);
    }
	
	@Test
    public void test_compatibleAWS_CurrentTime_DateEquals_Allow() {
	    String yesterdayString=OneDay0UTCTimeString(-1);
        String todyString=OneDay0UTCTimeString(0);
        
        String policyName="username_CurrentTime_DateEquals_Allow";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("DateEquals","aws:CurrentTime",Arrays.asList(yesterdayString)));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String groupName="testGroup01";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName,403);

        String policyName2="username_CurrentTime_DateEquals_Allow2";
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("DateEquals","ctyun:CurrentTime",Arrays.asList(todyString)));
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions2);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName2, 200);

        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName,200);
        IAMInterfaceTestUtils.ListGroups(user3accessKey, user3secretKey, groupName,200);
    }
	
	@Test
    public void test_compatibleAWS_CurrentTime_DateEquals_Deny() {
	    String policyName="username_CurrentTime_DateEquals_Deny2";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
       
        String yesterdayString=OneDay0UTCTimeString(-1);
        String todyString=OneDay0UTCTimeString(0);
        
        String policyName2="username_CurrentTime_DateEquals_Allow";
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("DateEquals","aws:CurrentTime",Arrays.asList(yesterdayString)));
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions2);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
        
        String groupName="testGroup01";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(user2accessKey, user2secretKey, groupName,200);
        
        String policyName3="username_CurrentTime_DateEquals_Deny";
        List<Condition> conditions3 = new ArrayList<Condition>();
        conditions3.add(IAMTestUtils.CreateCondition("DateEquals","ctyun:CurrentTime",Arrays.asList(todyString)));
        String policyString3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:ListGroups"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions3);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName3, policyString3,200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName3, 200);
       
        IAMInterfaceTestUtils.ListGroups(user1accessKey1, user1secretKey1, groupName,403);
        IAMInterfaceTestUtils.ListGroups(user3accessKey, user3secretKey, groupName,403);
    }
	
	@Test
    public void test_compatibleAWS_SecureTransport_true_Allow() {
	    String policyName="SecureTransport_true_Allow";
        String groupName="testGroup01";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("Bool","aws:SecureTransport",Arrays.asList("true")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // 允许ssl访问 
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
    }
	
	@Test
    public void test_compatibleAWS_SecureTransport_true_Deny() {
	    String groupName="testGroup01";
        
        String policyName="Allow";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 200);
        
        String policyName1="SecureTransport_true_Deny"; 
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("Bool","aws:SecureTransport",Arrays.asList("true")));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        
        IAMInterfaceTestUtils.GetGroup(user1accessKey1, user1secretKey1, groupName, 403);
    }
	
	@Test
    public void test_compatibleAWS_SourceIp_IpAddress_Allow() {
	    String groupName="testGroup01";;
        String userName=user1Name;
        String policyName="allowspecialIP";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("IpAddress","aws:SourceIp",Arrays.asList("192.168.1.1/24","192.168.3.1")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);

        // 在IP范围
        String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName;
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("X-Forwarded-For");
        param1.second("192.168.1.101");
        params.add(param1);
        
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(200, result.first().intValue());
        
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("X-Forwarded-For");
        param2.second("192.168.3.1");
        params2.add(param2);
        
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(200, result2.first().intValue());
        
        // 不在IP范围
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("X-Forwarded-For");
        param3.second("192.168.2.101");
        params3.add(param3);
        
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(403, result3.first().intValue());
    }
	
	@Test
    public void test_compatibleAWS_SourceIp_IpAddress_Deny() {
	    String groupName="testGroup01";;
        String userName=user1Name;
        
        String policyName="Allow";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String policyName1="allowspecialIP";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("IpAddress","aws:SourceIp",Arrays.asList("192.168.1.1/24","192.168.3.1")));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:GetGroup"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName1,200);
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);

        // 在IP范围
        String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName;
        List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("X-Forwarded-For");
        param1.second("192.168.1.101");
        params.add(param1);
        
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params);
        assertEquals(403, result.first().intValue());
        
        
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("X-Forwarded-For");
        param2.second("192.168.3.1");
        params2.add(param2);
        
        Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params2);
        assertEquals(403, result2.first().intValue());
        
        // 不在IP范围
        List<Pair<String, String>> params3=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param3= new Pair<String, String>();
        param3.first("X-Forwarded-For");
        param3.second("192.168.2.101");
        params3.add(param3);
        
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,params3);
        assertEquals(200, result3.first().intValue());
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
	        String errorResource = resource.split("/")[1];
	        errorResource = "*".equals(errorResource) ? "/" : errorResource;
	        assertEquals(errorResource, error.get("Resource"));
        } catch (Exception e) {
            e.printStackTrace();
        }
	    
    }
	
	/*
	 * 生成yyyy-MM-dd'T'HH:mm:ss'Z'格式的字符串
	 * 参数为相对今天的偏移量，0为今天，-1为昨天，1为明天以此类推
	 */
	public static String OneDay0UTCTimeString(int offset) {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        Calendar calendar=Calendar.getInstance();
        calendar.add(Calendar.DATE ,offset);
        calendar.set(Calendar.HOUR_OF_DAY, 0);
        calendar.set(Calendar.MINUTE, 0);
        calendar.set(Calendar.SECOND, 0);
        Date date=calendar.getTime();
        String dayString=dateFormat.format(date);
        System.out.println(dayString);
        return dayString;
    }

}
