package cn.ctyun.oos.iam.test.iamaccesscontrol;

import static org.junit.Assert.*;

import java.io.StringReader;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;

import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xml.sax.InputSource;

import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.Condition;
import cn.ctyun.oos.iam.server.entity.Group;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.metadata.OwnerMeta;
import common.tuple.Pair;

/*
 * User中的IAM权限控制
 * **/

public class UserActionAccessTest {
	public static final String OOS_IAM_DOMAIN="https://oos-xl-iam.ctyunapi.cn:9460/";
	public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
	public static final String regionName="xl";
	
	public static final String ownerName="test01@ctyun.cn";
	public static final String accessKey="65dd530d67f7f88e222f";
	public static final String secretKey="bee6a1d024e999bdf72e04d6a37d85bba789c5d3";
	public static final OwnerMeta owner=new OwnerMeta(ownerName);
	public static final String accountId="0000000gc0uy9";
	
	
	//用于策略添加到用户的测试
	public static String userName1="test01_subUser01";
	public static String userak1="ec722df7c43f7ace0949";
	public static String usersk1="d1fe8d0a300e650c4cae8d19c3564ee17a010fbe";
	
	//用户策略未添加到用户，但是添加到用户所在的组
	public static String userName2="test01_subUser02";
	public static String userak2="76d57c26a4921374853a";
	public static String usersk2="eba5505023a5dcd2692f4eb97dd0d725a10af291";
	
	//未添加任何策略，未加入组
	public static String userName3="test01_subUser03";
	public static String userak3="03de92d4b37f1c8b7fb0";
	public static String usersk3="0cc9f33b72f3b5b7f64cafc16ab88f4cfa2bd50b";
	
	//conditon中不满足条件的userName
	public static String userName21="test02_subUser01";
	public static String userak21="9913b8bf242b158c8375";
	public static String usersk21="1aa7cfb0ea2006c0bd564e520c73e496f1bea0eb";
	
	public static MetaClient metaClient = MetaClient.getGlobalClient();
	public static String groupName="testForuserPolicy";


	@BeforeClass
	public static void setUpBeforeClass() throws Exception {

	}

	@Before
	public void setUp() throws Exception {
		//将用户user2添加到组
		Group group =new Group();
		group.accountId=accountId;
		group.groupName=groupName;
		group=HBaseUtils.get(group);
		if(group==null)
			IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);		
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);	
		User user1 = new User();
		user1.userName="createUserbyUser";
		user1.accountId=accountId;
		user1=HBaseUtils.get(user1);
		if(user1 != null)
			IAMInterfaceTestUtils.DeleteUser(accessKey, secretKey,user1.userName,200);
		User user2 = new User();
		user2.accountId=accountId;
		user2.userName="createbyuser";
		user2=HBaseUtils.get(user2);
		if(user2 !=null)
			IAMInterfaceTestUtils.DeleteUser(accessKey, secretKey,user2.userName,200);
		User user3 = new User();
		user3.accountId=accountId;
		user3.userName="createbyuser02";
		user3=HBaseUtils.get(user3);
		if(user3 !=null)
			IAMInterfaceTestUtils.DeleteUser(accessKey, secretKey,user3.userName,200);
	}
	
	@After
	public void after() throws Exception {
		//将用户从组中移除，并删除组	
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DeleteGroup(accessKey, secretKey, groupName, 200);
		IAMTestUtils.TrancateTable("iam-policy-huxl");

	}
	
	/**
	 * 1个策略1个statement，
	 * effect为allow，Action,actions为允许CreateUser，GetUser，DeleteUser，ListGroupsForUser，设置resourceEffect为允许，无condition
	 * 发送请求与策略匹配，用户可以CreateUser，GetUser，DeleteUser，ListGroupsForUser
	 * **/
	
	@Test
	public void test_createGetDelLIstGroupsForUser_allow_match()throws Exception{
		//创建策略，Action，actions为CreateUser，，GetUser，DeleteUser,Resource,resources=user/*,无condition
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//发送CreateUser请求，因与策略匹配，CreateUser成功
		String userName="createUserbyUser";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(200, result.first().intValue());
		System.out.print(result.second());
		JSONObject resultAssert=ParseXmlToJson("CreateUser",result.second());
		assertEquals(userName,resultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultAssert.get("Arn"));
		assertNotNull(resultAssert.get("UserId"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(200, listresult.first().intValue());
		
		//发送GetUser请求，因与策略匹配，GetUser成功		
		String bodyget="Action=GetUser&Version=2010-05-08";
		Pair<Integer, String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(200, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=ParseXmlToJson("GetUser",resultget.second());
		assertEquals(userName1,resultgetAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName1,resultgetAssert.get("Arn"));
		
		//发送DeleteUser请求，因为策略匹配，Delete User成功
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(200, resultdel.first().intValue());
		System.out.println(resultdel.second());
		
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		//user2有创建用户的权限
		String userName02="CreateUserbyUser02";
		String createUserResult=IAMInterfaceTestUtils.CreateUser(userak2, usersk2, userName02, 200);		
		JSONObject resultcreateAssert=ParseXmlToJson("CreateUser",createUserResult);
		assertEquals(userName02,resultcreateAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName02,resultcreateAssert.get("Arn"));
		assertNotNull(resultcreateAssert.get("UserId"));
		
		String listbody2="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName02);
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest(listbody2, userak2, usersk2);
		assertEquals(200, listresult2.first().intValue());
		
		//user2有获取用户的权限		
		String getuserResult=IAMInterfaceTestUtils.GetUser(userak2, usersk2, userName02,200);
		JSONObject getResultAssert=ParseXmlToJson("GetUser",getuserResult);
		assertEquals(userName02,getResultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName02,getResultAssert.get("Arn"));
		
		//user2有删除用户的权限
		String deluserResult=IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 200);
		System.out.println(deluserResult);

		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);

	}
	
	/**
	 * 1个策略1个statement，
	 * effect为allow，Action,actions为允许CreateUser，GetUser，DeleteUser，ListGroupsForUser，设置resourceEffect为允许，无condition
	 * 发送请求与策略匹配，用户可以CreateUser，GetUser，DeleteUser，ListGroupsForUser
	 * resource=user/userName
	 * **/
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_userName()throws Exception{
		String userName="createUserbyUser";
		String userName02="CreateUserbyUser02";
		//创建策略，Action，actions为CreateUser，，GetUser，DeleteUser,Resource,resources=user/userName,无condition
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/"+ userName,"arn:ctyun:iam::0000000gc0uy9:user/"+ userName1,"arn:ctyun:iam::0000000gc0uy9:user/"+ userName02),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//发送CreateUser请求，因与策略匹配，CreateUser成功
		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(200, result.first().intValue());
		System.out.print(result.second());
		JSONObject resultAssert=ParseXmlToJson("CreateUser",result.second());
		assertEquals(userName,resultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultAssert.get("Arn"));
		assertNotNull(resultAssert.get("UserId"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(200, listresult.first().intValue());
		
		//发送GetUser请求，因与策略匹配，GetUser成功		
		String bodyget="Action=GetUser&Version=2010-05-08";
		Pair<Integer, String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(200, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=ParseXmlToJson("GetUser",resultget.second());
		assertEquals(userName1,resultgetAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName1,resultgetAssert.get("Arn"));
		
		//发送DeleteUser请求，因为策略匹配，Delete User成功
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(200, resultdel.first().intValue());
		System.out.println(resultdel.second());

		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		//user2有创建用户的权限
		String createUserResult=IAMInterfaceTestUtils.CreateUser(userak2, usersk2, userName02, 200);		
		JSONObject resultcreateAssert=ParseXmlToJson("CreateUser",createUserResult);
		assertEquals(userName02,resultcreateAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName02,resultcreateAssert.get("Arn"));
		assertNotNull(resultcreateAssert.get("UserId"));
		
		String listbody2="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName02);
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest(listbody2, userak2, usersk2);
		assertEquals(200, listresult2.first().intValue());
		
		//user2有获取用户的权限		
		String getuserResult=IAMInterfaceTestUtils.GetUser(userak2, usersk2, userName02,200);
		JSONObject getResultAssert=ParseXmlToJson("GetUser",getuserResult);
		assertEquals(userName02,getResultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName02,getResultAssert.get("Arn"));
		
		//user2有删除用户的权限
		String deluserResult=IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 200);
		System.out.println(deluserResult);
		
		
		//除actions列表中的actions外，其他action可访问成功
		
		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}
	
	/**
	 * 1个策略1个statement，
	 * effect为allow，Action,actions为允许CreateUser，GetUser，DeleteUser，ListGroupsForUser，设置resourceEffect为允许，无condition
	 * 发送请求与策略匹配，用户可以CreateUser，GetUser，DeleteUser，ListGroupsForUser
	 * resource=user/userName，不满足userName的资源
	 * **/
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_userName2()throws Exception{
		String userName="createUserbyUser";
		String userName02="CreateUserbyUser02";
		//创建策略，Action，actions为CreateUser，，GetUser，DeleteUser,Resource,resources=user/userName,无condition
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/"+ userName3),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//发送CreateUser请求，因与策略匹配，不满足资源，CreateUser失败
		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(403, result.first().intValue());
		System.out.print(result.second());
		JSONObject resultAssert=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("AccessDenied",resultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultAssert.get("Message"));
				
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(403, listresult.first().intValue());
		
		//发送GetUser请求，因与策略匹配，GetUser失败		
		String bodyget="Action=GetUser&Version=2010-05-08";
		Pair<Integer, String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(403, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=IAMTestUtils.ParseErrorToJson(resultget.second());
		assertEquals("AccessDenied",resultgetAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+".",resultgetAssert.get("Message"));
			
		//发送DeleteUser请求，因为策略匹配，Delete User失败
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(403, resultdel.first().intValue());
		System.out.println(resultdel.second());
		JSONObject resultdelAssert=IAMTestUtils.ParseErrorToJson(resultdel.second());
		assertEquals("AccessDenied",resultdelAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultdelAssert.get("Message"));
		
		//添加策略到组
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		//用户匹配策略，创建用户失败
		String createResult=IAMInterfaceTestUtils.CreateUser(userak2, usersk2, userName02, 403);
		JSONObject createResultAssert=IAMTestUtils.ParseErrorToJson(createResult);
		assertEquals("AccessDenied",createResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",createResultAssert.get("Message"));
		
		String listbody2="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName02);
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest(listbody2, userak2, usersk2);
		assertEquals(403, listresult2.first().intValue());
		
		//用户匹配策略，获取用户失败
		String getResult=IAMInterfaceTestUtils.GetUser(userak2, usersk2, userName02,403);
		JSONObject getResultAssert=IAMTestUtils.ParseErrorToJson(getResult);
		assertEquals("AccessDenied",getResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",getResultAssert.get("Message"));
		
		//删除用户失败
		String delResult=IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 403);
		JSONObject delResultAssert=IAMTestUtils.ParseErrorToJson(delResult);
		assertEquals("AccessDenied",delResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",delResultAssert.get("Message"));
		
		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}	
	
	/**
	 * 1个策略1个statement，
	 * effect为allow，Action,actions为允许CreateUser，GetUser，DeleteUser，ListGroupsForUser，设置resourceEffect为允许，无condition
	 * 发送请求与策略匹配，用户可以CreateUser，GetUser，DeleteUser，ListGroupsForUser
	 * resource=*
	 * **/
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_all()throws Exception{
		String userName="createUserbyUser";
		String userName02="CreateUserbyUser02";
		//创建策略，Action，actions为CreateUser，，GetUser，DeleteUser,Resource,resources=*,无condition
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//发送CreateUser请求，因与策略匹配，CreateUser成功
		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(200, result.first().intValue());
		System.out.print(result.second());
		JSONObject resultAssert=ParseXmlToJson("CreateUser",result.second());
		assertEquals(userName,resultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultAssert.get("Arn"));
		assertNotNull(resultAssert.get("UserId"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(200, listresult.first().intValue());
		
		//发送GetUser请求，因与策略匹配，GetUser成功		
		String bodyget="Action=GetUser&Version=2010-05-08";
		Pair<Integer, String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(200, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=ParseXmlToJson("GetUser",resultget.second());
		assertEquals(userName1,resultgetAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName1,resultgetAssert.get("Arn"));
		
		//发送DeleteUser请求，因为策略匹配，Delete User成功
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(200, resultdel.first().intValue());
		System.out.println(resultdel.second());

		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		//user2有创建用户的权限
		String createUserResult=IAMInterfaceTestUtils.CreateUser(userak2, usersk2, userName02, 200);		
		JSONObject resultcreateAssert=ParseXmlToJson("CreateUser",createUserResult);
		assertEquals(userName02,resultcreateAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName02,resultcreateAssert.get("Arn"));
		assertNotNull(resultcreateAssert.get("UserId"));
		
		String listbody2="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName02);
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest(listbody2, userak2, usersk2);
		assertEquals(200, listresult2.first().intValue());
		
		//user2有获取用户的权限		
		String getuserResult=IAMInterfaceTestUtils.GetUser(userak2, usersk2, userName02,200);
		JSONObject getResultAssert=ParseXmlToJson("GetUser",getuserResult);
		assertEquals(userName02,getResultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName02,getResultAssert.get("Arn"));
		
		//user2有删除用户的权限
		String deluserResult=IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 200);
		System.out.println(deluserResult);

		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}	
	
	/**
	 * 1个策略1个statement，
	 * effect为allow，NotAction,actions为允许CreateUser,GetUser，DeleteUser，设置resourceEffect为允许，无condition
	 * 发送的请求与策略匹配，策略为NotAction，CreateGroup，DeleteGroup,用户CreateGroup，DeleteGroup失败,其他action会成功，所以发送CreateUser，GetUser，DeleteUser，ListGroupsForUser，成功
	 * **/
	
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_notAction()throws Exception{
		String userName="createUserbyUser";
		String userName02="CreateUserbyUser02";
		//创建策略，NotAction，actions为CreateGroup，DeleteGroup,resource,resources为user/*,无condition
		String policyName="createPolicyFormatchNotAction";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:CreateGroup","iam:DeleteGroup"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//发送CreateUser请求，因与策略匹配，CreateUser成功		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(200, result.first().intValue());
		System.out.print(result.second());
		JSONObject resultAssert=ParseXmlToJson("CreateUser",result.second());
		assertEquals(userName,resultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultAssert.get("Arn"));
		assertNotNull(resultAssert.get("UserId"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(200, listresult.first().intValue());
		
		//发送GetUser请求，因与策略匹配，GetUser成功		
		String bodyget="Action=GetUser&Version=2010-05-08";
		Pair<Integer, String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(200, resultget.first().intValue());
		System.out.print(resultget.second());
		JSONObject resultgetAssert=ParseXmlToJson("GetUser",resultget.second());
		assertEquals(userName1,resultgetAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName1,resultgetAssert.get("Arn"));
		
		//发送DeleteUser请求，因为策略匹配，Delete User成功
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(200, resultdel.first().intValue());
		System.out.print(resultdel.second());
			
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		//user2有创建用户的权限
		String createUserResult=IAMInterfaceTestUtils.CreateUser(userak2, usersk2, userName02, 200);		
		JSONObject resultcreateAssert=ParseXmlToJson("CreateUser",createUserResult);
		assertEquals(userName02,resultcreateAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName02,resultcreateAssert.get("Arn"));
		assertNotNull(resultcreateAssert.get("UserId"));
		
		String listbody2="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName02);
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest(listbody2, userak2, usersk2);
		assertEquals(200, listresult2.first().intValue());
		
		//user2有获取用户的权限		
		String getuserResult=IAMInterfaceTestUtils.GetUser(userak2, usersk2, userName02,200);
		JSONObject getResultAssert=ParseXmlToJson("GetUser",getuserResult);
		assertEquals(userName02,getResultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName02,getResultAssert.get("Arn"));
		
		//user2有删除用户的权限
		String deluserResult=IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 200);
		System.out.println(deluserResult);

		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}
	
	/**
	 * 1个策略1个statement，
	 * effect为allow，NotAction,actions为允许CreateUser,GetUser，DeleteUser，设置resourceEffect为允许，无condition
	 * 发送的请求与策略匹配，策略为NotAction，CreateGroup，DeleteGroup,用户CreateGroup，DeleteGroup失败,其他action会成功，所以发送CreateUser，GetUser，DeleteUser，ListGroupsForUser，成功
	 * resource=user/userName
	 * **/
	
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_notAction_userName()throws Exception{
		String userName="createUserbyUser";
		String userName02="CreateUserbyUser02";
		//创建策略，NotAction，actions为CreateGroup，DeleteGroup,resource,resources为user/userName,无condition
		String policyName="createPolicyFormatchNotAction";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:CreateGroup","iam:DeleteGroup"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/"+ userName,"arn:ctyun:iam::0000000gc0uy9:user/"+ userName1,"arn:ctyun:iam::0000000gc0uy9:user/"+ userName02),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//发送CreateUser请求，因与策略匹配，CreateUser成功		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(200, result.first().intValue());
		System.out.print(result.second());
		JSONObject resultAssert=ParseXmlToJson("CreateUser",result.second());
		assertEquals(userName,resultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultAssert.get("Arn"));
		assertNotNull(resultAssert.get("UserId"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(200, listresult.first().intValue());
		
		//发送GetUser请求，因与策略匹配，GetUser成功		
		String bodyget="Action=GetUser&Version=2010-05-08";
		Pair<Integer, String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(200, resultget.first().intValue());
		System.out.print(resultget.second());
		JSONObject resultgetAssert=ParseXmlToJson("GetUser",resultget.second());
		assertEquals(userName1,resultgetAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName1,resultgetAssert.get("Arn"));
		
		//发送DeleteUser请求，因为策略匹配，Delete User成功
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(200, resultdel.first().intValue());
		System.out.print(resultdel.second());
			
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		//user2有创建用户的权限
		String createUserResult=IAMInterfaceTestUtils.CreateUser(userak2, usersk2, userName02, 200);		
		JSONObject resultcreateAssert=ParseXmlToJson("CreateUser",createUserResult);
		assertEquals(userName02,resultcreateAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName02,resultcreateAssert.get("Arn"));
		assertNotNull(resultcreateAssert.get("UserId"));
		
		String listbody2="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName02);
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest(listbody2, userak2, usersk2);
		assertEquals(200, listresult2.first().intValue());
		
		//user2有获取用户的权限		
		String getuserResult=IAMInterfaceTestUtils.GetUser(userak2, usersk2, userName02,200);
		JSONObject getResultAssert=ParseXmlToJson("GetUser",getuserResult);
		assertEquals(userName02,getResultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName02,getResultAssert.get("Arn"));
		
		//user2有删除用户的权限
		String deluserResult=IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 200);
		System.out.println(deluserResult);

		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}
	
	/**
	 * 1个策略1个statement，
	 * effect为allow，NotAction,actions为允许CreateUser,GetUser，DeleteUser，设置resourceEffect为允许，无condition
	 * 发送的请求与策略匹配，策略为NotAction，CreateGroup，DeleteGroup,用户CreateGroup，DeleteGroup失败,其他action会成功，所以发送CreateUser，GetUser，DeleteUser，ListGroupsForUser，成功
	 * resource=user/userName，不满足userName资源
	 * **/
	
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_notAction_userName2()throws Exception{
		String userName="createUserbyUser";
		String userName02="CreateUserbyUser02";
		//创建策略，NotAction，actions为CreateGroup，DeleteGroup,resource,resources为user/userName,无condition
		String policyName="createPolicyFormatchNotAction";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:CreateGroup","iam:DeleteGroup"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/"+ userName3),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		
		//发送CreateUser请求，因与策略匹配，不满足资源，CreateUser失败
		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(403, result.first().intValue());
		System.out.print(result.second());
		JSONObject resultAssert=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("AccessDenied",resultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultAssert.get("Message"));
				
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(403, listresult.first().intValue());
		
		//发送GetUser请求，因与策略匹配，GetUser失败		
		String bodyget="Action=GetUser&Version=2010-05-08";
		Pair<Integer, String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(403, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=IAMTestUtils.ParseErrorToJson(resultget.second());
		assertEquals("AccessDenied",resultgetAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+".",resultgetAssert.get("Message"));
			
		//发送DeleteUser请求，因为策略匹配，Delete User失败
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(403, resultdel.first().intValue());
		System.out.println(resultdel.second());
		JSONObject resultdelAssert=IAMTestUtils.ParseErrorToJson(resultdel.second());
		assertEquals("AccessDenied",resultdelAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultdelAssert.get("Message"));
		
		//添加策略到组
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		//用户匹配策略，创建用户失败
		String createResult=IAMInterfaceTestUtils.CreateUser(userak2, usersk2, userName02, 403);
		JSONObject createResultAssert=IAMTestUtils.ParseErrorToJson(createResult);
		assertEquals("AccessDenied",createResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",createResultAssert.get("Message"));
		
		String listbody2="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName02);
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest(listbody2, userak2, usersk2);
		assertEquals(403, listresult2.first().intValue());
		
		//用户匹配策略，获取用户失败
		String getResult=IAMInterfaceTestUtils.GetUser(userak2, usersk2, userName02,403);
		JSONObject getResultAssert=IAMTestUtils.ParseErrorToJson(getResult);
		assertEquals("AccessDenied",getResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",getResultAssert.get("Message"));
		
		//删除用户失败
		String delResult=IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 403);
		JSONObject delResultAssert=IAMTestUtils.ParseErrorToJson(delResult);
		assertEquals("AccessDenied",delResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",delResultAssert.get("Message"));
		
		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}	
	
	/**
	 * 1个策略1个statement，
	 * effect为allow，NotAction,actions为允许CreateUser,GetUser，DeleteUser，设置resourceEffect为允许，无condition
	 * 发送的请求与策略匹配，策略为NotAction，CreateGroup，DeleteGroup,用户CreateGroup，DeleteGroup失败,其他action会成功，所以发送CreateUser，GetUser，DeleteUser，ListGroupsForUser，成功
	 * resource=*
	 * **/
	
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_notAction_all()throws Exception{
		String userName="createUserbyUser";
		String userName02="CreateUserbyUser02";
		//创建策略，NotAction，actions为CreateGroup，DeleteGroup,resource,resources为user/userName,无condition
		String policyName="createPolicyFormatchNotAction";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:CreateGroup","iam:DeleteGroup"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//发送CreateUser请求，因与策略匹配，CreateUser成功		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(200, result.first().intValue());
		System.out.print(result.second());
		JSONObject resultAssert=ParseXmlToJson("CreateUser",result.second());
		assertEquals(userName,resultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultAssert.get("Arn"));
		assertNotNull(resultAssert.get("UserId"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(200, listresult.first().intValue());
		
		//发送GetUser请求，因与策略匹配，GetUser成功		
		String bodyget="Action=GetUser&Version=2010-05-08";
		Pair<Integer, String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(200, resultget.first().intValue());
		System.out.print(resultget.second());
		JSONObject resultgetAssert=ParseXmlToJson("GetUser",resultget.second());
		assertEquals(userName1,resultgetAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName1,resultgetAssert.get("Arn"));
		
		//发送DeleteUser请求，因为策略匹配，Delete User成功
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(200, resultdel.first().intValue());
		System.out.print(resultdel.second());
			
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		//user2有创建用户的权限
		String createUserResult=IAMInterfaceTestUtils.CreateUser(userak2, usersk2, userName02, 200);		
		JSONObject resultcreateAssert=ParseXmlToJson("CreateUser",createUserResult);
		assertEquals(userName02,resultcreateAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName02,resultcreateAssert.get("Arn"));
		assertNotNull(resultcreateAssert.get("UserId"));
		
		String listbody2="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName02);
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest(listbody2, userak2, usersk2);
		assertEquals(200, listresult2.first().intValue());
		
		//user2有获取用户的权限		
		String getuserResult=IAMInterfaceTestUtils.GetUser(userak2, usersk2, userName02,200);
		JSONObject getResultAssert=ParseXmlToJson("GetUser",getuserResult);
		assertEquals(userName02,getResultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName02,getResultAssert.get("Arn"));
		
		//user2有删除用户的权限
		String deluserResult=IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 200);
		System.out.println(deluserResult);

		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}	
		
	/**
	 * 1个策略1个statement，
	 * effect为allow，NotAction,actions为允许CreateUser,GetUser，DeleteUser，设置resourceEffect为允许，无condition
	 * 发送的请求与策略匹配，策略为NotAction，CrateUser，GetUser，DeleteUser,用户CreateUser，GetUser，DeleteUser，ListGroupsForUser失败
	 * **/
	
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_notAction2()throws Exception{
		String userName="createUserbyUser";
		String userName02="CreateUserbyUser02";
		//创建策略，NotAction，actions为CreateUser，GetUser，DeleteUser，ListGroupsForUser,resource,resources为user/*,无condition
		String policyName="createPolicyFormatchNotAction";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//发送CreateUser请求，因与策略匹配NotAction，CreateUser失败
		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(403, result.first().intValue());
		System.out.print(result.second());
		JSONObject resultAssert=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("AccessDenied",resultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultAssert.get("Message"));
				
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(403, listresult.first().intValue());
		
		//发送GetUser请求，因与策略匹配，GetUser失败		
		String bodyget="Action=GetUser&Version=2010-05-08";
		Pair<Integer, String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(403, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=IAMTestUtils.ParseErrorToJson(resultget.second());
		assertEquals("AccessDenied",resultgetAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+".",resultgetAssert.get("Message"));
			
		//发送DeleteUser请求，因为策略匹配，Delete User失败
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(403, resultdel.first().intValue());
		System.out.println(resultdel.second());
		JSONObject resultdelAssert=IAMTestUtils.ParseErrorToJson(resultdel.second());
		assertEquals("AccessDenied",resultdelAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultdelAssert.get("Message"));
		
		//添加策略到组
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		//用户匹配策略，创建用户失败
		String createResult=IAMInterfaceTestUtils.CreateUser(userak2, usersk2, userName02, 403);
		JSONObject createResultAssert=IAMTestUtils.ParseErrorToJson(createResult);
		assertEquals("AccessDenied",createResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",createResultAssert.get("Message"));
		
		String listbody2="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName02);
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest(listbody2, userak2, usersk2);
		assertEquals(403, listresult2.first().intValue());
		
		//用户匹配策略，获取用户失败
		String getResult=IAMInterfaceTestUtils.GetUser(userak2, usersk2, userName02,403);
		JSONObject getResultAssert=IAMTestUtils.ParseErrorToJson(getResult);
		assertEquals("AccessDenied",getResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",getResultAssert.get("Message"));
		
		//删除用户失败
		String delResult=IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 403);
		JSONObject delResultAssert=IAMTestUtils.ParseErrorToJson(delResult);
		assertEquals("AccessDenied",delResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",delResultAssert.get("Message"));
		
		//resource为user/*的其他actions可以访问成功
		
		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}
	
	/**
	 * 1个策略1个statement，
	 * effect为allow，Action,actions为允许CreateUser,GetUser，DeleteUser，设置resourceEffect为NotResource，无condition
	 * 发送的请求与策略匹配，策略为NotResource，resource为不匹配的资源,用户CreateUser，GetUser，DeleteUser，ListGroupsForUser成功
	 * **/	
	
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_notResource()throws Exception{
		String userName="createUserbyUser";
		String userName02="CreateUserbyUser02";
		//创建策略，Action，actions为CreateUser，Notresource,resources为不匹配的资源（匹配的资源为：user/*,无condition
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:group/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//发送CreateUser请求，因与策略匹配，CreateUser成功
		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(200, result.first().intValue());
		System.out.print(result.second());
		JSONObject resultAssert=ParseXmlToJson("CreateUser",result.second());
		assertEquals(userName,resultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultAssert.get("Arn"));
		assertNotNull(resultAssert.get("UserId"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(200, listresult.first().intValue());
		
		//发送GetUser请求，因与策略匹配，GetUser成功		
		String bodyget="Action=GetUser&Version=2010-05-08";
		Pair<Integer, String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(200, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=ParseXmlToJson("GetUser",resultget.second());
		assertEquals(userName1,resultgetAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName1,resultgetAssert.get("Arn"));
		assertNotNull(resultgetAssert.get("UserId"));
		
		//发送DeleteUser请求，因为策略匹配，Delete User成功
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(200, resultdel.first().intValue());
		System.out.println(resultdel.second());
		
		//添加策略到组
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		//user2有创建用户的权限
		String createUserResult=IAMInterfaceTestUtils.CreateUser(userak2, usersk2, userName02, 200);		
		JSONObject resultcreateAssert=ParseXmlToJson("CreateUser",createUserResult);
		assertEquals(userName02,resultcreateAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName02,resultcreateAssert.get("Arn"));
		assertNotNull(resultcreateAssert.get("UserId"));
		
		String listbody2="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName02);
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest(listbody2, userak2, usersk2);
		assertEquals(200, listresult2.first().intValue());
		
		//user2有获取用户的权限		
		String getuserResult=IAMInterfaceTestUtils.GetUser(userak2, usersk2, userName02,200);
		JSONObject getResultAssert=ParseXmlToJson("GetUser",getuserResult);
		assertEquals(userName02,getResultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName02,getResultAssert.get("Arn"));
		
		//user2有删除用户的权限
		String deluserResult=IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 200);
		System.out.println(deluserResult);
		
		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
				
	
	}
	/**
	 * 1个策略1个statement，
	 * effect为allow，Action,actions为允许CreateUser,GetUser，DeleteUser，设置resourceEffect为NotResource，无condition
	 * 发送的请求与策略匹配，策略为NotResource，resource=user/userName3(创建用户的user为userName和userName02),用户CreateUser，GetUser，DeleteUser，ListGroupsForUser成功
	 * 
	 * **/	
	
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_notResource_userName()throws Exception{
		String userName="createUserbyUser";
		String userName02="CreateUserbyUser02";
		//创建策略，Action，actions为CreateUser，Notresource,resources为不匹配的资源（匹配的资源为：user/*,无condition
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/"+userName3),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//发送CreateUser请求，因与策略匹配，CreateUser成功
		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(200, result.first().intValue());
		System.out.print(result.second());
		JSONObject resultAssert=ParseXmlToJson("CreateUser",result.second());
		assertEquals(userName,resultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultAssert.get("Arn"));
		assertNotNull(resultAssert.get("UserId"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(200, listresult.first().intValue());
		
		//发送GetUser请求，因与策略匹配，GetUser成功		
		String bodyget="Action=GetUser&Version=2010-05-08";
		Pair<Integer, String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(200, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=ParseXmlToJson("GetUser",resultget.second());
		assertEquals(userName1,resultgetAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName1,resultgetAssert.get("Arn"));
		assertNotNull(resultgetAssert.get("UserId"));
		
		//发送DeleteUser请求，因为策略匹配，Delete User成功
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(200, resultdel.first().intValue());
		System.out.println(resultdel.second());
		
		//添加策略到组
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		//user2有创建用户的权限
		String createUserResult=IAMInterfaceTestUtils.CreateUser(userak2, usersk2, userName02, 200);		
		JSONObject resultcreateAssert=ParseXmlToJson("CreateUser",createUserResult);
		assertEquals(userName02,resultcreateAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName02,resultcreateAssert.get("Arn"));
		assertNotNull(resultcreateAssert.get("UserId"));
		
		String listbody2="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName02);
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest(listbody2, userak2, usersk2);
		assertEquals(200, listresult2.first().intValue());
		
		//user2有获取用户的权限		
		String getuserResult=IAMInterfaceTestUtils.GetUser(userak2, usersk2, userName02,200);
		JSONObject getResultAssert=ParseXmlToJson("GetUser",getuserResult);
		assertEquals(userName02,getResultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName02,getResultAssert.get("Arn"));
		
		//user2有删除用户的权限
		String deluserResult=IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 200);
		System.out.println(deluserResult);
		
		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
				
	
	}
	
	/**
	 * 1个策略1个statement，
	 * effect为allow，Action,actions为允许CreateUser,GetUser，DeleteUser，设置resourceEffect为NotResource，Resource资源正确，无condition
	 * 发送的请求与策略匹配，策略为NotResource，resource为匹配的资源,用户CreateUser，GetUser，DeleteUser，ListGroupsForUser失败
	 * **/
	
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_notResource2()throws Exception{
		String userName="createUserbyUser";
		String userName02="CreateUserbyUser02";
		//创建策略，Action，actions为CreateUser，GetUser，DeleteUser，ListGroupsForUser,NotResource,resources为user/*,无condition
		String policyName="createPolicyFormatchNotResource";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//发送CreateUser请求，因与策略匹配NotAction，CreateUser失败
		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(403, result.first().intValue());
		System.out.print(result.second());
		JSONObject resultAssert=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("AccessDenied",resultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultAssert.get("Message"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(403, listresult.first().intValue());
		
		//发送GetUser请求，因与策略匹配，GetUser失败		
		String bodyget="Action=GetUser&Version=2010-05-08";
		Pair<Integer, String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(403, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=IAMTestUtils.ParseErrorToJson(resultget.second());
		assertEquals("AccessDenied",resultgetAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+".",resultgetAssert.get("Message"));
		
		//发送DeleteUser请求，因为策略匹配，Delete User失败
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(403, resultdel.first().intValue());
		System.out.println(resultdel.second());
		JSONObject resultdelAssert=IAMTestUtils.ParseErrorToJson(resultdel.second());
		assertEquals("AccessDenied",resultdelAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultdelAssert.get("Message"));
		
		//添加策略到组
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		//用户匹配策略，创建用户失败
		String createResult=IAMInterfaceTestUtils.CreateUser(userak2, usersk2, userName02, 403);
		JSONObject createResultAssert=IAMTestUtils.ParseErrorToJson(createResult);
		assertEquals("AccessDenied",createResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",createResultAssert.get("Message"));
		
		String listbody2="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName02);
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest(listbody2, userak2, usersk2);
		assertEquals(403, listresult2.first().intValue());
		
		//用户匹配策略，获取用户失败
		String getResult=IAMInterfaceTestUtils.GetUser(userak2, usersk2, userName02,403);
		JSONObject getResultAssert=IAMTestUtils.ParseErrorToJson(getResult);
		assertEquals("AccessDenied",getResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",getResultAssert.get("Message"));
		
		//删除用户失败
		String delResult=IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 403);
		JSONObject delResultAssert=IAMTestUtils.ParseErrorToJson(delResult);
		assertEquals("AccessDenied",delResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",delResultAssert.get("Message"));
		
		//resource为user/*的其他actions可以访问成功
		
		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}

	/**
	 * 1个策略1个statement，
	 * effect为allow，Action,actions为允许CreateUser,GetUser，DeleteUser，设置resourceEffect为NotResource，Resource资源正确，无condition
	 * 发送的请求与策略匹配，策略为NotResource，resource为匹配的资源,用户CreateUser，GetUser，DeleteUser，ListGroupsForUser失败
	 * resource=user/userName**/
	
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_notResource2_userName()throws Exception{
		String userName="createUserbyUser";
		String userName02="CreateUserbyUser02";
		//创建策略，Action，actions为CreateUser，GetUser，DeleteUser，ListGroupsForUser,NotResource,resources为user/userName,无condition
		String policyName="createPolicyFormatchNotResource";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/"+ userName,"arn:ctyun:iam::0000000gc0uy9:user/"+ userName1,"arn:ctyun:iam::0000000gc0uy9:user/"+ userName02),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//发送CreateUser请求，因与策略匹配NotAction，CreateUser失败
		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(403, result.first().intValue());
		System.out.print(result.second());
		JSONObject resultAssert=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("AccessDenied",resultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultAssert.get("Message"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(403, listresult.first().intValue());
		
		//发送GetUser请求，因与策略匹配，GetUser失败		
		String bodyget="Action=GetUser&Version=2010-05-08";
		Pair<Integer, String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(403, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=IAMTestUtils.ParseErrorToJson(resultget.second());
		assertEquals("AccessDenied",resultgetAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+".",resultgetAssert.get("Message"));
		
		//发送DeleteUser请求，因为策略匹配，Delete User失败
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(403, resultdel.first().intValue());
		System.out.println(resultdel.second());
		JSONObject resultdelAssert=IAMTestUtils.ParseErrorToJson(resultdel.second());
		assertEquals("AccessDenied",resultdelAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultdelAssert.get("Message"));
		
		//添加策略到组
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		//用户匹配策略，创建用户失败
		String createResult=IAMInterfaceTestUtils.CreateUser(userak2, usersk2, userName02, 403);
		JSONObject createResultAssert=IAMTestUtils.ParseErrorToJson(createResult);
		assertEquals("AccessDenied",createResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",createResultAssert.get("Message"));
		
		String listbody2="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName02);
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest(listbody2, userak2, usersk2);
		assertEquals(403, listresult2.first().intValue());
		
		//用户匹配策略，获取用户失败
		String getResult=IAMInterfaceTestUtils.GetUser(userak2, usersk2, userName02,403);
		JSONObject getResultAssert=IAMTestUtils.ParseErrorToJson(getResult);
		assertEquals("AccessDenied",getResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",getResultAssert.get("Message"));
		
		//删除用户失败
		String delResult=IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 403);
		JSONObject delResultAssert=IAMTestUtils.ParseErrorToJson(delResult);
		assertEquals("AccessDenied",delResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",delResultAssert.get("Message"));
		
		//resource为user/*的其他actions可以访问成功
		
		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}
	
	/**
	 * 1个策略1个statement，
	 * effect为allow，Action,actions为允许CreateUser,GetUser，DeleteUser，设置resourceEffect为NotResource，Resource资源正确，无condition
	 * 发送的请求与策略匹配，策略为NotResource，resource为匹配的资源,用户CreateUser，GetUser，DeleteUser，ListGroupsForUser失败
	 * resource=user/userName**/
	
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_notResource2_all()throws Exception{
		String userName="createUserbyUser";
		String userName02="CreateUserbyUser02";
		//创建策略，Action，actions为CreateUser，GetUser，DeleteUser，ListGroupsForUser,NotResource,resources为*,无condition
		String policyName="createPolicyFormatchNotResource";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//发送CreateUser请求，因与策略匹配NotAction，CreateUser失败
		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(403, result.first().intValue());
		System.out.print(result.second());
		JSONObject resultAssert=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("AccessDenied",resultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultAssert.get("Message"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(403, listresult.first().intValue());
		
		//发送GetUser请求，因与策略匹配，GetUser失败		
		String bodyget="Action=GetUser&Version=2010-05-08";
		Pair<Integer, String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(403, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=IAMTestUtils.ParseErrorToJson(resultget.second());
		assertEquals("AccessDenied",resultgetAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+".",resultgetAssert.get("Message"));
		
		//发送DeleteUser请求，因为策略匹配，Delete User失败
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(403, resultdel.first().intValue());
		System.out.println(resultdel.second());
		JSONObject resultdelAssert=IAMTestUtils.ParseErrorToJson(resultdel.second());
		assertEquals("AccessDenied",resultdelAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultdelAssert.get("Message"));
		
		//添加策略到组
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		//用户匹配策略，创建用户失败
		String createResult=IAMInterfaceTestUtils.CreateUser(userak2, usersk2, userName02, 403);
		JSONObject createResultAssert=IAMTestUtils.ParseErrorToJson(createResult);
		assertEquals("AccessDenied",createResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",createResultAssert.get("Message"));
		
		String listbody2="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName02);
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest(listbody2, userak2, usersk2);
		assertEquals(403, listresult2.first().intValue());
		
		//用户匹配策略，获取用户失败
		String getResult=IAMInterfaceTestUtils.GetUser(userak2, usersk2, userName02,403);
		JSONObject getResultAssert=IAMTestUtils.ParseErrorToJson(getResult);
		assertEquals("AccessDenied",getResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",getResultAssert.get("Message"));
		
		//删除用户失败
		String delResult=IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 403);
		JSONObject delResultAssert=IAMTestUtils.ParseErrorToJson(delResult);
		assertEquals("AccessDenied",delResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",delResultAssert.get("Message"));
		
		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}	
	
	
	/**
	 * 1个策略1个statement，
	 * effect为allow，NotAction,actions为CreateUser，GetUser，DeleteUser，ListGroupsForUser，设置resourceEffect为NotResource，无condition
	 * 发送请求与策略匹配，用户可以CreateUser，GetUser，DeleteUser，ListGroupsForUser
	 * **/
	
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_notActionNotResource()throws Exception{
		String userName="createUserbyUser";
		String userName02="createUserbyUser02";
		//创建策略，NotAction，actions为CreateGroup，DeleteGroup,NotResource,Reource无condition
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:CreateGroup","iam:DeleteGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:group/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//发送CreateUser请求，因与策略匹配，CreateUser成功
		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(200, result.first().intValue());
		System.out.print(result.second());
		JSONObject resultAssert=ParseXmlToJson("CreateUser",result.second());
		assertEquals(userName,resultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultAssert.get("Arn"));
		assertNotNull(resultAssert.get("UserId"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(200, listresult.first().intValue());
		
		
		//发送GetUser请求，因与策略匹配，GetUser成功		
		String bodyget="Action=GetUser&Version=2010-05-08";
		Pair<Integer, String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(200, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=ParseXmlToJson("GetUser",resultget.second());
		assertEquals(userName1,resultgetAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName1,resultgetAssert.get("Arn"));
		
		//发送DeleteUser请求，因为策略匹配，Delete User成功
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(200, resultdel.first().intValue());
		System.out.println(resultdel.second());
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		//user2有创建用户的权限
		String createUserResult=IAMInterfaceTestUtils.CreateUser(userak2, usersk2, userName02, 200);		
		JSONObject resultcreateAssert=ParseXmlToJson("CreateUser",createUserResult);
		assertEquals(userName02,resultcreateAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName02,resultcreateAssert.get("Arn"));
		assertNotNull(resultcreateAssert.get("UserId"));
		
		//user2有获取用户的权限		
		String getuserResult=IAMInterfaceTestUtils.GetUser(userak2, usersk2, userName02,200);
		JSONObject getResultAssert=ParseXmlToJson("GetUser",getuserResult);
		assertEquals(userName02,getResultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName02,getResultAssert.get("Arn"));
		
		String listbody2="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName02);
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest(listbody2, userak2, usersk2);
		assertEquals(200, listresult2.first().intValue());
		
		//user2有删除用户的权限
		String deluserResult=IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 200);
		System.out.println(deluserResult);

		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);

	}
	
	/**
	 * 1个策略1个statement，
	 * effect为allow，NotAction,actions为CreateUser，GetUser，DeleteUser，ListGroupsForUser，设置resourceEffect为NotResource，无condition
	 * 发送请求与策略匹配，用户可以CreateUser，GetUser，DeleteUser，ListGroupsForUser,userName为userName3
	 * **/
	
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_notActionNotResource_userName()throws Exception{
		String userName="createUserbyUser";
		String userName02="createUserbyUser02";
		//创建策略，NotAction，actions为CreateGroup，DeleteGroup,NotResource,Reource无condition
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:CreateGroup","iam:DeleteGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/userName3"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//发送CreateUser请求，因与策略匹配，CreateUser成功
		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(200, result.first().intValue());
		System.out.print(result.second());
		JSONObject resultAssert=ParseXmlToJson("CreateUser",result.second());
		assertEquals(userName,resultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultAssert.get("Arn"));
		assertNotNull(resultAssert.get("UserId"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(200, listresult.first().intValue());
		
		//发送GetUser请求，因与策略匹配，GetUser成功		
		String bodyget="Action=GetUser&Version=2010-05-08";
		Pair<Integer, String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(200, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=ParseXmlToJson("GetUser",resultget.second());
		assertEquals(userName1,resultgetAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName1,resultgetAssert.get("Arn"));
		
		//发送DeleteUser请求，因为策略匹配，Delete User成功
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(200, resultdel.first().intValue());
		System.out.println(resultdel.second());
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		//user2有创建用户的权限
		String createUserResult=IAMInterfaceTestUtils.CreateUser(userak2, usersk2, userName02, 200);		
		JSONObject resultcreateAssert=ParseXmlToJson("CreateUser",createUserResult);
		assertEquals(userName02,resultcreateAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName02,resultcreateAssert.get("Arn"));
		assertNotNull(resultcreateAssert.get("UserId"));
		
		String listbody2="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName02);
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest(listbody2, userak2, usersk2);
		assertEquals(200, listresult2.first().intValue());
		
		//user2有获取用户的权限		
		String getuserResult=IAMInterfaceTestUtils.GetUser(userak2, usersk2, userName02,200);
		JSONObject getResultAssert=ParseXmlToJson("GetUser",getuserResult);
		assertEquals(userName02,getResultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName02,getResultAssert.get("Arn"));
		
		//user2有删除用户的权限
		String deluserResult=IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 200);
		System.out.println(deluserResult);

		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);

	}
	/**
	 * 1个策略1个statement，
	 * effect为allow，NotAction,actions为CreateUser，GetUser，DeleteUser，ListGroupsForUser，设置resourceEffect为NotResource，无condition
	 * 发送请求与策略匹配，用户可以CreateUser，GetUser，DeleteUser，ListGroupsForUser,resource为*
	 * **/
	
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_notActionNotResource_all()throws Exception{
		String userName="createUserbyUser";
		String userName02="createUserbyUser02";
		//创建策略，NotAction，actions为CreateGroup，DeleteGroup,NotResource,Reource无condition
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:CreateGroup","iam:DeleteGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//发送CreateUser请求，因与策略匹配，CreateUser失败
		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(403, result.first().intValue());
		System.out.print(result.second());
		JSONObject resultAssert=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("AccessDenied",resultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultAssert.get("Message"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(403, listresult.first().intValue());
		
		//发送GetUser请求，因与策略匹配，GetUser失败		
		String bodyget="Action=GetUser&Version=2010-05-08";
		Pair<Integer, String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(403, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=IAMTestUtils.ParseErrorToJson(resultget.second());
		assertEquals("AccessDenied",resultgetAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+".",resultgetAssert.get("Message"));
		
		//发送DeleteUser请求，因为策略匹配，Delete User失败
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(403, resultdel.first().intValue());
		System.out.println(resultdel.second());
		JSONObject resultdelAssert=IAMTestUtils.ParseErrorToJson(resultdel.second());
		assertEquals("AccessDenied",resultdelAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultdelAssert.get("Message"));
		
		//添加策略到组
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		//用户匹配策略，创建用户失败
		String createResult=IAMInterfaceTestUtils.CreateUser(userak2, usersk2, userName02, 403);
		JSONObject createResultAssert=IAMTestUtils.ParseErrorToJson(createResult);
		assertEquals("AccessDenied",createResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",createResultAssert.get("Message"));
		
		String listbody2="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName02);
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest(listbody2, userak2, usersk2);
		assertEquals(403, listresult2.first().intValue());
		
		//用户匹配策略，获取用户失败
		String getResult=IAMInterfaceTestUtils.GetUser(userak2, usersk2, userName02,403);
		JSONObject getResultAssert=IAMTestUtils.ParseErrorToJson(getResult);
		assertEquals("AccessDenied",getResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",getResultAssert.get("Message"));
		
		//删除用户失败
		String delResult=IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 403);
		JSONObject delResultAssert=IAMTestUtils.ParseErrorToJson(delResult);
		assertEquals("AccessDenied",delResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",delResultAssert.get("Message"));
		
		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}		
	
	/**
	 * 1个策略1个statement，
	 * effect为allow，NotAction,actions为允许CreateUser，DeleteUser，设置resourceEffect为NotResource，Resource为user匹配的资源，无condition
	 * 发送的请求与策略匹配，策略为NotResource，resource为匹配的资源,用户CreateUser，GetUser，DeleteUser，ListGroupsForUser失败
	 * **/
	
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_notActionNotResource1()throws Exception{
		String userName="createUserbyUser";
		String userName02="createUserbyUser02";
		//创建策略，Action，actions为CreateUser,getUser,DeleteUser,NotResource,resources为user/*,无condition
		String policyName="createPolicyFormatchNotResource";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//发送CreateUser请求，因与策略匹配NotAction，CreateUser失败
		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(403, result.first().intValue());
		System.out.print(result.second());
		JSONObject resultAssert=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("AccessDenied",resultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultAssert.get("Message"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(403, listresult.first().intValue());
		
		//发送GetUser请求，因与策略匹配，GetUser失败		
		String bodyget="Action=GetUser&Version=2010-05-08";
		Pair<Integer, String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(403, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=IAMTestUtils.ParseErrorToJson(resultget.second());
		assertEquals("AccessDenied",resultgetAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+".",resultgetAssert.get("Message"));
		
		//发送DeleteUser请求，因为策略匹配，Delete User失败
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(403, resultdel.first().intValue());
		System.out.println(resultdel.second());
		JSONObject resultdelAssert=IAMTestUtils.ParseErrorToJson(resultdel.second());
		assertEquals("AccessDenied",resultdelAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultdelAssert.get("Message"));
		
		//添加策略到组
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		//用户匹配策略，创建用户失败
		String createResult=IAMInterfaceTestUtils.CreateUser(userak2, usersk2, userName02, 403);
		JSONObject createResultAssert=IAMTestUtils.ParseErrorToJson(createResult);
		assertEquals("AccessDenied",createResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",createResultAssert.get("Message"));
		
		String listbody2="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName02);
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest(listbody2, userak2, usersk2);
		assertEquals(403, listresult2.first().intValue());
		
		//用户匹配策略，获取用户失败
		String getResult=IAMInterfaceTestUtils.GetUser(userak2, usersk2, userName02,403);
		JSONObject getResultAssert=IAMTestUtils.ParseErrorToJson(getResult);
		assertEquals("AccessDenied",getResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",getResultAssert.get("Message"));
		
		//删除用户失败
		String delResult=IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 403);
		JSONObject delResultAssert=IAMTestUtils.ParseErrorToJson(delResult);
		assertEquals("AccessDenied",delResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",delResultAssert.get("Message"));
		
		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}	
	/**
	 * 1个策略1个statement，
	 * effect为allow，NotAction,actions为允许CreateGroup，DeleteGroup，设置resourceEffect为NotResource，Resource为user匹配的资源，无condition
	 * 发送的请求与策略匹配，策略为NotResource，resource为匹配的资源,用户CreateUser，GetUser，DeleteUser，ListGroupsForUser失败
	 * **/
	
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_notActionNotResource2()throws Exception{
		String userName="createUserbyUser";
		String userName02="createUserbyUser02";
		//创建策略，Action，actions为CreateGroup，DeleteGroup,NotResource,resources为user/*,无condition
		String policyName="createPolicyFormatchNotResource";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:CreateGroup","iam:DeleteGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//发送CreateUser请求，因与策略匹配NotAction，CreateUser失败
		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(403, result.first().intValue());
		System.out.print(result.second());
		JSONObject resultAssert=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("AccessDenied",resultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultAssert.get("Message"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(403, listresult.first().intValue());
		
		//发送GetUser请求，因与策略匹配，GetUser失败		
		String bodyget="Action=GetUser&Version=2010-05-08";
		Pair<Integer, String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(403, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=IAMTestUtils.ParseErrorToJson(resultget.second());
		assertEquals("AccessDenied",resultgetAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+".",resultgetAssert.get("Message"));
		
		//发送DeleteUser请求，因为策略匹配，Delete User失败
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(403, resultdel.first().intValue());
		System.out.println(resultdel.second());
		JSONObject resultdelAssert=IAMTestUtils.ParseErrorToJson(resultdel.second());
		assertEquals("AccessDenied",resultdelAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultdelAssert.get("Message"));
		
		//添加策略到组
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		//用户匹配策略，创建用户失败
		String createResult=IAMInterfaceTestUtils.CreateUser(userak2, usersk2, userName02, 403);
		JSONObject createResultAssert=IAMTestUtils.ParseErrorToJson(createResult);
		assertEquals("AccessDenied",createResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",createResultAssert.get("Message"));
		
		String listbody2="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName02);
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest(listbody2, userak2, usersk2);
		assertEquals(403, listresult2.first().intValue());
		
		//用户匹配策略，获取用户失败
		String getResult=IAMInterfaceTestUtils.GetUser(userak2, usersk2, userName02,403);
		JSONObject getResultAssert=IAMTestUtils.ParseErrorToJson(getResult);
		assertEquals("AccessDenied",getResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",getResultAssert.get("Message"));
		
		//删除用户失败
		String delResult=IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 403);
		JSONObject delResultAssert=IAMTestUtils.ParseErrorToJson(delResult);
		assertEquals("AccessDenied",delResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",delResultAssert.get("Message"));
		
		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}
	
	/**
	 * 1个策略1个statement，
	 * effect为allow，NotAction,actions为允许CreateGroup，DeleteGroup，设置resourceEffect为NotResource，Resource为user匹配的资源，无condition
	 * 发送的请求与策略匹配，策略为NotResource，resource为匹配的资源,用户CreateUser，GetUser，DeleteUser，ListGroupsForUser失败
	 * **/
	
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_notActionNotResource2_userName()throws Exception{
		String userName="createUserbyUser";
		String userName02="createUserbyUser02";
		//创建策略，Action，actions为CreateGroup，DeleteGroup,NotResource,resources为user/userName,无condition
		String policyName="createPolicyFormatchNotResource";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:CreateGroup","iam:DeleteGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/"+ userName,"arn:ctyun:iam::0000000gc0uy9:user/"+ userName1,"arn:ctyun:iam::0000000gc0uy9:user/"+ userName02),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//发送CreateUser请求，因与策略匹配NotAction，CreateUser失败
		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(403, result.first().intValue());
		System.out.print(result.second());
		JSONObject resultAssert=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("AccessDenied",resultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultAssert.get("Message"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(403, listresult.first().intValue());
		
		//发送GetUser请求，因与策略匹配，GetUser失败		
		String bodyget="Action=GetUser&Version=2010-05-08";
		Pair<Integer, String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(403, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=IAMTestUtils.ParseErrorToJson(resultget.second());
		assertEquals("AccessDenied",resultgetAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+".",resultgetAssert.get("Message"));
		
		//发送DeleteUser请求，因为策略匹配，Delete User失败
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(403, resultdel.first().intValue());
		System.out.println(resultdel.second());
		JSONObject resultdelAssert=IAMTestUtils.ParseErrorToJson(resultdel.second());
		assertEquals("AccessDenied",resultdelAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultdelAssert.get("Message"));
		
		//添加策略到组
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		//用户匹配策略，创建用户失败
		String createResult=IAMInterfaceTestUtils.CreateUser(userak2, usersk2, userName02, 403);
		JSONObject createResultAssert=IAMTestUtils.ParseErrorToJson(createResult);
		assertEquals("AccessDenied",createResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",createResultAssert.get("Message"));
		
		String listbody2="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName02);
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest(listbody2, userak2, usersk2);
		assertEquals(403, listresult2.first().intValue());
		
		//用户匹配策略，获取用户失败
		String getResult=IAMInterfaceTestUtils.GetUser(userak2, usersk2, userName02,403);
		JSONObject getResultAssert=IAMTestUtils.ParseErrorToJson(getResult);
		assertEquals("AccessDenied",getResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",getResultAssert.get("Message"));
		
		//删除用户失败
		String delResult=IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 403);
		JSONObject delResultAssert=IAMTestUtils.ParseErrorToJson(delResult);
		assertEquals("AccessDenied",delResultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName02+".",delResultAssert.get("Message"));
		
		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}	

	/**
	 * 1个策略1个statement，
	 * effect为allow，Action,actions为允许CreateUser，GetUser，DeleteUser，ListGroupsForUser，设置resourceEffect为允许，有condition
	 * 发送请求与策略匹配，用户可以CreateUser，GetUser，DeleteUser，ListGroupsForUser
	 * 有condition，符合条件--sourceIP,create/get/delUser成功，不符合IP的create/get/delUser失败（403）
	 * user添加策略；user2未添加策略，所在group添加策略
	 * **/
	
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_condition_resourceIp()throws Exception{
		String userName="createUserbyUser";
		//创建策略，Action，actions为CreateUser，，GetUser，DeleteUser,Resource,resources=user/*,有condition
		String policyName="policyFrotestSourceIP";
	    List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("IpAddress","ctyun:SourceIp",Arrays.asList("192.168.1.1/24")));
        
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),conditions);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//在IP范围内
		List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("X-Forwarded-For");
        param1.second("192.168.1.101");
        params.add(param1);
        
        //不在IP范围内
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("X-Forwarded-For");
        param2.second("192.168.2.101");
        params2.add(param2);
		
		//发送CreateUser请求，因与策略匹配，CreateUser成功
		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);        
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, userak1, usersk1,params);
        assertEquals(200, result.first().intValue());
		JSONObject resultAssert=ParseXmlToJson("CreateUser",result.second());
		assertEquals(userName,resultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultAssert.get("Arn"));
		assertNotNull(resultAssert.get("UserId"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest2(listbody, userak1, usersk1,params);
		assertEquals(200, listresult.first().intValue());
		
		//发送GetUser请求，因与策略匹配，GetUser成功		
		String bodyget="Action=GetUser&Version=2010-05-08";
		Pair<Integer,String> resultget=IAMTestUtils.invokeHttpsRequest2(bodyget, userak1, usersk1,params);
		assertEquals(200, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=ParseXmlToJson("GetUser",resultget.second());
		assertEquals(userName1,resultgetAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName1,resultgetAssert.get("Arn"));
		
		//发送DeleteUser请求，因为策略匹配，Delete User成功
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest2(bodydel, userak1, usersk1,params);
		assertEquals(200, resultdel.first().intValue());
		System.out.println(resultdel.second());

		//发送请求时，不在IP范围内，put/get/delUser会403异常
		Pair<Integer, String> result2=IAMTestUtils.invokeHttpsRequest2(body, userak1, usersk1,params2);
		assertEquals(403, result2.first().intValue());
		System.out.print(result2.second());
		JSONObject resultAssert2=IAMTestUtils.ParseErrorToJson(result2.second());
		assertEquals("AccessDenied",resultAssert2.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultAssert2.get("Message"));
		
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest2(listbody, userak1, usersk1,params2);
		assertEquals(403, listresult2.first().intValue());
		
		Pair<Integer, String> resultget2=IAMTestUtils.invokeHttpsRequest2(bodyget, userak1, usersk1,params2);
		assertEquals(403, resultget2.first().intValue());
		System.out.println(resultget2.second());
		JSONObject resultgetAssert2=IAMTestUtils.ParseErrorToJson(resultget2.second());
		assertEquals("AccessDenied",resultgetAssert2.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+".",resultgetAssert2.get("Message"));
		
		Pair<Integer, String> resultdel2=IAMTestUtils.invokeHttpsRequest2(bodydel, userak1, usersk1,params2);
		assertEquals(403, resultdel2.first().intValue());
		System.out.println(resultdel2.second());
		JSONObject resultdelAssert2=IAMTestUtils.ParseErrorToJson(resultdel2.second());
		assertEquals("AccessDenied",resultdelAssert2.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultdelAssert2.get("Message"));

		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		//user2发送请求在IP范围内，有create/get/delUser的权限
		Pair<Integer, String> createUserResult=IAMTestUtils.invokeHttpsRequest2(body, userak2, usersk2,params);
		assertEquals(200,createUserResult.first().intValue());
		JSONObject resultcreateAssert=ParseXmlToJson("CreateUser",createUserResult.second());
		assertEquals(userName,resultcreateAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultcreateAssert.get("Arn"));
		assertNotNull(resultcreateAssert.get("UserId"));
			
		Pair<Integer, String> getuserResult=IAMTestUtils.invokeHttpsRequest2(bodyget, userak2, usersk2,params);
		assertEquals(200,getuserResult.first().intValue());
		JSONObject getResultAssert=ParseXmlToJson("GetUser",getuserResult.second());
		assertEquals(userName2,getResultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName2,getResultAssert.get("Arn"));
		
		Pair<Integer, String> deluserResult=IAMTestUtils.invokeHttpsRequest2(bodydel, userak2, usersk2,params);
		assertEquals(200,deluserResult.first().intValue());
		System.out.println(deluserResult.second());
		
		//user2发送的请求不在IP范围内，create/get/delUser失败
		Pair<Integer, String> createUserResult2=IAMTestUtils.invokeHttpsRequest2(body, userak2, usersk2,params2);
		assertEquals(403,createUserResult2.first().intValue());
		System.out.print(createUserResult2.second());
		JSONObject resultcreateAssert2=IAMTestUtils.ParseErrorToJson(createUserResult2.second());
		assertEquals("AccessDenied",resultcreateAssert2.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultcreateAssert2.get("Message"));
		
		Pair<Integer, String> getuserResult2=IAMTestUtils.invokeHttpsRequest2(bodyget, userak2, usersk2,params2);
		assertEquals(403,getuserResult2.first().intValue());
		System.out.println(getuserResult2.second());
		JSONObject getResultAssert2=IAMTestUtils.ParseErrorToJson(getuserResult2.second());
		assertEquals("AccessDenied",getResultAssert2.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+".",getResultAssert2.get("Message"));
		
		Pair<Integer, String> deluserResult2=IAMTestUtils.invokeHttpsRequest2(bodydel, userak2, usersk2,params2);
		assertEquals(403,deluserResult2.first().intValue());
		System.out.println(deluserResult2.second());
		JSONObject delresultAssert2=IAMTestUtils.ParseErrorToJson(deluserResult2.second());
		assertEquals("AccessDenied",delresultAssert2.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",delresultAssert2.get("Message"));

		
		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);

	}
	//notIpAddress
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_condition_resourceIp2()throws Exception{
		String userName="createUserbyUser";
		//创建策略，Action，actions为CreateUser，，GetUser，DeleteUser,Resource,resources=user/*,有condition
		String policyName="policyFrotestSourceIP";
	    List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("NotIpAddress","ctyun:SourceIp",Arrays.asList("192.168.1.1/24")));
        
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),conditions);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//在IP范围内
		List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param1= new Pair<String, String>();
        param1.first("X-Forwarded-For");
        param1.second("192.168.1.101");
        params.add(param1);
        
        //不在IP范围内
        List<Pair<String, String>> params2=new ArrayList<Pair<String,String>>();
        Pair<String, String>  param2= new Pair<String, String>();
        param2.first("X-Forwarded-For");
        param2.second("192.168.2.101");
        params2.add(param2);
		
		//发送CreateUser请求，因与策略不匹配，CreateUser成功
		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);        
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest2(body, userak1, usersk1,params2);
        assertEquals(200, result.first().intValue());
		JSONObject resultAssert=ParseXmlToJson("CreateUser",result.second());
		assertEquals(userName,resultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultAssert.get("Arn"));
		assertNotNull(resultAssert.get("UserId"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest2(listbody, userak1, usersk1,params2);
		assertEquals(200, listresult.first().intValue());
		
		//发送GetUser请求，因与策略匹配，GetUser成功		
		String bodyget="Action=GetUser&Version=2010-05-08";
		Pair<Integer,String> resultget=IAMTestUtils.invokeHttpsRequest2(bodyget, userak1, usersk1,params2);
		assertEquals(200, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=ParseXmlToJson("GetUser",resultget.second());
		assertEquals(userName1,resultgetAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName1,resultgetAssert.get("Arn"));
		
		//发送DeleteUser请求，因为策略匹配，Delete User成功
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest2(bodydel, userak1, usersk1,params2);
		assertEquals(200, resultdel.first().intValue());
		System.out.println(resultdel.second());

		//发送请求时，在IP范围内，put/get/delUser会403异常
		Pair<Integer, String> result2=IAMTestUtils.invokeHttpsRequest2(body, userak1, usersk1,params);
		assertEquals(403, result2.first().intValue());
		System.out.print(result2.second());
		JSONObject resultAssert2=IAMTestUtils.ParseErrorToJson(result2.second());
		assertEquals("AccessDenied",resultAssert2.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultAssert2.get("Message"));
		
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest2(listbody, userak1, usersk1,params);
		assertEquals(200, listresult2.first().intValue());
		
		Pair<Integer, String> resultget2=IAMTestUtils.invokeHttpsRequest2(bodyget, userak1, usersk1,params);
		assertEquals(403, resultget2.first().intValue());
		System.out.println(resultget2.second());
		JSONObject resultgetAssert2=IAMTestUtils.ParseErrorToJson(resultget2.second());
		assertEquals("AccessDenied",resultgetAssert2.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+".",resultgetAssert2.get("Message"));
		
		Pair<Integer, String> resultdel2=IAMTestUtils.invokeHttpsRequest2(bodydel, userak1, usersk1,params);
		assertEquals(403, resultdel2.first().intValue());
		System.out.println(resultdel2.second());
		JSONObject resultdelAssert2=IAMTestUtils.ParseErrorToJson(resultdel2.second());
		assertEquals("AccessDenied",resultdelAssert2.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultdelAssert2.get("Message"));

		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		//user2发送请求不在IP范围内，有create/get/delUser的权限
		Pair<Integer, String> createUserResult=IAMTestUtils.invokeHttpsRequest2(body, userak2, usersk2,params2);
		assertEquals(200,createUserResult.first().intValue());
		JSONObject resultcreateAssert=ParseXmlToJson("CreateUser",createUserResult.second());
		assertEquals(userName,resultcreateAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultcreateAssert.get("Arn"));
		assertNotNull(resultcreateAssert.get("UserId"));
			
		Pair<Integer, String> getuserResult=IAMTestUtils.invokeHttpsRequest2(bodyget, userak2, usersk2,params2);
		assertEquals(200,getuserResult.first().intValue());
		JSONObject getResultAssert=ParseXmlToJson("GetUser",getuserResult.second());
		assertEquals(userName2,getResultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName2,getResultAssert.get("Arn"));
		
		Pair<Integer, String> deluserResult=IAMTestUtils.invokeHttpsRequest2(bodydel, userak2, usersk2,params2);
		assertEquals(200,deluserResult.first().intValue());
		System.out.println(deluserResult.second());
		
		//user2发送的请求在IP范围内，create/get/delUser失败
		Pair<Integer, String> createUserResult2=IAMTestUtils.invokeHttpsRequest2(body, userak2, usersk2,params);
		assertEquals(403,createUserResult2.first().intValue());
		System.out.print(createUserResult2.second());
		JSONObject resultcreateAssert2=IAMTestUtils.ParseErrorToJson(createUserResult2.second());
		assertEquals("AccessDenied",resultcreateAssert2.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultcreateAssert2.get("Message"));
		
		Pair<Integer, String> getuserResult2=IAMTestUtils.invokeHttpsRequest2(bodyget, userak2, usersk2,params);
		assertEquals(403,getuserResult2.first().intValue());
		System.out.println(getuserResult2.second());
		JSONObject getResultAssert2=IAMTestUtils.ParseErrorToJson(getuserResult2.second());
		assertEquals("AccessDenied",getResultAssert2.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+".",getResultAssert2.get("Message"));
		
		Pair<Integer, String> deluserResult2=IAMTestUtils.invokeHttpsRequest2(bodydel, userak2, usersk2,params);
		assertEquals(403,deluserResult2.first().intValue());
		System.out.println(deluserResult2.second());
		JSONObject delresultAssert2=IAMTestUtils.ParseErrorToJson(deluserResult2.second());
		assertEquals("AccessDenied",delresultAssert2.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",delresultAssert2.get("Message"));

		
		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);

	}
	
	/**
	 * 1个策略1个statement，
	 * effect为allow，Action,actions为允许CreateUser，GetUser，DeleteUser，ListGroupsForUser，设置resourceEffect为允许，有condition
	 * 发送请求与策略匹配，用户可以CreateUser，GetUser，DeleteUser，ListGroupsForUser
	 * 有condition，条件运算符为StringLike,区分大小写
	 * 符合条件--userName,create/get/delUser成功，不符合userName的create/get/delUser失败（403）
	 * user添加策略；user2未添加策略，所在group添加策略，user21添加策略但是不符合条件
	 * **/
	
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_condition_userName()throws Exception{
		String userName="createUserbyUser";
		//创建策略，Action，actions为CreateUser，，GetUser，DeleteUser,Resource,resources=user/*,有condition
		String policyName="policyFortestuserName";
	    List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test01*","TEST02*")));
        
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser","iam:ListGroupsForUser","iam:ListGroupsForUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),conditions);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		attachPolicyToUser(userName21,policyArn);

		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);	
		String bodyget="Action=GetUser&Version=2010-05-08&UserName=" + userName;
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
	
		//user1因与策略匹配，Create/get/delUser成功
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
        assertEquals(200, result.first().intValue());
		JSONObject resultAssert=ParseXmlToJson("CreateUser",result.second());
		assertEquals(userName,resultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultAssert.get("Arn"));
		assertNotNull(resultAssert.get("UserId"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(200, listresult.first().intValue());
				
		Pair<Integer,String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(200, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=ParseXmlToJson("GetUser",resultget.second());
		assertEquals(userName,resultgetAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultgetAssert.get("Arn"));
		
		//发送DeleteUser请求，因为策略匹配，Delete User成功	
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(200, resultdel.first().intValue());
		System.out.println(resultdel.second());

		//发送请求时不符合userName条件，put/get/delUser会403异常
		Pair<Integer, String> result2=IAMTestUtils.invokeHttpsRequest(body, userak21, usersk21);
		assertEquals(403, result2.first().intValue());
		System.out.print(result2.second());
		JSONObject resultAssert2=IAMTestUtils.ParseErrorToJson(result2.second());
		assertEquals("AccessDenied",resultAssert2.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName21+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultAssert2.get("Message"));
		
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest(listbody, userak21, usersk21);
		assertEquals(403, listresult2.first().intValue());
		
		Pair<Integer, String> resultget2=IAMTestUtils.invokeHttpsRequest(bodyget, userak21, usersk21);
		assertEquals(403, resultget2.first().intValue());
		System.out.println(resultget2.second());
		JSONObject resultgetAssert2=IAMTestUtils.ParseErrorToJson(resultget2.second());
		assertEquals("AccessDenied",resultgetAssert2.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName21+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultgetAssert2.get("Message"));
		
		Pair<Integer, String> resultdel2=IAMTestUtils.invokeHttpsRequest(bodydel, userak21, usersk21);
		assertEquals(403, resultdel2.first().intValue());
		System.out.println(resultdel2.second());
		JSONObject resultdelAssert2=IAMTestUtils.ParseErrorToJson(resultdel2.second());
		assertEquals("AccessDenied",resultdelAssert2.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName21+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultdelAssert2.get("Message"));
	
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		//user2发送请求userName符合条件，有create/get/delUser的权限
		Pair<Integer, String> createUserResult=IAMTestUtils.invokeHttpsRequest(body, userak2, usersk2);
		assertEquals(200,createUserResult.first().intValue());
		JSONObject resultcreateAssert=ParseXmlToJson("CreateUser",createUserResult.second());
		assertEquals(userName,resultcreateAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultcreateAssert.get("Arn"));
		assertNotNull(resultcreateAssert.get("UserId"));
		
		Pair<Integer, String> listresult3=IAMTestUtils.invokeHttpsRequest(listbody, userak2, usersk2);
		assertEquals(200, listresult3.first().intValue());
			
		Pair<Integer, String> getuserResult=IAMTestUtils.invokeHttpsRequest(bodyget, userak2, usersk2);
		assertEquals(200,getuserResult.first().intValue());
		JSONObject getResultAssert=ParseXmlToJson("GetUser",getuserResult.second());
		assertEquals(userName,getResultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,getResultAssert.get("Arn"));
		
		Pair<Integer, String> deluserResult=IAMTestUtils.invokeHttpsRequest(bodydel, userak2, usersk2);
		assertEquals(200,deluserResult.first().intValue());
		System.out.println(deluserResult.second());
		
		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		detachPolicyFromUser(userName21,policyArn);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);

	}
	
	/**
	 * 1个策略1个statement，
	 * effect为allow，Action,actions为允许CreateUser，GetUser，DeleteUser，ListGroupsForUser，设置resourceEffect为允许，有condition
	 * 发送请求与策略匹配，用户可以CreateUser，GetUser，DeleteUser，ListGroupsForUser
	 * 有condition，条件运算符为StringEquals
	 * 符合条件--userName,create/get/delUser成功，不符合userName的create/get/delUser失败（403）
	 * user添加策略；user2未添加策略，所在group添加策略，user21添加策略但是不符合条件
	 * **/
	
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_condition_userName2()throws Exception{
		String userName="createUserbyUser";
		//创建策略，Action，actions为CreateUser，，GetUser，DeleteUser,Resource,resources=user/*,有condition
		String policyName="policyFortestuserName";
	    List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList("test01_subUser01","test01_subUser02")));
        
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),conditions);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		attachPolicyToUser(userName21,policyArn);

		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);	
		String bodyget="Action=GetUser&Version=2010-05-08&UserName=" + userName;
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
	
		//user1因与策略匹配，Create/get/delUser成功
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
        assertEquals(200, result.first().intValue());
		JSONObject resultAssert=ParseXmlToJson("CreateUser",result.second());
		assertEquals(userName,resultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultAssert.get("Arn"));
		assertNotNull(resultAssert.get("UserId"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(200, listresult.first().intValue());
				
		Pair<Integer,String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(200, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=ParseXmlToJson("GetUser",resultget.second());
		assertEquals(userName,resultgetAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultgetAssert.get("Arn"));
		
		//发送DeleteUser请求，因为策略匹配，Delete User成功	
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(200, resultdel.first().intValue());
		System.out.println(resultdel.second());

		//发送请求时不符合userName条件，put/get/delUser会403异常
		Pair<Integer, String> result2=IAMTestUtils.invokeHttpsRequest(body, userak21, usersk21);
		assertEquals(403, result2.first().intValue());
		System.out.print(result2.second());
		JSONObject resultAssert2=IAMTestUtils.ParseErrorToJson(result2.second());
		assertEquals("AccessDenied",resultAssert2.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName21+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultAssert2.get("Message"));
		
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest(listbody, userak21, usersk21);
		assertEquals(403, listresult2.first().intValue());
		
		Pair<Integer, String> resultget2=IAMTestUtils.invokeHttpsRequest(bodyget, userak21, usersk21);
		assertEquals(403, resultget2.first().intValue());
		System.out.println(resultget2.second());
		JSONObject resultgetAssert2=IAMTestUtils.ParseErrorToJson(resultget2.second());
		assertEquals("AccessDenied",resultgetAssert2.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName21+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultgetAssert2.get("Message"));
		
		Pair<Integer, String> resultdel2=IAMTestUtils.invokeHttpsRequest(bodydel, userak21, usersk21);
		assertEquals(403, resultdel2.first().intValue());
		System.out.println(resultdel2.second());
		JSONObject resultdelAssert2=IAMTestUtils.ParseErrorToJson(resultdel2.second());
		assertEquals("AccessDenied",resultdelAssert2.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName21+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultdelAssert2.get("Message"));
	
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		//user2发送请求userName符合条件，有create/get/delUser的权限
		Pair<Integer, String> createUserResult=IAMTestUtils.invokeHttpsRequest(body, userak2, usersk2);
		assertEquals(200,createUserResult.first().intValue());
		JSONObject resultcreateAssert=ParseXmlToJson("CreateUser",createUserResult.second());
		assertEquals(userName,resultcreateAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultcreateAssert.get("Arn"));
		assertNotNull(resultcreateAssert.get("UserId"));
			
		Pair<Integer, String> listresult3=IAMTestUtils.invokeHttpsRequest(listbody, userak2, usersk2);
		assertEquals(200, listresult3.first().intValue());
		
		Pair<Integer, String> getuserResult=IAMTestUtils.invokeHttpsRequest(bodyget, userak2, usersk2);
		assertEquals(200,getuserResult.first().intValue());
		JSONObject getResultAssert=ParseXmlToJson("GetUser",getuserResult.second());
		assertEquals(userName,getResultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,getResultAssert.get("Arn"));
		
		Pair<Integer, String> deluserResult=IAMTestUtils.invokeHttpsRequest(bodydel, userak2, usersk2);
		assertEquals(200,deluserResult.first().intValue());
		System.out.println(deluserResult.second());
		
		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		detachPolicyFromUser(userName21,policyArn);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);

	}
	
	//StringEquals区分大小写
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_condition_userName3()throws Exception{
		String userName="createUserbyUser";
		//创建策略，Action，actions为CreateUser，，GetUser，DeleteUser,Resource,resources=user/*,有condition
		String policyName="policyFortestuserName";
	    List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList("TEST01_subUser01")));
        
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),conditions);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);

		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);	
		String bodyget="Action=GetUser&Version=2010-05-08&UserName=" + userName;
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;

		//发送请求时不符合userName条件，put/get/delUser会403异常
		Pair<Integer, String> result2=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(403, result2.first().intValue());
		System.out.print(result2.second());
		JSONObject resultAssert2=IAMTestUtils.ParseErrorToJson(result2.second());
		assertEquals("AccessDenied",resultAssert2.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultAssert2.get("Message"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(403, listresult.first().intValue());
		
		Pair<Integer, String> resultget2=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(403, resultget2.first().intValue());
		System.out.println(resultget2.second());
		JSONObject resultgetAssert2=IAMTestUtils.ParseErrorToJson(resultget2.second());
		assertEquals("AccessDenied",resultgetAssert2.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultgetAssert2.get("Message"));
		
		Pair<Integer, String> resultdel2=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(403, resultdel2.first().intValue());
		System.out.println(resultdel2.second());
		JSONObject resultdelAssert2=IAMTestUtils.ParseErrorToJson(resultdel2.second());
		assertEquals("AccessDenied",resultdelAssert2.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultdelAssert2.get("Message"));
	
		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);

	}	
	
	//StringEqualsIgnoreCase不区分大小写
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_condition_userName4()throws Exception{
		String userName="createUserbyUser";
		//创建策略，Action，actions为CreateUser，，GetUser，DeleteUser,Resource,resources=user/*,有condition
		String policyName="policyFortestuserName";
	    List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","ctyun:username",Arrays.asList("TEST01_subUser01","test01_subUser02")));
        
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),conditions);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);

		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);	
		String bodyget="Action=GetUser&Version=2010-05-08&UserName=" + userName;
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
	
		//user1因与策略匹配，Create/get/delUser成功
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
        assertEquals(200, result.first().intValue());
		JSONObject resultAssert=ParseXmlToJson("CreateUser",result.second());
		assertEquals(userName,resultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultAssert.get("Arn"));
		assertNotNull(resultAssert.get("UserId"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(200, listresult.first().intValue());
				
		Pair<Integer,String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(200, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=ParseXmlToJson("GetUser",resultget.second());
		assertEquals(userName,resultgetAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultgetAssert.get("Arn"));
		
		//发送DeleteUser请求，因为策略匹配，Delete User成功	
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(200, resultdel.first().intValue());
		System.out.println(resultdel.second());
		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
	}	
	//StringNotEqualsIgnoreCase，不区分大小写
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_condition_userName5()throws Exception{
		String userName="createUserbyUser";
		//创建策略，Action，actions为CreateUser，，GetUser，DeleteUser,Resource,resources=user/*,有condition
		String policyName="policyFortestuserName";
	    List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","ctyun:username",Arrays.asList("TEST01_subUser01")));
        
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),conditions);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);

		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);	
		String bodyget="Action=GetUser&Version=2010-05-08&UserName=" + userName;
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
	
		//发送请求时符合userName条件，put/get/delUser会403异常
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(403, result.first().intValue());
		System.out.print(result.second());
		JSONObject resultAssert=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("AccessDenied",resultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultAssert.get("Message"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(403, listresult.first().intValue());
		
		Pair<Integer, String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(403, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=IAMTestUtils.ParseErrorToJson(resultget.second());
		assertEquals("AccessDenied",resultgetAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultgetAssert.get("Message"));
		
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(403, resultdel.first().intValue());
		System.out.println(resultdel.second());
		JSONObject resultdelAssert=IAMTestUtils.ParseErrorToJson(resultdel.second());
		assertEquals("AccessDenied",resultdelAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultdelAssert.get("Message"));
	
		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
	}
	
	
	//StringNotEquals，区分大小写
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_condition_userName6()throws Exception{
		String userName="createUserbyUser";
		//创建策略，Action，actions为CreateUser，，GetUser，DeleteUser,Resource,resources=user/*,有condition
		String policyName="policyFortestuserName";
	    List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","ctyun:username",Arrays.asList("test02_subUser01")));
        
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),conditions);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		attachPolicyToUser(userName21,policyArn);

		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);	
		String bodyget="Action=GetUser&Version=2010-05-08&UserName=" + userName;
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
	
		//Create/get/delUser成功
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
        assertEquals(200, result.first().intValue());
		JSONObject resultAssert=ParseXmlToJson("CreateUser",result.second());
		assertEquals(userName,resultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultAssert.get("Arn"));
		assertNotNull(resultAssert.get("UserId"));
				
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(200, listresult.first().intValue());
		
		Pair<Integer,String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(200, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=ParseXmlToJson("GetUser",resultget.second());
		assertEquals(userName,resultgetAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultgetAssert.get("Arn"));
		
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(200, resultdel.first().intValue());
		System.out.println(resultdel.second());

		//发送请求时符合userName条件，put/get/delUser会403异常
		Pair<Integer, String> result2=IAMTestUtils.invokeHttpsRequest(body, userak21, usersk21);
		assertEquals(403, result2.first().intValue());
		System.out.print(result2.second());
		JSONObject resultAssert2=IAMTestUtils.ParseErrorToJson(result2.second());
		assertEquals("AccessDenied",resultAssert2.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName21+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultAssert2.get("Message"));
		
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest(listbody, userak21, usersk21);
		assertEquals(403, listresult2.first().intValue());
		
		Pair<Integer, String> resultget2=IAMTestUtils.invokeHttpsRequest(bodyget, userak21, usersk21);
		assertEquals(403, resultget2.first().intValue());
		System.out.println(resultget2.second());
		JSONObject resultgetAssert2=IAMTestUtils.ParseErrorToJson(resultget2.second());
		assertEquals("AccessDenied",resultgetAssert2.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName21+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultgetAssert2.get("Message"));
		
		Pair<Integer, String> resultdel2=IAMTestUtils.invokeHttpsRequest(bodydel, userak21, usersk21);
		assertEquals(403, resultdel2.first().intValue());
		System.out.println(resultdel2.second());
		JSONObject resultdelAssert2=IAMTestUtils.ParseErrorToJson(resultdel2.second());
		assertEquals("AccessDenied",resultdelAssert2.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName21+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultdelAssert2.get("Message"));
		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		detachPolicyFromUser(userName21,policyArn);
		
		//区分大小写
		List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("StringNotEquals","ctyun:username",Arrays.asList("TEST01_subUser01")));
        
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser","iam:ListGroupsForUser","iam:ListGroupsForUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),conditions);
		attachPolicyToUser(userName1,policyArn);
		
		//Create/get/delUser成功
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
        assertEquals(200, result3.first().intValue());
		JSONObject resultAssert3=ParseXmlToJson("CreateUser",result3.second());
		assertEquals(userName,resultAssert3.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultAssert3.get("Arn"));
		assertNotNull(resultAssert3.get("UserId"));
				
		Pair<Integer, String> listresult3=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(200, listresult3.first().intValue());
		
		Pair<Integer,String> resultget3=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(200, resultget3.first().intValue());
		System.out.println(resultget3.second());
		JSONObject resultgetAssert3=ParseXmlToJson("GetUser",resultget3.second());
		assertEquals(userName,resultgetAssert3.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultgetAssert3.get("Arn"));
		
		Pair<Integer, String> resultdel3=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(200, resultdel3.first().intValue());
		System.out.println(resultdel3.second());
		
	}	
	
	//StringNotLike，区分大小写
	@Test
	public void test_createGetDelListGroupsForUser_allow_match_condition_userName7()throws Exception{
		String userName="createUserbyUser";
		//创建策略，Action，actions为CreateUser，，GetUser，DeleteUser,Resource,resources=user/*,有condition
		String policyName="policyFortestuserName";
	    List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotLike","ctyun:username",Arrays.asList("test*")));
        
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),conditions);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);

		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);	
		String bodyget="Action=GetUser&Version=2010-05-08&UserName=" + userName;
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
	
		//发送请求时符合userName条件，put/get/delUser会403异常
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(403, result.first().intValue());
		System.out.print(result.second());
		JSONObject resultAssert=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("AccessDenied",resultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultAssert.get("Message"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(403, listresult.first().intValue());
		
		Pair<Integer, String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(403, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=IAMTestUtils.ParseErrorToJson(resultget.second());
		assertEquals("AccessDenied",resultgetAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultgetAssert.get("Message"));
		
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(403, resultdel.first().intValue());
		System.out.println(resultdel.second());
		JSONObject resultdelAssert=IAMTestUtils.ParseErrorToJson(resultdel.second());
		assertEquals("AccessDenied",resultdelAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultdelAssert.get("Message"));
	
		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		
		//测试区分大小写
		List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("StringNotLike","ctyun:username",Arrays.asList("TEST*")));
        
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser","iam:ListGroupsForUser","iam:ListGroupsForUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),conditions2);
		attachPolicyToUser(userName1,policyArn);
		//Create/get/delUser成功
        Pair<Integer,String> result3=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
        assertEquals(200, result3.first().intValue());
		JSONObject resultAssert3=ParseXmlToJson("CreateUser",result3.second());
		assertEquals(userName,resultAssert3.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultAssert3.get("Arn"));
		assertNotNull(resultAssert3.get("UserId"));
				
		Pair<Integer, String> listresult3=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(200, listresult3.first().intValue());
		
		Pair<Integer,String> resultget3=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(200, resultget3.first().intValue());
		System.out.println(resultget3.second());
		JSONObject resultgetAssert3=ParseXmlToJson("GetUser",resultget3.second());
		assertEquals(userName,resultgetAssert3.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,resultgetAssert3.get("Arn"));
		
		Pair<Integer, String> resultdel3=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(200, resultdel3.first().intValue());
		System.out.println(resultdel3.second());
		
		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
	}	
	
	
	/**
	 * effect为Deny，Action,actions为CreateUser，GetUser，DeleteUser，ListGroupsForUser，设置resourceEffect为Resource，Resource为user匹配的资源，无condition
	 * 发送的请求与策略匹配，策略为Action，resource为匹配的资源,拒绝用户CreateUser，GetUser，DeleteUser，ListGroupsForUser操作，用户CreateUser，GetUser，DeleteUser，ListGroupsForUser失败
	 * 
	 * 给user添加allow策略且策略为允许create/get/delUser，存在deny和allow两种策略的情况下，deny优先allow，如果deny匹配则deny策略生效，用户创建/获取/删除User失败
	 * **/
	
	@Test
	public void test_createGetDelListGroupsForUser_deny_match()throws Exception{
		//创建策略，Action，actions为CreateUser，GetUser，DeleteUser，ListGroupsForUser,Resource,resources为user/*,无condition
		String policyName="createPolicyFormatchdeny";
		List<String> actions=Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser");
		List<String> resources=Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*");
		createPolicy(Effect.Deny,policyName,"Action",actions,"Resource",resources,null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//发送CreateUser请求，因与策略匹配为deny Action，CreateUser失败
		String userName="createUserbyUser";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(403, result.first().intValue());
		System.out.print(result.second());
		JSONObject resultAssert=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("AccessDenied",resultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultAssert.get("Message"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(403, listresult.first().intValue());
		
		//发送GetUser请求，因与策略匹配deny，GetUser失败		
		String bodyget="Action=GetUser&Version=2010-05-08";
		Pair<Integer, String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(403, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=IAMTestUtils.ParseErrorToJson(resultget.second());
		assertEquals("AccessDenied",resultgetAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+".",resultgetAssert.get("Message"));
		
		//发送DeleteUser请求，因为策略匹配deny,Delete User失败
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(403, resultdel.first().intValue());
		System.out.println(resultdel.second());
		JSONObject resultdelAssert=IAMTestUtils.ParseErrorToJson(resultdel.second());
		assertEquals("AccessDenied",resultdelAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultdelAssert.get("Message"));

		String policyName2="testforAllowAfterDeny";
		String policyArn2=attacheUserallowedPolicy_allow(userName1,policyName2,actions,resources);
		
		//添加allowed策略之后，create/get/delUser失败
		String createUserResult=IAMInterfaceTestUtils.CreateUser(userak1, usersk1, userName, 403);		
		System.out.print(createUserResult);
		JSONObject resultcreateAssert=IAMTestUtils.ParseErrorToJson(createUserResult);
		assertEquals("AccessDenied",resultcreateAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultcreateAssert.get("Message"));
		
		String listresult2=IAMInterfaceTestUtils.ListGroupsForUser(userak1, usersk1, userName, 403);
		System.out.print(listresult2);
		JSONObject listresult2Assert=IAMTestUtils.ParseErrorToJson(listresult2);
		assertEquals("AccessDenied",listresult2Assert.get("Code"));
		
		String getuserResult=IAMInterfaceTestUtils.GetUser(userak1, usersk1, userName,403);
		System.out.println(getuserResult);
		JSONObject getresultAssert=IAMTestUtils.ParseErrorToJson(getuserResult);
		assertEquals("AccessDenied",getresultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",getresultAssert.get("Message"));
		
		String deluserResult=IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 403);
		System.out.println(deluserResult);
		JSONObject delresultAssert=IAMTestUtils.ParseErrorToJson(deluserResult);
		assertEquals("AccessDenied",delresultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",delresultAssert.get("Message"));

		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		detachPolicyFromUser(userName1,policyArn2);
		
	}
	
	/**
	 * 1个策略1个statement，
	 * effect为Deny，NotAction,actions为CreateGroup,DeleteGroup，设置resourceEffect为Resource，Resource为user匹配的资源，无condition
	 * 发送的请求与策略匹配，策略为NotAction，resource为匹配的资源,与NotAction匹配，与resources匹配，effect为Deny，CreateUser，GetUser,DeleteUse失败
	 * **/
	
	@Test
	public void test_createGetDelListGroupsForUser_deny_match_notAction()throws Exception{
		//创建策略，NotAction，actions为CreateGroup，DeleteGroup,Resource,resources=user/*,无condition
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Deny,policyName,"NotAction",Arrays.asList("iam:CreateGroup","iam:DeleteGroup"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//发送CreateUser请求，策略为NotAction且不在actions中，statement匹配，effect为deny，则请求失败
		String userName="createUserbyUser";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(403, result.first().intValue());
		System.out.print(result.second());
		JSONObject resultAssert=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("AccessDenied",resultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultAssert.get("Message"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(403, listresult.first().intValue());
		
		//发送GetUser请求，策略为NotAction且不在actions中，statement匹配，effect为deny，则请求失败		
		String bodyget="Action=GetUser&Version=2010-05-08";
		Pair<Integer, String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(403, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=IAMTestUtils.ParseErrorToJson(resultget.second());
		assertEquals("AccessDenied",resultgetAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+".",resultgetAssert.get("Message"));
		
		//发送DeleteUser请求，因为策略匹配，且为deny，Delete User失败
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(403, resultdel.first().intValue());
		System.out.println(resultdel.second());
		JSONObject resultdelAssert=IAMTestUtils.ParseErrorToJson(resultdel.second());
		assertEquals("AccessDenied",resultdelAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultdelAssert.get("Message"));

		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		
	}
	
	/**
	 * 1个策略1个statement，
	 * effect为Deny，Action,actions为CreateUser，GetUser，DeleteUser，ListGroupsForUser，设置resourceEffect为NotResource，Resource不为user匹配的资源，无condition
	 * 发送的请求与策略匹配，策略为Action，resource为匹配的资源,与Action匹配，与NotResource匹配，effect为deny，CreateUser，GetUser,DeleteUse失败
	 * **/
	
	@Test
	public void test_createGetDelListGroupsForUser_deny_match_notResource()throws Exception{
		//创建策略，NotAction，actions为CreateUser，GetUser，DeleteUser，ListGroupsForUser,Resource,resources=user/*,无condition
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Deny,policyName,"Action",Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:group/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//发送CreateUser请求，策略为NotResource且不在resource中，statement匹配，effect为deny，则请求失败
		String userName="createUserbyUser";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(403, result.first().intValue());
		System.out.print(result.second());
		JSONObject resultAssert=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("AccessDenied",resultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultAssert.get("Message"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(403, listresult.first().intValue());
		
		//发送GetUser请求，策略为NotResource且不在resource中，statement匹配，effect为deny，则请求失败		
		String bodyget="Action=GetUser&Version=2010-05-08";
		Pair<Integer, String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(403, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=IAMTestUtils.ParseErrorToJson(resultget.second());
		assertEquals("AccessDenied",resultgetAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+".",resultgetAssert.get("Message"));
		
		//发送DeleteUser请求，因为策略匹配，且为deny，Delete User失败
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(403, resultdel.first().intValue());
		System.out.println(resultdel.second());
		JSONObject resultdelAssert=IAMTestUtils.ParseErrorToJson(resultdel.second());
		assertEquals("AccessDenied",resultdelAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultdelAssert.get("Message"));

		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		
	}
	
	/**
	 * 1个策略1个statement，
	 * effect为Deny，NotAction,actions为CreateUser，GetUser，DeleteUser，ListGroupsForUser，设置resourceEffect为NotResource，Resource不为user匹配的资源，无condition
	 * 发送的请求与策略匹配，策略为NotAction，resource为匹配的资源,与NotAction匹配，与NotResource匹配，effect为deny，CreateUser，GetUser,DeleteUse失败
	 * **/
	@Test
	public void test_createGetDelListGroupsForUser_deny_match_notActionNotResource()throws Exception{
		//创建策略，NotAction，actions为CreateGroup,DeleteGroup,Resource,resources=user/*,无condition
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Deny,policyName,"NotAction",Arrays.asList("iam:CreateGroup","iam:DeleteGroup"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:group/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//发送CreateUser请求，与statement匹配，effect为deny，则请求失败
		String userName="createUserbyUser";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(403, result.first().intValue());
		System.out.print(result.second());
		JSONObject resultAssert=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("AccessDenied",resultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultAssert.get("Message"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(403, listresult.first().intValue());
		
		//发送GetUser请求，与statement匹配，effect为deny，则请求失败		
		String bodyget="Action=GetUser&Version=2010-05-08";
		Pair<Integer, String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(403, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=IAMTestUtils.ParseErrorToJson(resultget.second());
		assertEquals("AccessDenied",resultgetAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+".",resultgetAssert.get("Message"));
		
		//发送DeleteUser请求，因为策略匹配，且为deny，Delete User失败
		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(403, resultdel.first().intValue());
		System.out.println(resultdel.second());
		JSONObject resultdelAssert=IAMTestUtils.ParseErrorToJson(resultdel.second());
		assertEquals("AccessDenied",resultdelAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultdelAssert.get("Message"));

		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		
	}
	
	/**
	 * 1个策略1个statement，
	 * effect为Deny，Action,actions为CreateGroup,DeleteGroup，设置resourceEffect为Resource，Resource为user匹配的资源，condition匹配
	 * 发送的请求与策略匹配，策略为Action，resource为匹配的资源,与Action匹配，与resources匹配，effect为Deny，CreateUser，GetUser,DeleteUse失败
	 * **/
	@Test
	public void test_createGetDelListGroupsForUser_deny_match_condition()throws Exception{
		//创建策略，NotAction，actions为CreateGroup，DeleteGroup,Resource,resources=user/*,condition
		String policyName="createPolicyFormatch";
		List<Condition> conditions = new ArrayList<Condition>();
	    conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test01*")));	
		createPolicy(Effect.Deny,policyName,"Action",Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),conditions);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		String userName="createUserbyUser";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body, userak1, usersk1);
		assertEquals(403, result.first().intValue());
		System.out.print(result.second());
		JSONObject resultAssert=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("AccessDenied",resultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultAssert.get("Message"));
			
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(403, listresult.first().intValue());
		
		String bodyget="Action=GetUser&Version=2010-05-08";
		Pair<Integer, String> resultget=IAMTestUtils.invokeHttpsRequest(bodyget, userak1, usersk1);
		assertEquals(403, resultget.first().intValue());
		System.out.println(resultget.second());
		JSONObject resultgetAssert=IAMTestUtils.ParseErrorToJson(resultget.second());
		assertEquals("AccessDenied",resultgetAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+".",resultgetAssert.get("Message"));

		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(403, resultdel.first().intValue());
		System.out.println(resultdel.second());
		JSONObject resultdelAssert=IAMTestUtils.ParseErrorToJson(resultdel.second());
		assertEquals("AccessDenied",resultdelAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultdelAssert.get("Message"));

		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		
	}	
	
	/**
	 * effect为Deny，Action,actions为CreateUser，GetUser，DeleteUser，ListGroupsForUser，设置resourceEffect为Resource，Resource为user匹配的资源
	 * deny策略condition不匹配，只有一条不匹配的deny策略，隐式拒绝
	 * 给user添加allow策略且策略为允许create/get/delUser，存在deny和allow两种策略的情况下，deny优先allow，如果deny不匹配，验证allow，如果allow匹配且允许用户创建/获取/删除User，则create/get/delUser成功
	 * **/
	@Test
	public void test_createGetDelListGroupsForUser_deny_notMatch_condition()throws Exception{
		String userName="createUserbyUser";
		//创建策略，Action，actions为CreateUser，GetUser，DeleteUser，ListGroupsForUser,Resource,resources为user/*,condition不匹配
		String policyName="createPolicyFormatchdeny";
		List<Condition> conditions = new ArrayList<Condition>();
	    conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("TEST01*")));
		List<String> actions=Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser");
		List<String> resources=Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*");
		createPolicy(Effect.Deny,policyName,"Action",actions,"Resource",resources,conditions);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		//只有一条不匹配的deny策略，此时隐式拒绝create/get/delUser
		String createUserResult=IAMInterfaceTestUtils.CreateUser(userak1, usersk1, userName, 403);		
		System.out.print(createUserResult);
		JSONObject resultcreateAssert=IAMTestUtils.ParseErrorToJson(createUserResult);
		assertEquals("AccessDenied",resultcreateAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultcreateAssert.get("Message"));
		
		String listbody="Action=ListGroupsForUser&Version=2010-05-08&UserName="+URLEncoder.encode(userName);
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(listbody, userak1, usersk1);
		assertEquals(403, listresult.first().intValue());
		
		String getuserResult=IAMInterfaceTestUtils.GetUser(userak1, usersk1, userName,403);
		System.out.println(getuserResult);
		JSONObject getresultAssert=IAMTestUtils.ParseErrorToJson(getuserResult);
		assertEquals("AccessDenied",getresultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",getresultAssert.get("Message"));
		
		String deluserResult=IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 403);
		System.out.println(deluserResult);
		JSONObject delresultAssert=IAMTestUtils.ParseErrorToJson(deluserResult);
		assertEquals("AccessDenied",delresultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",delresultAssert.get("Message"));

		//添加allow策略，允许create/get/delUser
		String policyName2="testforAllowAfterDeny";
		String policyArn2=attacheUserallowedPolicy_allow(userName1,policyName2,actions,resources);

		String createResult=IAMInterfaceTestUtils.CreateUser(userak1, usersk1, userName, 200);		
		JSONObject createAssert=ParseXmlToJson("CreateUser",createResult);
		assertEquals(userName,createAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,createAssert.get("Arn"));
		assertNotNull(createAssert.get("UserId"));
		
		String listresult2=IAMInterfaceTestUtils.ListGroupsForUser(userak1, usersk1, userName, 200);
		
		String getResult=IAMInterfaceTestUtils.GetUser(userak1, usersk1, userName,200);
		JSONObject getResultAssert=ParseXmlToJson("GetUser",getResult);
		assertEquals(userName,getResultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,getResultAssert.get("Arn"));

		String delResult=IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		System.out.println(delResult);
		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		detachPolicyFromUser(userName1,policyArn2);
		
	}
	
	/**
	 * effect为Deny，Action,actions为Create，Get,Delete，设置resourceEffect为Resource，Resource为user匹配的资源
	 * deny策略actions不匹配，只有一条不匹配的deny策略，隐式拒绝
	 * 给user添加allow策略且策略为允许create/get/delUser，存在deny和allow两种策略的情况下，deny优先allow，如果deny不匹配，验证allow，如果allow匹配且允许用户创建/获取/删除User，则create/get/delUser成功
	 * **/
	
	@Test
	public void test_createGetDelListGroupsForUser_deny_notMatch_actions()throws Exception{
		String userName="createUserbyUser";
		//创建策略，Action，actions为CreateUser，GetUser，DeleteUser，ListGroupsForUser,Resource,resources为user/*,condition不匹配
		String policyName="createPolicyFormatchdeny";
		List<Condition> conditions = new ArrayList<Condition>();
	    conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test01*")));
		List<String> actions=Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser");
		List<String> resources=Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*");
		createPolicy(Effect.Deny,policyName,"Action",Arrays.asList("iam:Create","iam:Delete","iam:Get"),"Resource",resources,conditions);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		//只有一条不匹配的deny策略，此时隐式拒绝create/get/delUser
		String createUserResult=IAMInterfaceTestUtils.CreateUser(userak1, usersk1, userName, 403);		
		System.out.print(createUserResult);
		JSONObject resultcreateAssert=IAMTestUtils.ParseErrorToJson(createUserResult);
		assertEquals("AccessDenied",resultcreateAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultcreateAssert.get("Message"));
		
		String listresult=IAMInterfaceTestUtils.ListGroupsForUser(userak1, usersk1, userName, 403);
		
		String getuserResult=IAMInterfaceTestUtils.GetUser(userak1, usersk1, userName,403);
		System.out.println(getuserResult);
		JSONObject getresultAssert=IAMTestUtils.ParseErrorToJson(getuserResult);
		assertEquals("AccessDenied",getresultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",getresultAssert.get("Message"));
		
		String deluserResult=IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 403);
		System.out.println(deluserResult);
		JSONObject delresultAssert=IAMTestUtils.ParseErrorToJson(deluserResult);
		assertEquals("AccessDenied",delresultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",delresultAssert.get("Message"));

		//添加allow策略，允许create/get/delUser
		String policyName2="testforAllowAfterDeny";
		String policyArn2=attacheUserallowedPolicy_allow(userName1,policyName2,actions,resources);

		String createResult=IAMInterfaceTestUtils.CreateUser(userak1, usersk1, userName, 200);		
		JSONObject createAssert=ParseXmlToJson("CreateUser",createResult);
		assertEquals(userName,createAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,createAssert.get("Arn"));
		assertNotNull(createAssert.get("UserId"));
		
		String listresult2=IAMInterfaceTestUtils.ListGroupsForUser(userak1, usersk1, userName, 200);
		
		String getResult=IAMInterfaceTestUtils.GetUser(userak1, usersk1, userName,200);
		JSONObject getResultAssert=ParseXmlToJson("GetUser",getResult);
		assertEquals(userName,getResultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,getResultAssert.get("Arn"));

		String delResult=IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		System.out.println(delResult);
		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		detachPolicyFromUser(userName1,policyArn2);
		
	}
	
	/**
	 * effect为Deny，Action,actions为CreateUser，GetUser，DeleteUser，ListGroupsForUser，设置resourceEffect为Resource，Resource为user匹配的资源
	 * deny策略resources不匹配，只有一条不匹配的deny策略，隐式拒绝
	 * 给user添加allow策略且策略为允许create/get/delUser，存在deny和allow两种策略的情况下，deny优先allow，如果deny不匹配，验证allow，如果allow匹配且允许用户创建/获取/删除User，则create/get/delUser成功
	 * **/
	
	@Test
	public void test_createGetDelListGroupsForUser_deny_notMatch_resource()throws Exception{
		String userName="createUserbyUser";
		//创建策略，Action，actions为CreateUser，GetUser，DeleteUser，ListGroupsForUser,Resource,resources为user/userName
		String policyName="createPolicyFormatchdeny";
		List<Condition> conditions = new ArrayList<Condition>();
	    conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test01*")));
		List<String> actions=Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser");
		List<String> resources=Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*");
		createPolicy(Effect.Deny,policyName,"Action",actions,"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/"+userName3),conditions);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		//只有一条不匹配的deny策略，此时隐式拒绝create/get/delUser
		String createUserResult=IAMInterfaceTestUtils.CreateUser(userak1, usersk1, userName, 403);		
		System.out.print(createUserResult);
		JSONObject resultcreateAssert=IAMTestUtils.ParseErrorToJson(createUserResult);
		assertEquals("AccessDenied",resultcreateAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultcreateAssert.get("Message"));
		
		String listresult=IAMInterfaceTestUtils.ListGroupsForUser(userak1, usersk1, userName, 403);
		
		String getuserResult=IAMInterfaceTestUtils.GetUser(userak1, usersk1, userName,403);
		System.out.println(getuserResult);
		JSONObject getresultAssert=IAMTestUtils.ParseErrorToJson(getuserResult);
		assertEquals("AccessDenied",getresultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",getresultAssert.get("Message"));
		
		String deluserResult=IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 403);
		System.out.println(deluserResult);
		JSONObject delresultAssert=IAMTestUtils.ParseErrorToJson(deluserResult);
		assertEquals("AccessDenied",delresultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",delresultAssert.get("Message"));

		//添加allow策略，允许create/get/delUser
		String policyName2="testforAllowAfterDeny";
		String policyArn2=attacheUserallowedPolicy_allow(userName1,policyName2,actions,resources);

		String createResult=IAMInterfaceTestUtils.CreateUser(userak1, usersk1, userName, 200);		
		JSONObject createAssert=ParseXmlToJson("CreateUser",createResult);
		assertEquals(userName,createAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,createAssert.get("Arn"));
		assertNotNull(createAssert.get("UserId"));
		
		String listresult2=IAMInterfaceTestUtils.ListGroupsForUser(userak1, usersk1, userName, 200);
		
		String getResult=IAMInterfaceTestUtils.GetUser(userak1, usersk1, userName,200);
		JSONObject getResultAssert=ParseXmlToJson("GetUser",getResult);
		assertEquals(userName,getResultAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName,getResultAssert.get("Arn"));

		String delResult=IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		System.out.println(delResult);
		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		detachPolicyFromUser(userName1,policyArn2);
		
	}	
	
	/**
	 * effect为Deny，Action,actions为CreateUser，GetUser，DeleteUser，ListGroupsForUser，设置resourceEffect为Resource，Resource为user匹配的资源
	 * deny策略condition不匹配，只有一条不匹配的deny策略，隐式拒绝
	 * 给user添加allow策略且策略为允许create/get/delUser，存在deny和allow两种策略的情况下，deny优先allow，如果deny不匹配，验证allow，如果allow不匹配则不允许用户创建/获取/删除User
	 * **/
	@Test
	public void test_createGetDelListGroupsForUser_deny_notMatch_notAllowed()throws Exception{
		String userName="createUserbyUser";
		//创建策略，Action，actions为CreateUser，GetUser，DeleteUser，ListGroupsForUser,Resource,resources为user/*,condition不匹配
		String policyName="createPolicyFormatchdeny";
		List<Condition> conditions = new ArrayList<Condition>();
	    conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("TEST01*")));
		List<String> actions=Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser");
		List<String> resources=Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*");
		createPolicy(Effect.Deny,policyName,"Action",actions,"Resource",resources,conditions);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		//只有一条不匹配的deny策略，此时隐式拒绝create/get/delUser
		String createUserResult=IAMInterfaceTestUtils.CreateUser(userak1, usersk1, userName, 403);		
		System.out.print(createUserResult);
		JSONObject resultcreateAssert=IAMTestUtils.ParseErrorToJson(createUserResult);
		assertEquals("AccessDenied",resultcreateAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultcreateAssert.get("Message"));
		
		String listresult=IAMInterfaceTestUtils.ListGroupsForUser(userak1, usersk1, userName, 403);
		
		String getuserResult=IAMInterfaceTestUtils.GetUser(userak1, usersk1, userName,403);
		System.out.println(getuserResult);
		JSONObject getresultAssert=IAMTestUtils.ParseErrorToJson(getuserResult);
		assertEquals("AccessDenied",getresultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",getresultAssert.get("Message"));
		
		String deluserResult=IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 403);
		System.out.println(deluserResult);
		JSONObject delresultAssert=IAMTestUtils.ParseErrorToJson(deluserResult);
		assertEquals("AccessDenied",delresultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",delresultAssert.get("Message"));

		//添加allow策略，但策略不匹配，隐式拒绝
		String policyName2="testforDeny";
		String policyArn2=attacheUserallowedPolicy_deny(userName1,policyName2);

		String createResult=IAMInterfaceTestUtils.CreateUser(userak1, usersk1, userName, 403);		
		System.out.print(createResult);
		JSONObject createAssert=IAMTestUtils.ParseErrorToJson(createResult);
		assertEquals("AccessDenied",createAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",createAssert.get("Message"));
		
		String getResult=IAMInterfaceTestUtils.GetUser(userak1, usersk1, userName,403);
		System.out.println(getResult);
		JSONObject getAssert=IAMTestUtils.ParseErrorToJson(getResult);
		assertEquals("AccessDenied",getAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",getAssert.get("Message"));
		
		String listresult2=IAMInterfaceTestUtils.ListGroupsForUser(userak1, usersk1, userName, 403);
		
		String delResult=IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 403);
		System.out.println(delResult);
		JSONObject delAssert=IAMTestUtils.ParseErrorToJson(delResult);
		assertEquals("AccessDenied",delAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",delAssert.get("Message"));

		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		detachPolicyFromUser(userName1,policyArn2);
		
	}	
	
		
	
	/**
	 * effect为Deny，Action,actions为CreateUser，GetUser，DeleteUser，ListGroupsForUser，设置resourceEffect为Resource，Resource为user匹配的资源，condition匹配
	 * 发送的请求与策略匹配，策略为Action，resource为匹配的资源,拒绝用户CreateUser，GetUser，DeleteUser，ListGroupsForUser操作，用户CreateUser，GetUser，DeleteUser，ListGroupsForUser失败
	 * 
	 * 给user添加allow策略且策略为不允许create/get/delUser，存在deny和allow两种策略的情况下，allow策略生效，用户无创建/获取/删除User权限
	 * **/
	
	
	
	/**
	 * 1个策略1个statement，
	 * effect为allow，Action,actions为允许TagUser，UntagUser，ListUserTags，设置resourceEffect为允许，无condition
	 * 发送请求与策略匹配，用户可以TagUser，UntagUser，ListUserTags
	 * **/
	
	@Test
	public void test_tagUntagListUserTags_allow_match()throws Exception{
		//用户有创建获取删除用户的权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName2,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		String userName02="createbyuser02";
		createUser(userName02,userak2,usersk2);
				
		//创建策略，Action，actions为TagUser，UntagUser，ListUserTags,Resource,resources=user/*,无condition
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:TagUser","iam:UntagUser","iam:ListUserTags"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		

		List<Pair<String, String>> tags=new ArrayList<>();
		Pair<String,String> tag1=new Pair<>();
		tag1.first("tag1Key");
		tag1.second("tag1Value");
		Pair<String,String> tag2=new Pair<>();
		tag2.first("tag2Key");
		tag2.second("tag2Value");
		tags.add(tag1);
		tags.add(tag2);
			
		//发送TagUser请求，因与策略匹配，TagUser成功
		String result=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 200);
		
		//发送ListUserTags请求，因与策略匹配，ListUserTags成功		
		String listtagsResult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 200);		
		System.out.println(listtagsResult);

		//发送UntagUser请求，因为策略匹配，UntagUser成功
		List<String> tagKeys=new ArrayList<>();
		tagKeys.add(tag1.first());
		tagKeys.add(tag2.first());
		String untagUserResult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 200);	
		
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		//user2有添加tag的权限
		String tagUserResult=IAMInterfaceTestUtils.TagUser(userak2, usersk2, userName02, tags, 200);		
		
		//user2有获取用户tags的权限		
		String listtageResult=IAMInterfaceTestUtils.ListUserTags(userak2, usersk2, userName02,200);
		System.out.println(listtageResult);
		
		//user2有删除用户的tags权限
		String untagResult=IAMInterfaceTestUtils.UntagUser(userak2, usersk2, userName02,tagKeys, 200);

		//删除创建的用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName02, 200);
		//移除用户中的策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName2, policyName1, 200);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);

	}
	
	/**
	 * resource=user/userName，不为设定userName的拒绝
	 * */
	@Test
	public void test_tagUntagListUserTags_allow_match_userName()throws Exception{
		//用户有创建获取删除用户的权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName2,policyName1);
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName3,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		String userName02="createbyuser02";
		createUser(userName02,userak2,usersk2);
		String userName03="createbyuser03";
		createUser(userName03,userak3,usersk3);
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:TagUser","iam:UntagUser","iam:ListUserTags"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/"+userName,"arn:ctyun:iam::0000000gc0uy9:user/"+userName02),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);

		List<Pair<String, String>> tags=new ArrayList<>();
		Pair<String,String> tag1=new Pair<>();
		tag1.first("tag1Key");
		tag1.second("tag1Value");
		Pair<String,String> tag2=new Pair<>();
		tag2.first("tag2Key");
		tag2.second("tag2Value");
		tags.add(tag1);
		tags.add(tag2);
			
		//发送TagUser请求，因与策略匹配，TagUser成功
		String result=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 200);
		
		//发送ListUserTags请求，因与策略匹配，ListUserTags成功		
		String listtagsResult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 200);		
		System.out.println(listtagsResult);

		//发送UntagUser请求，因为策略匹配，UntagUser成功
		List<String> tagKeys=new ArrayList<>();
		tagKeys.add(tag1.first());
		tagKeys.add(tag2.first());
		String untagUserResult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 200);	
		
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		//user2有添加tag的权限
		String tagUserResult=IAMInterfaceTestUtils.TagUser(userak2, usersk2, userName02, tags, 200);		
		
		//user2有获取用户tags的权限		
		String listtageResult=IAMInterfaceTestUtils.ListUserTags(userak2, usersk2, userName02,200);
		System.out.println(listtageResult);
		
		//user2有删除用户的tags权限
		String untagResult=IAMInterfaceTestUtils.UntagUser(userak2, usersk2, userName02,tagKeys, 200);

		//user3添加策略，但是resource不符合，拒绝
		attachPolicyToUser(userName3,policyArn);
		String tagUserResult3=IAMInterfaceTestUtils.TagUser(userak3, usersk3, userName03, tags, 403);
		System.out.println(tagUserResult3);
		String listtageResult3=IAMInterfaceTestUtils.ListUserTags(userak3, usersk3, userName03,403);
		System.out.println(listtageResult3);
		String untagResult3=IAMInterfaceTestUtils.UntagUser(userak3, usersk3, userName03,tagKeys, 403);
		System.out.println(untagResult3);
		
		//删除创建的用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 200);
		IAMInterfaceTestUtils.DeleteUser(userak3, usersk3, userName03, 200);
		//移除用户中的策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName2, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName3, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName3, policyName, 200);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
	}	
	
	/**
	 * resource=*
	 * */
	@Test
	public void test_tagUntagListUserTags_allow_match_all()throws Exception{
		//用户有创建获取删除用户的权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName2,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		String userName02="createbyuser02";
		createUser(userName02,userak2,usersk2);
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:TagUser","iam:UntagUser","iam:ListUserTags"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);

		List<Pair<String, String>> tags=new ArrayList<>();
		Pair<String,String> tag1=new Pair<>();
		tag1.first("tag1Key");
		tag1.second("tag1Value");
		Pair<String,String> tag2=new Pair<>();
		tag2.first("tag2Key");
		tag2.second("tag2Value");
		tags.add(tag1);
		tags.add(tag2);
			
		//发送TagUser请求，因与策略匹配，TagUser成功
		String result=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 200);
		
		//发送ListUserTags请求，因与策略匹配，ListUserTags成功		
		String listtagsResult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 200);		
		System.out.println(listtagsResult);

		//发送UntagUser请求，因为策略匹配，UntagUser成功
		List<String> tagKeys=new ArrayList<>();
		tagKeys.add(tag1.first());
		tagKeys.add(tag2.first());
		String untagUserResult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 200);	
		
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		//user2有添加tag的权限
		String tagUserResult=IAMInterfaceTestUtils.TagUser(userak2, usersk2, userName02, tags, 200);		
		
		//user2有获取用户tags的权限		
		String listtageResult=IAMInterfaceTestUtils.ListUserTags(userak2, usersk2, userName02,200);
		System.out.println(listtageResult);
		
		//user2有删除用户的tags权限
		String untagResult=IAMInterfaceTestUtils.UntagUser(userak2, usersk2, userName02,tagKeys, 200);

		//删除创建的用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 200);
		//移除用户中的策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName2, policyName1, 200);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
	}

	/**
	 * ActionEffect为NotAction
	 * */
	@Test
	public void test_tagUntagListUserTags_allow_match_NotAction()throws Exception{
		//用户有创建获取删除用户的权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName2,policyName1);
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName3,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		String userName02="createbyuser02";
		createUser(userName02,userak2,usersk2);
		
		String userName03="createbyuser03";
		createUser(userName03,userak3,usersk3);
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:GetUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		attachPolicyToUser(userName3,policyArn);

		List<Pair<String, String>> tags=new ArrayList<>();
		Pair<String,String> tag1=new Pair<>();
		tag1.first("tag1Key");
		tag1.second("tag1Value");
		Pair<String,String> tag2=new Pair<>();
		tag2.first("tag2Key");
		tag2.second("tag2Value");
		tags.add(tag1);
		tags.add(tag2);
			
		//发送TagUser请求，因与策略匹配，TagUser成功
		String result=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 200);
		
		//发送ListUserTags请求，因与策略匹配，ListUserTags成功		
		String listtagsResult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 200);		
		System.out.println(listtagsResult);

		//发送UntagUser请求，因为策略匹配，UntagUser成功
		List<String> tagKeys=new ArrayList<>();
		tagKeys.add(tag1.first());
		tagKeys.add(tag2.first());
		String untagUserResult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 200);	
		
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		//user2有添加tag的权限
		String tagUserResult=IAMInterfaceTestUtils.TagUser(userak2, usersk2, userName02, tags, 200);		
		
		//user2有获取用户tags的权限		
		String listtageResult=IAMInterfaceTestUtils.ListUserTags(userak2, usersk2, userName02,200);
		System.out.println(listtageResult);
		
		//user2有删除用户的tags权限
		String untagResult=IAMInterfaceTestUtils.UntagUser(userak2, usersk2, userName02,tagKeys, 200);
		
		//user3getUser失败
		String getuserResult=IAMInterfaceTestUtils.GetUser(userak3, userak3, userName03, 403);

		//删除创建的用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 200);
		IAMInterfaceTestUtils.DeleteUser(userak3, usersk3, userName03, 200);
		//移除用户中的策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName2, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName3, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName3, policyName, 200);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
	}	
	
	/**
	 * ActionEffect为NotAction
	 * */
	@Test
	public void test_tagUntagListUserTags_allow_match_NotAction_userName()throws Exception{
		//用户有创建获取删除用户的权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName2,policyName1);
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName3,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		String userName02="createbyuser02";
		createUser(userName02,userak2,usersk2);
		
		String userName03="createbyuser03";
		createUser(userName03,userak3,usersk3);
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:GetUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/"+userName,"arn:ctyun:iam::0000000gc0uy9:user/"+userName02),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		attachPolicyToUser(userName3,policyArn);

		List<Pair<String, String>> tags=new ArrayList<>();
		Pair<String,String> tag1=new Pair<>();
		tag1.first("tag1Key");
		tag1.second("tag1Value");
		Pair<String,String> tag2=new Pair<>();
		tag2.first("tag2Key");
		tag2.second("tag2Value");
		tags.add(tag1);
		tags.add(tag2);
			
		//发送TagUser请求，因与策略匹配，TagUser成功
		String result=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 200);
		
		//发送ListUserTags请求，因与策略匹配，ListUserTags成功		
		String listtagsResult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 200);		
		System.out.println(listtagsResult);

		//发送UntagUser请求，因为策略匹配，UntagUser成功
		List<String> tagKeys=new ArrayList<>();
		tagKeys.add(tag1.first());
		tagKeys.add(tag2.first());
		String untagUserResult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 200);	
		
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		//user2有添加tag的权限
		String tagUserResult=IAMInterfaceTestUtils.TagUser(userak2, usersk2, userName02, tags, 200);		
		
		//user2有获取用户tags的权限		
		String listtageResult=IAMInterfaceTestUtils.ListUserTags(userak2, usersk2, userName02,200);
		System.out.println(listtageResult);
		
		//user2有删除用户的tags权限
		String untagResult=IAMInterfaceTestUtils.UntagUser(userak2, usersk2, userName02,tagKeys, 200);
		
		//user3匹配NotAction但是无resource权限
		String taguserResult=IAMInterfaceTestUtils.TagUser(userak3, userak3, userName03, tags,403);
		String listTagsResult=IAMInterfaceTestUtils.ListUserTags(userak3, usersk3, userName03, 403);
		String untagresult=IAMInterfaceTestUtils.UntagUser(userak3, usersk3, userName03, tagKeys, 403);
		

		//删除创建的用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 200);
		IAMInterfaceTestUtils.DeleteUser(userak3, usersk3, userName03, 200);
		//移除用户中的策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName2, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName3, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName3, policyName, 200);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
	}	
	
	/**
	 * ActionEffect为NotAction
	 * */
	@Test
	public void test_tagUntagListUserTags_allow_match_NotAction_all()throws Exception{
		//用户有创建获取删除用户的权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName2,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		String userName02="createbyuser02";
		createUser(userName02,userak2,usersk2);
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:GetUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);

		List<Pair<String, String>> tags=new ArrayList<>();
		Pair<String,String> tag1=new Pair<>();
		tag1.first("tag1Key");
		tag1.second("tag1Value");
		Pair<String,String> tag2=new Pair<>();
		tag2.first("tag2Key");
		tag2.second("tag2Value");
		tags.add(tag1);
		tags.add(tag2);
			
		//发送TagUser请求，因与策略匹配，TagUser成功
		String result=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 200);
		
		//发送ListUserTags请求，因与策略匹配，ListUserTags成功		
		String listtagsResult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 200);		
		System.out.println(listtagsResult);

		//发送UntagUser请求，因为策略匹配，UntagUser成功
		List<String> tagKeys=new ArrayList<>();
		tagKeys.add(tag1.first());
		tagKeys.add(tag2.first());
		String untagUserResult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 200);	
		
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		//user2有添加tag的权限
		String tagUserResult=IAMInterfaceTestUtils.TagUser(userak2, usersk2, userName02, tags, 200);		
		
		//user2有获取用户tags的权限		
		String listtageResult=IAMInterfaceTestUtils.ListUserTags(userak2, usersk2, userName02,200);
		System.out.println(listtageResult);
		
		//user2有删除用户的tags权限
		String untagResult=IAMInterfaceTestUtils.UntagUser(userak2, usersk2, userName02,tagKeys, 200);
		

		//删除创建的用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 200);
		//移除用户中的策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName2, policyName1, 200);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
	}	
	
	/**
	 * ActionEffect为NotAction
	 * */
	@Test
	public void test_tagUntagListUserTags_allow_match_NotAction_deny()throws Exception{
		//用户有创建获取删除用户的权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName2,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		String userName02="createbyuser02";
		createUser(userName02,userak2,usersk2);
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:TagUser","iam:UntagUser","iam:ListUserTags"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);

		List<Pair<String, String>> tags=new ArrayList<>();
		Pair<String,String> tag1=new Pair<>();
		tag1.first("tag1Key");
		tag1.second("tag1Value");
		Pair<String,String> tag2=new Pair<>();
		tag2.first("tag2Key");
		tag2.second("tag2Value");
		tags.add(tag1);
		tags.add(tag2);
			
		//发送TagUser请求，因与策略匹配，TagUser失败
		String result=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 403);
		
		//发送ListUserTags请求，因与策略匹配，ListUserTags失败		
		String listtagsResult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 403);		
		System.out.println(listtagsResult);

		//发送UntagUser请求，因为策略匹配，UntagUser失败
		List<String> tagKeys=new ArrayList<>();
		tagKeys.add(tag1.first());
		tagKeys.add(tag2.first());
		String untagUserResult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 403);	
		
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		//user2无添加tag的权限
		String tagUserResult=IAMInterfaceTestUtils.TagUser(userak2, usersk2, userName02, tags, 403);		
		
		//user2无获取用户tags的权限		
		String listtageResult=IAMInterfaceTestUtils.ListUserTags(userak2, usersk2, userName02,403);
		System.out.println(listtageResult);
		
		//user2无删除用户的tags权限
		String untagResult=IAMInterfaceTestUtils.UntagUser(userak2, usersk2, userName02,tagKeys, 403);
		
		//删除创建的用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 200);
		//移除用户中的策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName2, policyName1, 200);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
	}
	

	/**
	 * ResourceEffect为NotResource
	 * */
	@Test
	public void test_tagUntagListUserTags_allow_match_NotResource()throws Exception{
		//用户有创建获取删除用户的权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName2,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		String userName02="createbyuser02";
		createUser(userName02,userak2,usersk2);
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:TagUser","iam:UntagUser","iam:ListUserTags"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:group/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);

		List<Pair<String, String>> tags=new ArrayList<>();
		Pair<String,String> tag1=new Pair<>();
		tag1.first("tag1Key");
		tag1.second("tag1Value");
		Pair<String,String> tag2=new Pair<>();
		tag2.first("tag2Key");
		tag2.second("tag2Value");
		tags.add(tag1);
		tags.add(tag2);
			
		//发送TagUser请求，因与策略匹配，TagUser成功
		String result=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 200);
		
		//发送ListUserTags请求，因与策略匹配，ListUserTags成功		
		String listtagsResult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 200);		
		System.out.println(listtagsResult);

		//发送UntagUser请求，因为策略匹配，UntagUser成功
		List<String> tagKeys=new ArrayList<>();
		tagKeys.add(tag1.first());
		tagKeys.add(tag2.first());
		String untagUserResult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 200);	
		
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		//user2有添加tag的权限
		String tagUserResult=IAMInterfaceTestUtils.TagUser(userak2, usersk2, userName02, tags, 200);		
		
		//user2有获取用户tags的权限		
		String listtageResult=IAMInterfaceTestUtils.ListUserTags(userak2, usersk2, userName02,200);
		System.out.println(listtageResult);
		
		//user2有删除用户的tags权限
		String untagResult=IAMInterfaceTestUtils.UntagUser(userak2, usersk2, userName02,tagKeys, 200);
		
		//删除创建的用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 200);
		//移除用户中的策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName2, policyName1, 200);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
	}	
		
	/**
	 * ResourceEffect为NotResource
	 * */
	@Test
	public void test_tagUntagListUserTags_allow_match_NotResource_userName()throws Exception{
		//用户有创建获取删除用户的权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName2,policyName1);
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName3,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		String userName02="createbyuser02";
		createUser(userName02,userak2,usersk2);
		String userName03="createbyuser03";
		createUser(userName03,userak3,usersk3);
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:TagUser","iam:UntagUser","iam:ListUserTags"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/"+userName03),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		attachPolicyToUser(userName3,policyArn);

		List<Pair<String, String>> tags=new ArrayList<>();
		Pair<String,String> tag1=new Pair<>();
		tag1.first("tag1Key");
		tag1.second("tag1Value");
		Pair<String,String> tag2=new Pair<>();
		tag2.first("tag2Key");
		tag2.second("tag2Value");
		tags.add(tag1);
		tags.add(tag2);
			
		//发送TagUser请求，因与策略匹配，TagUser成功
		String result=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 200);
		
		//发送ListUserTags请求，因与策略匹配，ListUserTags成功		
		String listtagsResult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 200);		
		System.out.println(listtagsResult);

		//发送UntagUser请求，因为策略匹配，UntagUser成功
		List<String> tagKeys=new ArrayList<>();
		tagKeys.add(tag1.first());
		tagKeys.add(tag2.first());
		String untagUserResult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 200);	
		
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		//user2有添加tag的权限
		String tagUserResult=IAMInterfaceTestUtils.TagUser(userak2, usersk2, userName02, tags, 200);		
		
		//user2有获取用户tags的权限		
		String listtageResult=IAMInterfaceTestUtils.ListUserTags(userak2, usersk2, userName02,200);
		System.out.println(listtageResult);
		
		//user2有删除用户的tags权限
		String untagResult=IAMInterfaceTestUtils.UntagUser(userak2, usersk2, userName02,tagKeys, 200);
		
		//user3无权限
		String taguserResult=IAMInterfaceTestUtils.TagUser(userak3, usersk3, userName03, tags, 403);
		String listTageResult=IAMInterfaceTestUtils.ListUserTags(userak3, usersk3, userName03,403);
		String untagresult=IAMInterfaceTestUtils.UntagUser(userak3, usersk3, userName03, tagKeys, 403);
		
		//删除创建的用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 200);
		IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName03, 200);
		//移除用户中的策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName2, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName3, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName3, policyName, 200);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
	}
		
	/**
	 * ResourceEffect为NotResource
	 * */
	@Test
	public void test_tagUntagListUserTags_allow_match_NotResource_all()throws Exception{
		//用户有创建获取删除用户的权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName2,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		String userName02="createbyuser02";
		createUser(userName02,userak2,usersk2);
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:TagUser","iam:UntagUser","iam:ListUserTags"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);

		List<Pair<String, String>> tags=new ArrayList<>();
		Pair<String,String> tag1=new Pair<>();
		tag1.first("tag1Key");
		tag1.second("tag1Value");
		Pair<String,String> tag2=new Pair<>();
		tag2.first("tag2Key");
		tag2.second("tag2Value");
		tags.add(tag1);
		tags.add(tag2);
			
		//发送TagUser请求，因与策略匹配，TagUser失败
		String result=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 403);
	
		String listtagsResult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 403);		
		System.out.println(listtagsResult);

		//发送UntagUser请求，因为策略匹配，UntagUser失败
		List<String> tagKeys=new ArrayList<>();
		tagKeys.add(tag1.first());
		tagKeys.add(tag2.first());
		String untagUserResult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 403);	
		
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		//user2无添加tag的权限
		String tagUserResult=IAMInterfaceTestUtils.TagUser(userak2, usersk2, userName02, tags, 403);		
		
		//user2无获取用户tags的权限		
		String listtageResult=IAMInterfaceTestUtils.ListUserTags(userak2, usersk2, userName02,403);
		System.out.println(listtageResult);
		
		//user2无删除用户的tags权限
		String untagResult=IAMInterfaceTestUtils.UntagUser(userak2, usersk2, userName02,tagKeys, 403);
		
		//删除创建的用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 200);
		//移除用户中的策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName2, policyName1, 200);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
	}	
	
	/**
	 * ResourceEffect为NotResource
	 * */
	@Test
	public void test_tagUntagListUserTags_allow_match_NotResource_user()throws Exception{
		//用户有创建获取删除用户的权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName2,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		String userName02="createbyuser02";
		
		createUser(userName02,userak2,usersk2);
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:TagUser","iam:UntagUser","iam:ListUserTags"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);

		List<Pair<String, String>> tags=new ArrayList<>();
		Pair<String,String> tag1=new Pair<>();
		tag1.first("tag1Key");
		tag1.second("tag1Value");
		Pair<String,String> tag2=new Pair<>();
		tag2.first("tag2Key");
		tag2.second("tag2Value");
		tags.add(tag1);
		tags.add(tag2);
			
		//发送TagUser请求，因与策略匹配，TagUser失败
		String result=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 403);
	
		String listtagsResult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 403);		
		System.out.println(listtagsResult);

		//发送UntagUser请求，因为策略匹配，UntagUser失败
		List<String> tagKeys=new ArrayList<>();
		tagKeys.add(tag1.first());
		tagKeys.add(tag2.first());
		String untagUserResult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 403);	
		
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		//user2无添加tag的权限
		String tagUserResult=IAMInterfaceTestUtils.TagUser(userak2, usersk2, userName02, tags, 403);		
		
		//user2无获取用户tags的权限		
		String listtageResult=IAMInterfaceTestUtils.ListUserTags(userak2, usersk2, userName02,403);
		System.out.println(listtageResult);
		
		//user2无删除用户的tags权限
		String untagResult=IAMInterfaceTestUtils.UntagUser(userak2, usersk2, userName02,tagKeys, 403);
		
		//删除创建的用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 200);
		//移除用户中的策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName2, policyName1, 200);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
	}	
	
	/**
	 * ActionEffect味NotAction，ResourceEffect为NotResource
	 * */
	@Test
	public void test_tagUntagListUserTags_allow_match_notActionNotResource()throws Exception{
		//用户有创建获取删除用户的权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName2,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		String userName02="createbyuser02";
		createUser(userName02,userak2,usersk2);
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:GetUser"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:group/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);

		List<Pair<String, String>> tags=new ArrayList<>();
		Pair<String,String> tag1=new Pair<>();
		tag1.first("tag1Key");
		tag1.second("tag1Value");
		Pair<String,String> tag2=new Pair<>();
		tag2.first("tag2Key");
		tag2.second("tag2Value");
		tags.add(tag1);
		tags.add(tag2);
			
		//发送TagUser请求，因与策略匹配，TagUser成功
		String result=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 200);
	
		String listtagsResult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 200);		
		System.out.println(listtagsResult);

		//发送UntagUser请求，因为策略匹配，UntagUser成功
		List<String> tagKeys=new ArrayList<>();
		tagKeys.add(tag1.first());
		tagKeys.add(tag2.first());
		String untagUserResult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 200);	
		
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		//user2有添加tag的权限
		String tagUserResult=IAMInterfaceTestUtils.TagUser(userak2, usersk2, userName02, tags, 200);		
		
		//user2有获取用户tags的权限		
		String listtageResult=IAMInterfaceTestUtils.ListUserTags(userak2, usersk2, userName02,200);
		System.out.println(listtageResult);
		
		//user2有删除用户的tags权限
		String untagResult=IAMInterfaceTestUtils.UntagUser(userak2, usersk2, userName02,tagKeys, 200);
		
		//删除创建的用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 200);
		//移除用户中的策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName2, policyName1, 200);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
	}
	
	/**
	 * ActionEffect为NotAction，ResourceEffect为NotResource
	 * 设置resource为user/userName，不满足resource为userName的请求成功，resource为userName的拒绝访问
	 * 满足actions中操作的，访问拒绝
	 * */
	@Test
	public void test_tagUntagListUserTags_allow_match_notActionNotResource_userName()throws Exception{
		//用户有创建获取删除用户的权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName2,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		String userName02="createbyuser02";
		createUser(userName02,userak2,usersk2);
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:GetUser"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/"+ userName02),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);

		List<Pair<String, String>> tags=new ArrayList<>();
		Pair<String,String> tag1=new Pair<>();
		tag1.first("tag1Key");
		tag1.second("tag1Value");
		Pair<String,String> tag2=new Pair<>();
		tag2.first("tag2Key");
		tag2.second("tag2Value");
		tags.add(tag1);
		tags.add(tag2);
			
		//发送TagUser请求，因与策略匹配，TagUser成功/失败
		String result=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 200);
		String result2=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName02, tags, 403);
	
		String listtagsResult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 200);	
		String listtagsResult2=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName02, 403);
		System.out.println(listtagsResult);

		//发送UntagUser请求，因为策略匹配，UntagUser成功/失败
		List<String> tagKeys=new ArrayList<>();
		tagKeys.add(tag1.first());
		tagKeys.add(tag2.first());
		String untagUserResult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 200);	
		String untagUserResult2=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName02, tagKeys, 403);
		
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		//user2有添加tag的权限
		String tagUserResult=IAMInterfaceTestUtils.TagUser(userak2, usersk2, userName, tags, 200);
		
		String tagUserResult2=IAMInterfaceTestUtils.TagUser(userak2, usersk2, userName02, tags, 403);
		
		//user2有获取用户tags的权限		
		String listtageResult=IAMInterfaceTestUtils.ListUserTags(userak2, usersk2, userName,200);
		
		String listtageResult2=IAMInterfaceTestUtils.ListUserTags(userak2, usersk2, userName02,403);
		
		//user2有删除用户的tags权限
		String untagResult=IAMInterfaceTestUtils.UntagUser(userak2, usersk2, userName,tagKeys, 200);
		
		String untagResult2=IAMInterfaceTestUtils.UntagUser(userak2, usersk2, userName02,tagKeys, 403);
		
		//user3添加策略，getUser失败
		attachPolicyToUser(userName3,policyArn);
		String getUserResult=IAMInterfaceTestUtils.GetUser(userak3, usersk3, userName, 403);
		
		//删除创建的用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 200);
		//移除用户中的策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName2, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName3, policyName, 200);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
	}	
	/***
	 * NotAction，NotResource，resource为user/*时，访问拒绝
	 * ***/
	@Test
	public void test_tagUntagListUserTags_allow_match_notActionNotResource_user()throws Exception{
		//用户有创建获取删除用户的权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:GetUser"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);

		List<Pair<String, String>> tags=new ArrayList<>();
		Pair<String,String> tag1=new Pair<>();
		tag1.first("tag1Key");
		tag1.second("tag1Value");
		Pair<String,String> tag2=new Pair<>();
		tag2.first("tag2Key");
		tag2.second("tag2Value");
		tags.add(tag1);
		tags.add(tag2);
			
		//发送TagUser请求，因与策略匹配，TagUser失败
		String result=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 403);
	
		String listtagsResult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 403);	
		System.out.println(listtagsResult);

		//发送UntagUser请求，因为策略匹配，UntagUser成功/失败
		List<String> tagKeys=new ArrayList<>();
		tagKeys.add(tag1.first());
		tagKeys.add(tag2.first());
		String untagUserResult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 403);	
		
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		//user2有添加tag的权限
		String tagUserResult=IAMInterfaceTestUtils.TagUser(userak2, usersk2, userName, tags, 403);
		
		//user2有获取用户tags的权限		
		String listtageResult=IAMInterfaceTestUtils.ListUserTags(userak2, usersk2, userName,403);
		
		//user2有删除用户的tags权限
		String untagResult=IAMInterfaceTestUtils.UntagUser(userak2, usersk2, userName,tagKeys, 403);
		
		//user3添加策略，getUser失败
		attachPolicyToUser(userName3,policyArn);
		String getUserResult=IAMInterfaceTestUtils.GetUser(userak3, usersk3, userName, 403);
		
		//删除创建的用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		//移除用户中的策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName2, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName3, policyName, 200);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
	}		
	
	/***
	 * NotAction，NotResource，resource为*时，访问拒绝
	 * ***/
	@Test
	public void test_tagUntagListUserTags_allow_match_notActionNotResource_all()throws Exception{
		//用户有创建获取删除用户的权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:GetUser"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);

		List<Pair<String, String>> tags=new ArrayList<>();
		Pair<String,String> tag1=new Pair<>();
		tag1.first("tag1Key");
		tag1.second("tag1Value");
		Pair<String,String> tag2=new Pair<>();
		tag2.first("tag2Key");
		tag2.second("tag2Value");
		tags.add(tag1);
		tags.add(tag2);
			
		//发送TagUser请求，因与策略匹配，TagUser失败
		String result=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 403);
	
		String listtagsResult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 403);	
		System.out.println(listtagsResult);

		//发送UntagUser请求，因为策略匹配，UntagUser成功/失败
		List<String> tagKeys=new ArrayList<>();
		tagKeys.add(tag1.first());
		tagKeys.add(tag2.first());
		String untagUserResult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 403);	
		
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		//user2有添加tag的权限
		String tagUserResult=IAMInterfaceTestUtils.TagUser(userak2, usersk2, userName, tags, 403);
		
		//user2有获取用户tags的权限		
		String listtageResult=IAMInterfaceTestUtils.ListUserTags(userak2, usersk2, userName,403);
		
		//user2有删除用户的tags权限
		String untagResult=IAMInterfaceTestUtils.UntagUser(userak2, usersk2, userName,tagKeys, 403);
		
		//user3添加策略，getUser失败
		attachPolicyToUser(userName3,policyArn);
		String getUserResult=IAMInterfaceTestUtils.GetUser(userak3, usersk3, userName, 403);
		
		//删除创建的用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		//移除用户中的策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName2, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName3, policyName, 200);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
	}	
	
	
	
	
	/***
	 * NotAction，NotResource，
	 * resource为userName，满足actions不满足userName，访问拒绝
	 * 不为actions，且不满足userName，访问允许
	 * ***/
	@Test
	public void test_tagUntagListUserTags_allow_match_notActionNotResource_userName2()throws Exception{
		//用户有创建获取删除用户的权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		String userName02="createbyuser02";
		createUser(userName02,userak1,usersk1);
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:TagUser","iam:ListUserTags","iam:UntagUser"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/"+userName02),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);

		List<Pair<String, String>> tags=new ArrayList<>();
		Pair<String,String> tag1=new Pair<>();
		tag1.first("tag1Key");
		tag1.second("tag1Value");
		Pair<String,String> tag2=new Pair<>();
		tag2.first("tag2Key");
		tag2.second("tag2Value");
		tags.add(tag1);
		tags.add(tag2);
			
		//发送TagUser请求，因与策略匹配，TagUser失败
		String result=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 403);
	
		String listtagsResult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 403);	
		System.out.println(listtagsResult);

		//发送UntagUser请求，因为策略匹配，UntagUser失败
		List<String> tagKeys=new ArrayList<>();
		tagKeys.add(tag1.first());
		tagKeys.add(tag2.first());
		String untagUserResult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 403);	
		
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		//user2无添加tag的权限
		String tagUserResult=IAMInterfaceTestUtils.TagUser(userak2, usersk2, userName, tags, 403);
		
		//user2无获取用户tags的权限		
		String listtageResult=IAMInterfaceTestUtils.ListUserTags(userak2, usersk2, userName,403);
		
		//user2无删除用户的tags权限
		String untagResult=IAMInterfaceTestUtils.UntagUser(userak2, usersk2, userName,tagKeys, 403);
		
		//user3添加策略，getUser成功
		attachPolicyToUser(userName3,policyArn);
		String getUserResult=IAMInterfaceTestUtils.GetUser(userak3, usersk3, userName, 200);
		
		//删除创建的用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		//移除用户中的策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName2, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName3, policyName, 200);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
	}	
	
	/**
	 * 策略为deny，deny策略匹配，访问拒绝
	 * 存在allow策略，策略允许，访问拒绝，deny优先级高于allow
	 * */
	@Test
	public void test_tagUntagListUserTags_deny_match()throws Exception{
		//用户有创建获取删除用户的权限
		String policyName1="creategetdeluserperssion";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);

		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Deny,policyName,"Action",Arrays.asList("iam:TagUser","iam:ListUserTags","iam:UntagUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);

		List<Pair<String, String>> tags=new ArrayList<>();
		Pair<String,String> tag1=new Pair<>();
		tag1.first("tag1Key");
		tag1.second("tag1Value");
		Pair<String,String> tag2=new Pair<>();
		tag2.first("tag2Key");
		tag2.second("tag2Value");
		tags.add(tag1);
		tags.add(tag2);
			
		//发送TagUser请求，因与策略匹配，TagUser失败
		String result=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 403);
	
		String listtagsResult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 403);	
		System.out.println(listtagsResult);

		//发送UntagUser请求，因为策略匹配，UntagUser失败
		List<String> tagKeys=new ArrayList<>();
		tagKeys.add(tag1.first());
		tagKeys.add(tag2.first());
		String untagUserResult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 403);	
		
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			

		String tagUserResult=IAMInterfaceTestUtils.TagUser(userak2, usersk2, userName, tags, 403);
		
		String listtageResult=IAMInterfaceTestUtils.ListUserTags(userak2, usersk2, userName,403);

		String untagResult=IAMInterfaceTestUtils.UntagUser(userak2, usersk2, userName,tagKeys, 403);
		
		//添加allow策略，策略有权限
		String policyName2="tagUntagListperssion";
		UseraboutPolicies(accessKey,secretKey,"tagUntagListperssion",userName1,policyName2);
		
		//deny匹配优先级最高，user1仍旧无权限
		String result2=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 403);
		String listtagresult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 403);
		String untagresult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 403);
				
		//删除创建的用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		//移除用户中的策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
	}

	/**
	 * 策略为deny，NotAction,deny策略匹配，访问拒绝
	 * 存在allow策略，策略允许，访问拒绝，deny优先级高于allow
	 * */
	@Test
	public void test_tagUntagListUserTags_deny_match_notAction()throws Exception{
		//用户有创建获取删除用户的权限
		String policyName1="creategetdeluserperssion";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);

		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Deny,policyName,"NotAction",Arrays.asList("iam:GetUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);

		List<Pair<String, String>> tags=new ArrayList<>();
		Pair<String,String> tag1=new Pair<>();
		tag1.first("tag1Key");
		tag1.second("tag1Value");
		Pair<String,String> tag2=new Pair<>();
		tag2.first("tag2Key");
		tag2.second("tag2Value");
		tags.add(tag1);
		tags.add(tag2);
			
		//发送TagUser请求，因与策略匹配，TagUser失败
		String result=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 403);
	
		String listtagsResult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 403);	
		System.out.println(listtagsResult);

		//发送UntagUser请求，因为策略匹配，UntagUser失败
		List<String> tagKeys=new ArrayList<>();
		tagKeys.add(tag1.first());
		tagKeys.add(tag2.first());
		String untagUserResult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 403);	
		
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			

		String tagUserResult=IAMInterfaceTestUtils.TagUser(userak2, usersk2, userName, tags, 403);
		
		String listtageResult=IAMInterfaceTestUtils.ListUserTags(userak2, usersk2, userName,403);

		String untagResult=IAMInterfaceTestUtils.UntagUser(userak2, usersk2, userName,tagKeys, 403);
		
		//添加allow策略，策略有权限
		String policyName2="tagUntagListperssion";
		UseraboutPolicies(accessKey,secretKey,"tagUntagListperssion",userName1,policyName2);
		
		//deny匹配优先级最高，user1仍旧无权限
		String result2=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 403);
		String listtagresult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 403);
		String untagresult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 403);
				
		//移除用户中的策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		
		//删除创建的用户，注意先移除策略，在删除，因为deny的优先级高deleteUser满足deny，会拒绝访问
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
	}
	
	/**
	 * 策略为deny，NotResource,deny策略匹配，访问拒绝
	 * 存在allow策略，策略允许，访问拒绝，deny优先级高于allow
	 * */
	@Test
	public void test_tagUntagListUserTags_deny_match_notResource()throws Exception{
		//用户有创建获取删除用户的权限
		String policyName1="creategetdeluserperssion";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);

		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Deny,policyName,"Action",Arrays.asList("iam:TagUser","iam:ListUserTags","iam:UntagUser"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:group/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);

		List<Pair<String, String>> tags=new ArrayList<>();
		Pair<String,String> tag1=new Pair<>();
		tag1.first("tag1Key");
		tag1.second("tag1Value");
		Pair<String,String> tag2=new Pair<>();
		tag2.first("tag2Key");
		tag2.second("tag2Value");
		tags.add(tag1);
		tags.add(tag2);
			
		//发送TagUser请求，因与策略匹配，TagUser失败
		String result=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 403);
	
		String listtagsResult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 403);	
		System.out.println(listtagsResult);

		//发送UntagUser请求，因为策略匹配，UntagUser失败
		List<String> tagKeys=new ArrayList<>();
		tagKeys.add(tag1.first());
		tagKeys.add(tag2.first());
		String untagUserResult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 403);	
		
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			

		String tagUserResult=IAMInterfaceTestUtils.TagUser(userak2, usersk2, userName, tags, 403);
		
		String listtageResult=IAMInterfaceTestUtils.ListUserTags(userak2, usersk2, userName,403);

		String untagResult=IAMInterfaceTestUtils.UntagUser(userak2, usersk2, userName,tagKeys, 403);
		
		//添加allow策略，策略有权限
		String policyName2="tagUntagListperssion";
		UseraboutPolicies(accessKey,secretKey,"tagUntagListperssion",userName1,policyName2);
		
		//deny匹配优先级最高，user1仍旧无权限
		String result2=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 403);
		String listtagresult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 403);
		String untagresult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 403);
				
		//删除创建的用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		//移除用户中的策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
	}
	
	/**
	 * 策略为deny，NotAction,NotResource,deny策略匹配，访问拒绝
	 * 存在allow策略，策略允许，访问拒绝，deny优先级高于allow
	 * */
	@Test
	public void test_tagUntagListUserTags_deny_match_notActionNotResource()throws Exception{
		//用户有创建获取删除用户的权限
		String policyName1="creategetdeluserperssion";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);

		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Deny,policyName,"NotAction",Arrays.asList("iam:GetUser"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:group/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);

		List<Pair<String, String>> tags=new ArrayList<>();
		Pair<String,String> tag1=new Pair<>();
		tag1.first("tag1Key");
		tag1.second("tag1Value");
		Pair<String,String> tag2=new Pair<>();
		tag2.first("tag2Key");
		tag2.second("tag2Value");
		tags.add(tag1);
		tags.add(tag2);
			
		//发送TagUser请求，因与策略匹配，TagUser失败
		String result=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 403);
	
		String listtagsResult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 403);	
		System.out.println(listtagsResult);

		//发送UntagUser请求，因为策略匹配，UntagUser失败
		List<String> tagKeys=new ArrayList<>();
		tagKeys.add(tag1.first());
		tagKeys.add(tag2.first());
		String untagUserResult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 403);	
		
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			

		String tagUserResult=IAMInterfaceTestUtils.TagUser(userak2, usersk2, userName, tags, 403);
		
		String listtageResult=IAMInterfaceTestUtils.ListUserTags(userak2, usersk2, userName,403);

		String untagResult=IAMInterfaceTestUtils.UntagUser(userak2, usersk2, userName,tagKeys, 403);
		
		//添加allow策略，策略有权限
		String policyName2="tagUntagListperssion";
		UseraboutPolicies(accessKey,secretKey,"tagUntagListperssion",userName1,policyName2);
		
		String result2=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 403);
		String listtagresult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 403);
		String untagresult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 403);
				

		//移除用户中的策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		//删除创建的用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
	}	
	
	/**
	 * 策略为deny，NotAction,NotResource,deny策略匹配，访问拒绝
	 * 存在allow策略，策略允许，访问拒绝，deny优先级高于allow
	 * */
	@Test
	public void test_tagUntagListUserTags_deny_match_condition()throws Exception{
		//用户有创建获取删除用户的权限
		String policyName1="creategetdeluserperssion";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);

		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		
		String policyName="createPolicyFormatch";
		List<Condition> conditions = new ArrayList<Condition>();
	    conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test01*")));
		createPolicy(Effect.Deny,policyName,"NotAction",Arrays.asList("iam:GetUser"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:group/*"),conditions);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);

		List<Pair<String, String>> tags=new ArrayList<>();
		Pair<String,String> tag1=new Pair<>();
		tag1.first("tag1Key");
		tag1.second("tag1Value");
		Pair<String,String> tag2=new Pair<>();
		tag2.first("tag2Key");
		tag2.second("tag2Value");
		tags.add(tag1);
		tags.add(tag2);
			
		//发送TagUser请求，因与策略匹配，TagUser失败
		String result=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 403);
	
		String listtagsResult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 403);	
		System.out.println(listtagsResult);

		//发送UntagUser请求，因为策略匹配，UntagUser失败
		List<String> tagKeys=new ArrayList<>();
		tagKeys.add(tag1.first());
		tagKeys.add(tag2.first());
		String untagUserResult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 403);	
		
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			

		String tagUserResult=IAMInterfaceTestUtils.TagUser(userak2, usersk2, userName, tags, 403);
		
		String listtageResult=IAMInterfaceTestUtils.ListUserTags(userak2, usersk2, userName,403);

		String untagResult=IAMInterfaceTestUtils.UntagUser(userak2, usersk2, userName,tagKeys, 403);
		
		//添加allow策略，策略有权限
		String policyName2="tagUntagListperssion";
		UseraboutPolicies(accessKey,secretKey,"tagUntagListperssion",userName1,policyName2);
		
		String result2=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 403);
		String listtagresult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 403);
		String untagresult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 403);
				
		//移除用户中的策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		//删除创建的用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
	}
	
	/**
	 * 策略为deny，NotAction,NotResource,deny策略不匹配，访问拒绝（隐式拒绝）
	 * deny策略不匹配时，如果存在allow策略，验证allow策略，若策略允许，则用户允许访问
	 * 存在allow策略，策略允许，用户有权限访问
	 * */
	@Test
	public void test_tagUntagListUserTags_deny_notMatch_condition()throws Exception{
		//用户有创建获取删除用户的权限
		String policyName1="creategetdeluserperssion";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);

		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		
		String policyName="createPolicyFormatch";
		List<Condition> conditions = new ArrayList<Condition>();
	    conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("TEST01*")));
		createPolicy(Effect.Deny,policyName,"Action",Arrays.asList("iam:TagUser","iam:ListUserTags","iam:UntagUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),conditions);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);

		List<Pair<String, String>> tags=new ArrayList<>();
		Pair<String,String> tag1=new Pair<>();
		tag1.first("tag1Key");
		tag1.second("tag1Value");
		Pair<String,String> tag2=new Pair<>();
		tag2.first("tag2Key");
		tag2.second("tag2Value");
		tags.add(tag1);
		tags.add(tag2);
			
		String result=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 403);
	
		String listtagsResult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 403);	
		System.out.println(listtagsResult);

		List<String> tagKeys=new ArrayList<>();
		tagKeys.add(tag1.first());
		tagKeys.add(tag2.first());
		String untagUserResult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 403);	
		
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			

		String tagUserResult=IAMInterfaceTestUtils.TagUser(userak2, usersk2, userName, tags, 403);
		
		String listtageResult=IAMInterfaceTestUtils.ListUserTags(userak2, usersk2, userName,403);

		String untagResult=IAMInterfaceTestUtils.UntagUser(userak2, usersk2, userName,tagKeys, 403);
		
		//添加allow策略，策略有权限
		String policyName2="tagUntagListperssion";
		UseraboutPolicies(accessKey,secretKey,"tagUntagListperssion",userName1,policyName2);
		
		String result2=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 200);
		String listtagresult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 200);
		String untagresult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 200);
				
		//删除创建的用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		//移除用户中的策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
	}	
	
	/**
	 * 策略为deny，deny策略不匹配，隐式拒绝
	 * 添加allow策略，deny策略不匹配，判断allow策略
	 * allow策略允许则允许访问
	 * */
	@Test
	public void test_tagUntagListUserTags_deny_notMatch_action()throws Exception{
		//用户有创建获取删除用户的权限
		String policyName1="creategetdeluserperssion";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);

		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		
		String policyName="createPolicyFormatch";
		List<Condition> conditions = new ArrayList<Condition>();
	    conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test01*")));
		createPolicy(Effect.Deny,policyName,"Action",Arrays.asList("iam:Tag","iam:List","iam:Untag"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),conditions);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);

		List<Pair<String, String>> tags=new ArrayList<>();
		Pair<String,String> tag1=new Pair<>();
		tag1.first("tag1Key");
		tag1.second("tag1Value");
		Pair<String,String> tag2=new Pair<>();
		tag2.first("tag2Key");
		tag2.second("tag2Value");
		tags.add(tag1);
		tags.add(tag2);
			
		//发送TagUser请求，因与策略匹配，TagUser失败
		String result=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 403);
	
		String listtagsResult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 403);	
		System.out.println(listtagsResult);

		//发送UntagUser请求，因为策略匹配，UntagUser失败
		List<String> tagKeys=new ArrayList<>();
		tagKeys.add(tag1.first());
		tagKeys.add(tag2.first());
		String untagUserResult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 403);	
		
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		String tagUserResult=IAMInterfaceTestUtils.TagUser(userak2, usersk2, userName, tags, 403);
		
		String listtageResult=IAMInterfaceTestUtils.ListUserTags(userak2, usersk2, userName,403);

		String untagResult=IAMInterfaceTestUtils.UntagUser(userak2, usersk2, userName,tagKeys, 403);
		
		//添加allow策略，策略有权限
		String policyName2="tagUntagListperssion";
		UseraboutPolicies(accessKey,secretKey,"tagUntagListperssion",userName1,policyName2);
		
		String result2=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 200);
		String listtagresult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 200);
		String untagresult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 200);
				
		//删除创建的用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		//移除用户中的策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
	}	
	
	/**
	 * 策略为deny，deny策略不匹配，隐式拒绝
	 * 添加allow策略，deny策略不匹配，判断allow策略
	 * allow策略允许则允许访问
	 * */
	@Test
	public void test_tagUntagListUserTags_deny_notMatch_resource()throws Exception{
		//用户有创建获取删除用户的权限
		String policyName1="creategetdeluserperssion";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);

		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		
		String policyName="createPolicyFormatch";
		List<Condition> conditions = new ArrayList<Condition>();
	    conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test01*")));
		createPolicy(Effect.Deny,policyName,"Action",Arrays.asList("iam:Tag","iam:List","iam:Untag"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/"+userName3),conditions);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);

		List<Pair<String, String>> tags=new ArrayList<>();
		Pair<String,String> tag1=new Pair<>();
		tag1.first("tag1Key");
		tag1.second("tag1Value");
		Pair<String,String> tag2=new Pair<>();
		tag2.first("tag2Key");
		tag2.second("tag2Value");
		tags.add(tag1);
		tags.add(tag2);
			
		//发送TagUser请求，因与策略匹配，TagUser失败
		String result=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 403);
	
		String listtagsResult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 403);	
		System.out.println(listtagsResult);

		//发送UntagUser请求，因为策略匹配，UntagUser失败
		List<String> tagKeys=new ArrayList<>();
		tagKeys.add(tag1.first());
		tagKeys.add(tag2.first());
		String untagUserResult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 403);	
		
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		String tagUserResult=IAMInterfaceTestUtils.TagUser(userak2, usersk2, userName, tags, 403);
		
		String listtageResult=IAMInterfaceTestUtils.ListUserTags(userak2, usersk2, userName,403);

		String untagResult=IAMInterfaceTestUtils.UntagUser(userak2, usersk2, userName,tagKeys, 403);
		
		//添加allow策略，策略有权限
		String policyName2="tagUntagListperssion";
		UseraboutPolicies(accessKey,secretKey,"tagUntagListperssion",userName1,policyName2);
		
		String result2=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 200);
		String listtagresult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 200);
		String untagresult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 200);
				
		//删除创建的用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		//移除用户中的策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
	}
	
	/**
	 * 策略为deny，deny策略不匹配，隐式拒绝
	 * 添加allow策略，deny策略不匹配，判断allow策略
	 * 不满足allow策略，则隐式拒绝
	 * */
	@Test
	public void test_tagUntagListUserTags_deny_notMatch_allowPolicy()throws Exception{
		//用户有创建获取删除用户的权限
		String policyName1="creategetdeluserperssion";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);

		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		
		String policyName="createPolicyFormatch";
		List<Condition> conditions = new ArrayList<Condition>();
	    conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test01*")));
		createPolicy(Effect.Deny,policyName,"Action",Arrays.asList("iam:Tag","iam:List","iam:Untag"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/"+userName3),conditions);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);

		List<Pair<String, String>> tags=new ArrayList<>();
		Pair<String,String> tag1=new Pair<>();
		tag1.first("tag1Key");
		tag1.second("tag1Value");
		Pair<String,String> tag2=new Pair<>();
		tag2.first("tag2Key");
		tag2.second("tag2Value");
		tags.add(tag1);
		tags.add(tag2);
			
		//发送TagUser请求，因与策略匹配，TagUser失败
		String result=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 403);
	
		String listtagsResult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 403);	
		System.out.println(listtagsResult);

		//发送UntagUser请求，因为策略匹配，UntagUser失败
		List<String> tagKeys=new ArrayList<>();
		tagKeys.add(tag1.first());
		tagKeys.add(tag2.first());
		String untagUserResult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 403);	
		
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		String tagUserResult=IAMInterfaceTestUtils.TagUser(userak2, usersk2, userName, tags, 403);
		
		String listtageResult=IAMInterfaceTestUtils.ListUserTags(userak2, usersk2, userName,403);

		String untagResult=IAMInterfaceTestUtils.UntagUser(userak2, usersk2, userName,tagKeys, 403);
		
		//添加allow策略，策略无权限
		String policyName2="tagUntagListdeny";
		attacheUserallowedPolicy_deny(userName1,policyName2);
		
		//deny匹配优先级最高，user1仍旧无权限
		String result2=IAMInterfaceTestUtils.TagUser(userak1, usersk1, userName, tags, 403);
		String listtagresult=IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 403);
		String untagresult=IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 403);
				
		//删除创建的用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		//移除用户中的策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
	}
	
	/**
	 * allow策略，允许putgetupdatedelLoginProfile
	 * 满足策略，允许访问
	 * ***/
	@Test
	public void test_createGetUpdateDelLogionProfile_allow_match() throws Exception{
		String newpassword="password123";
		String newpassword2="password456";
		//给用户赋putgetdelUser权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateLoginProfile","iam:GetLoginProfile","iam:UpdateLoginProfile","iam:DeleteLoginProfile"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//符合策略，有权限
		String createresult=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 200);
		String updateresult=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 200);
		String getresult=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 200);
		String delresult=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 200);
		
		//给组添加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		//用户2有权限
		String createresult2=IAMInterfaceTestUtils.CreateLoginProfile(userak2, usersk2, userName, newpassword, 200);
		String updateresult2=IAMInterfaceTestUtils.UpdateLoginProfile(userak2, usersk2, userName, newpassword2, 200);
		String getresult2=IAMInterfaceTestUtils.GetLoginProfile(userak2, usersk2, userName, 200);
		String delresult2=IAMInterfaceTestUtils.DeleteLoginProfile(userak2, usersk2, userName, 200);
		
		//删除用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		
		//移除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		//移除组中策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}
	
	/**
	 * allow策略，允许putgetupdatedelLoginProfile
	 * 满足策略，允许访问
	 * ***/
	@Test
	public void test_createGetUpdateDelLogionProfile_allow_match_condition() throws Exception{
		String newpassword="password123";
		String newpassword2="password456";
		//给用户赋putgetdelUser权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		
		String policyName="createPolicyFormatch";
		List<Condition> conditions = new ArrayList<Condition>();
	    conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test01*")));
	        
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateLoginProfile","iam:GetLoginProfile","iam:UpdateLoginProfile","iam:DeleteLoginProfile"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),conditions);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//符合策略，有权限
		String createresult=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 200);
		String updateresult=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 200);
		String getresult=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 200);
		String delresult=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 200);
		
		//给组添加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		//用户2有权限
		String createresult2=IAMInterfaceTestUtils.CreateLoginProfile(userak2, usersk2, userName, newpassword, 200);
		String updateresult2=IAMInterfaceTestUtils.UpdateLoginProfile(userak2, usersk2, userName, newpassword2, 200);
		String getresult2=IAMInterfaceTestUtils.GetLoginProfile(userak2, usersk2, userName, 200);
		String delresult2=IAMInterfaceTestUtils.DeleteLoginProfile(userak2, usersk2, userName, 200);
		
		//删除用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		
		//移除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		//移除组中策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}	
	

	
	/**
	 * allow策略，允许putgetupdatedelLoginProfile
	 * resource=user/userName
	 * 满足策略，允许访问
	 * 不符合userName，访问拒绝
	 * ***/
	@Test
	public void test_createGetUpdateDelLogionProfile_allow_match_userName() throws Exception{
		String newpassword="password123";
		String newpassword2="password456";
		//给用户赋putgetdelUser权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		String userName02="createbyuser02";
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateLoginProfile","iam:GetLoginProfile","iam:UpdateLoginProfile","iam:DeleteLoginProfile"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/"+userName),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//符合策略，有权限
		String createresult=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 200);
		String updateresult=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 200);
		String getresult=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 200);
		String delresult=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 200);
		
		String createresult12=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName02, newpassword, 403);
		String updateresult12=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName02, newpassword2, 403);
		String getresult12=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName02, 403);
		String delresult12=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName02, 403);
		
		//给组添加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		//用户2有权限
		String createresult2=IAMInterfaceTestUtils.CreateLoginProfile(userak2, usersk2, userName, newpassword, 200);
		String updateresult2=IAMInterfaceTestUtils.UpdateLoginProfile(userak2, usersk2, userName, newpassword2, 200);
		String getresult2=IAMInterfaceTestUtils.GetLoginProfile(userak2, usersk2, userName, 200);
		String delresult2=IAMInterfaceTestUtils.DeleteLoginProfile(userak2, usersk2, userName, 200);
		
		String createresult21=IAMInterfaceTestUtils.CreateLoginProfile(userak2, usersk2, userName02, newpassword, 403);
		String updateresult21=IAMInterfaceTestUtils.UpdateLoginProfile(userak2, usersk2, userName02, newpassword2, 403);
		String getresult21=IAMInterfaceTestUtils.GetLoginProfile(userak2, usersk2, userName02, 403);
		String delresult21=IAMInterfaceTestUtils.DeleteLoginProfile(userak2, usersk2, userName02, 403);
		
		//删除用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		
		//移除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		//移除组中策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}
	
	/**
	 * allow策略，允许putgetupdatedelLoginProfile
	 * resource为*
	 * 满足策略，允许访问
	 * ***/
	@Test
	public void test_createGetUpdateDelLogionProfile_allow_match_all() throws Exception{
		String newpassword="password123";
		String newpassword2="password456";
		//给用户赋putgetdelUser权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateLoginProfile","iam:GetLoginProfile","iam:UpdateLoginProfile","iam:DeleteLoginProfile"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//符合策略，有权限
		String createresult=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 200);
		String updateresult=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 200);
		String getresult=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 200);
		String delresult=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 200);
		
		//给组添加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		//用户2有权限
		String createresult2=IAMInterfaceTestUtils.CreateLoginProfile(userak2, usersk2, userName, newpassword, 200);
		String updateresult2=IAMInterfaceTestUtils.UpdateLoginProfile(userak2, usersk2, userName, newpassword2, 200);
		String getresult2=IAMInterfaceTestUtils.GetLoginProfile(userak2, usersk2, userName, 200);
		String delresult2=IAMInterfaceTestUtils.DeleteLoginProfile(userak2, usersk2, userName, 200);
		
		//删除用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		
		//移除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		//移除组中策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}	
	
	/**
	 * allow策略，允许putgetupdatedelLoginProfile
	 * NotAction
	 * ***/
	@Test
	public void test_createGetUpdateDelLogionProfile_allow_match_notAction() throws Exception{
		String newpassword="password123";
		String newpassword2="password456";
		//给用户赋putgetdelUser权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:Create","iam:GetUser","iam:Update","iam:Delete"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//符合策略，有权限
		String createresult=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 200);
		String updateresult=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 200);
		String getresult=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 200);
		String delresult=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 200);
		
		//给组添加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		//用户2有权限
		String createresult2=IAMInterfaceTestUtils.CreateLoginProfile(userak2, usersk2, userName, newpassword, 200);
		String updateresult2=IAMInterfaceTestUtils.UpdateLoginProfile(userak2, usersk2, userName, newpassword2, 200);
		String getresult2=IAMInterfaceTestUtils.GetLoginProfile(userak2, usersk2, userName, 200);
		String delresult2=IAMInterfaceTestUtils.DeleteLoginProfile(userak2, usersk2, userName, 200);
		
		//删除用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		
		//移除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		//移除组中策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}	
	
	/**
	 * allow策略，允许putgetupdatedelLoginProfile
	 * NotAction
	 * ***/
	@Test
	public void test_createGetUpdateDelLogionProfile_allow_match_notAction_userName() throws Exception{
		String newpassword="password123";
		String newpassword2="password456";
		//给用户赋putgetdelUser权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		String userName02="createbyuser02";
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:GetUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/"+userName),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//符合策略，有权限
		String createresult=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 200);
		String updateresult=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 200);
		String getresult=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 200);
		String delresult=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 200);
		
		//给组添加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		//用户2无权限，不满足resource
		String createresult2=IAMInterfaceTestUtils.CreateLoginProfile(userak2, usersk2, userName02, newpassword, 403);
		String updateresult2=IAMInterfaceTestUtils.UpdateLoginProfile(userak2, usersk2, userName02, newpassword2, 403);
		String getresult2=IAMInterfaceTestUtils.GetLoginProfile(userak2, usersk2, userName02, 403);
		String delresult2=IAMInterfaceTestUtils.DeleteLoginProfile(userak2, usersk2, userName02, 403);

		//删除用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		
		//移除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		//移除组中策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}
	
	/**
	 * allow策略，允许putgetupdatedelLoginProfile
	 * NotAction
	 * ***/
	@Test
	public void test_createGetUpdateDelLogionProfile_allow_match_notAction_all() throws Exception{
		String newpassword="password123";
		String newpassword2="password456";
		//给用户赋putgetdelUser权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		String userName02="createbyuser02";
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:GetUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//符合策略，有权限
		String createresult=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 200);
		String updateresult=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 200);
		String getresult=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 200);
		String delresult=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 200);
		
		//给组添加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		//用户2有权限
		String createresult2=IAMInterfaceTestUtils.CreateLoginProfile(userak2, usersk2, userName, newpassword, 200);
		String updateresult2=IAMInterfaceTestUtils.UpdateLoginProfile(userak2, usersk2, userName, newpassword2, 200);
		String getresult2=IAMInterfaceTestUtils.GetLoginProfile(userak2, usersk2, userName, 200);
		String delresult2=IAMInterfaceTestUtils.DeleteLoginProfile(userak2, usersk2, userName, 200);

		//删除用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		
		//移除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		//移除组中策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}	
	
	/**
	 * allow策略，允许putgetupdatedelLoginProfile
	 * NotAction
	 * ***/
	@Test
	public void test_createGetUpdateDelLogionProfile_allow_match_notAction_deny() throws Exception{
		String newpassword="password123";
		String newpassword2="password456";
		//给用户赋putgetdelUser权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		String userName02="createbyuser02";
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:CreateLoginProfile","iam:GetLoginProfile","iam:UpdateLoginProfile","iam:DeleteLoginProfile"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		//符合策略，无权限
		String createresult=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 403);
		String updateresult=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 403);
		String getresult=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 403);
		String delresult=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 403);
		
		//给组添加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		//用户2无权限
		String createresult2=IAMInterfaceTestUtils.CreateLoginProfile(userak2, usersk2, userName, newpassword, 403);
		String updateresult2=IAMInterfaceTestUtils.UpdateLoginProfile(userak2, usersk2, userName, newpassword2, 403);
		String getresult2=IAMInterfaceTestUtils.GetLoginProfile(userak2, usersk2, userName, 403);
		String delresult2=IAMInterfaceTestUtils.DeleteLoginProfile(userak2, usersk2, userName, 403);

		//删除用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		
		//移除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		//移除组中策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}
	
	/**
	 * allow策略，允许putgetupdatedelLoginProfile
	 * NotResource
	 * ***/
	@Test
	public void test_createGetUpdateDelLogionProfile_allow_match_notResource() throws Exception{
		String newpassword="password123";
		String newpassword2="password456";
		//给用户赋putgetdelUser权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		String userName02="createbyuser02";
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateLoginProfile","iam:GetLoginProfile","iam:UpdateLoginProfile","iam:DeleteLoginProfile"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:group/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		String createresult=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 200);
		String updateresult=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 200);
		String getresult=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 200);
		String delresult=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 200);
		
		//给组添加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		String createresult2=IAMInterfaceTestUtils.CreateLoginProfile(userak2, usersk2, userName, newpassword, 200);
		String updateresult2=IAMInterfaceTestUtils.UpdateLoginProfile(userak2, usersk2, userName, newpassword2, 200);
		String getresult2=IAMInterfaceTestUtils.GetLoginProfile(userak2, usersk2, userName, 200);
		String delresult2=IAMInterfaceTestUtils.DeleteLoginProfile(userak2, usersk2, userName, 200);

		//删除用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		
		//移除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		//移除组中策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}	
	
	/**
	 * allow策略，允许putgetupdatedelLoginProfile
	 * NotResource
	 * ***/
	@Test
	public void test_createGetUpdateDelLogionProfile_allow_match_notResource_userName() throws Exception{
		String newpassword="password123";
		String newpassword2="password456";
		//给用户赋putgetdelUser权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		String userName02="createbyuser02";
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateLoginProfile","iam:GetLoginProfile","iam:UpdateLoginProfile","iam:DeleteLoginProfile"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/"+userName02),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		String createresult=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 200);
		String updateresult=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 200);
		String getresult=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 200);
		String delresult=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 200);
		
		//给组添加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		String createresult2=IAMInterfaceTestUtils.CreateLoginProfile(userak2, usersk2, userName02, newpassword, 403);
		String updateresult2=IAMInterfaceTestUtils.UpdateLoginProfile(userak2, usersk2, userName02, newpassword2, 403);
		String getresult2=IAMInterfaceTestUtils.GetLoginProfile(userak2, usersk2, userName02, 403);
		String delresult2=IAMInterfaceTestUtils.DeleteLoginProfile(userak2, usersk2, userName02, 403);

		//删除用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		
		//移除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		//移除组中策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}
	
	/**
	 * allow策略，允许putgetupdatedelLoginProfile
	 * NotResource
	 * ***/
	@Test
	public void test_createGetUpdateDelLogionProfile_allow_match_notResource_user() throws Exception{
		String newpassword="password123";
		String newpassword2="password456";
		//给用户赋putgetdelUser权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		String userName02="createbyuser02";
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateLoginProfile","iam:GetLoginProfile","iam:UpdateLoginProfile","iam:DeleteLoginProfile"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		String createresult=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 403);
		String updateresult=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 403);
		String getresult=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 403);
		String delresult=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 403);
		
		//给组添加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		String createresult2=IAMInterfaceTestUtils.CreateLoginProfile(userak2, usersk2, userName02, newpassword, 403);
		String updateresult2=IAMInterfaceTestUtils.UpdateLoginProfile(userak2, usersk2, userName02, newpassword2, 403);
		String getresult2=IAMInterfaceTestUtils.GetLoginProfile(userak2, usersk2, userName02, 403);
		String delresult2=IAMInterfaceTestUtils.DeleteLoginProfile(userak2, usersk2, userName02, 403);

		//删除用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		
		//移除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		//移除组中策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}
	
	/**
	 * allow策略，允许putgetupdatedelLoginProfile
	 * NotResource
	 * ***/
	@Test
	public void test_createGetUpdateDelLogionProfile_allow_match_notResource_all() throws Exception{
		String newpassword="password123";
		String newpassword2="password456";
		//给用户赋putgetdelUser权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		String userName02="createbyuser02";
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateLoginProfile","iam:GetLoginProfile","iam:UpdateLoginProfile","iam:DeleteLoginProfile"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		String createresult=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 403);
		String updateresult=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 403);
		String getresult=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 403);
		String delresult=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 403);
		
		//给组添加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		String createresult2=IAMInterfaceTestUtils.CreateLoginProfile(userak2, usersk2, userName02, newpassword, 403);
		String updateresult2=IAMInterfaceTestUtils.UpdateLoginProfile(userak2, usersk2, userName02, newpassword2, 403);
		String getresult2=IAMInterfaceTestUtils.GetLoginProfile(userak2, usersk2, userName02, 403);
		String delresult2=IAMInterfaceTestUtils.DeleteLoginProfile(userak2, usersk2, userName02, 403);

		//删除用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		
		//移除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		//移除组中策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}
	
	/**
	 * allow策略，允许putgetupdatedelLoginProfile
	 * NotAction,NotResource
	 * ***/
	@Test
	public void test_createGetUpdateDelLogionProfile_allow_match_notActionNotResource() throws Exception{
		String newpassword="password123";
		String newpassword2="password456";
		//给用户赋putgetdelUser权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:GetUser"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:group/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		String createresult=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 200);
		String updateresult=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 200);
		String getresult=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 200);
		String delresult=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 200);
		
		//给组添加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		String createresult2=IAMInterfaceTestUtils.CreateLoginProfile(userak2, usersk2, userName, newpassword, 200);
		String updateresult2=IAMInterfaceTestUtils.UpdateLoginProfile(userak2, usersk2, userName, newpassword2, 200);
		String getresult2=IAMInterfaceTestUtils.GetLoginProfile(userak2, usersk2, userName, 200);
		String delresult2=IAMInterfaceTestUtils.DeleteLoginProfile(userak2, usersk2, userName, 200);

		//删除用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		
		//移除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		//移除组中策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}
	
	/**
	 * allow策略，允许putgetupdatedelLoginProfile
	 * NotAction,NotResource
	 * ***/
	@Test
	public void test_createGetUpdateDelLogionProfile_allow_match_notActionNotResource_userName() throws Exception{
		String newpassword="password123";
		String newpassword2="password456";
		//给用户赋putgetdelUser权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		String userName02="createbyuser02";
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:GetUser"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/"+userName02),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		String createresult=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 200);
		String updateresult=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 200);
		String getresult=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 200);
		String delresult=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 200);
		
		//给组添加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		String createresult2=IAMInterfaceTestUtils.CreateLoginProfile(userak2, usersk2, userName02, newpassword, 403);
		String updateresult2=IAMInterfaceTestUtils.UpdateLoginProfile(userak2, usersk2, userName02, newpassword2, 403);
		String getresult2=IAMInterfaceTestUtils.GetLoginProfile(userak2, usersk2, userName02, 403);
		String delresult2=IAMInterfaceTestUtils.DeleteLoginProfile(userak2, usersk2, userName02, 403);

		//删除用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		
		//移除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		//移除组中策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}
	
	/**
	 * allow策略，putgetupdatedelLoginProfile
	 * NotAction,NotResource
	 * ***/
	@Test
	public void test_createGetUpdateDelLogionProfile_allow_match_notActionNotResource_user() throws Exception{
		String newpassword="password123";
		String newpassword2="password456";
		//给用户赋putgetdelUser权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		String userName02="createbyuser02";
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:GetUser"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		String createresult=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 403);
		String updateresult=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 403);
		String getresult=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 403);
		String delresult=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 403);
		
		//给组添加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		String createresult2=IAMInterfaceTestUtils.CreateLoginProfile(userak2, usersk2, userName02, newpassword, 403);
		String updateresult2=IAMInterfaceTestUtils.UpdateLoginProfile(userak2, usersk2, userName02, newpassword2, 403);
		String getresult2=IAMInterfaceTestUtils.GetLoginProfile(userak2, usersk2, userName02, 403);
		String delresult2=IAMInterfaceTestUtils.DeleteLoginProfile(userak2, usersk2, userName02, 403);

		//删除用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		
		//移除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		//移除组中策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}
	
	/**
	 * allow策略，允许putgetupdatedelLoginProfile
	 * NotAction,NotResource
	 * ***/
	@Test
	public void test_createGetUpdateDelLogionProfile_allow_match_notActionNotResource_all() throws Exception{
		String newpassword="password123";
		String newpassword2="password456";
		//给用户赋putgetdelUser权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		String userName02="createbyuser02";
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:GetUser"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		String createresult=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 403);
		String updateresult=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 403);
		String getresult=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 403);
		String delresult=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 403);
		
		//给组添加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		String createresult2=IAMInterfaceTestUtils.CreateLoginProfile(userak2, usersk2, userName02, newpassword, 403);
		String updateresult2=IAMInterfaceTestUtils.UpdateLoginProfile(userak2, usersk2, userName02, newpassword2, 403);
		String getresult2=IAMInterfaceTestUtils.GetLoginProfile(userak2, usersk2, userName02, 403);
		String delresult2=IAMInterfaceTestUtils.DeleteLoginProfile(userak2, usersk2, userName02, 403);

		//删除用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		
		//移除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		//移除组中策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}	
	
	/**
	 * deny策略，deny策略中为不允许putgetupdatedelLoginProfile
	 * 如果策略匹配，访问拒绝
	 * 添加allow策略，deny策略优先级高于allow
	 * ***/
	@Test
	public void test_createGetUpdateDelLogionProfile_deny_match() throws Exception{
		String newpassword="password123";
		String newpassword2="password456";
		//给用户赋putgetdelUser权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Deny,policyName,"Action",Arrays.asList("iam:CreateLoginProfile","iam:GetLoginProfile","iam:UpdateLoginProfile","iam:DeleteLoginProfile"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		String createresult=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 403);
		String updateresult=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 403);
		String getresult=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 403);
		String delresult=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 403);
		
		//给组添加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);

		String createresult2=IAMInterfaceTestUtils.CreateLoginProfile(userak2, usersk2, userName, newpassword, 403);
		String updateresult2=IAMInterfaceTestUtils.UpdateLoginProfile(userak2, usersk2, userName, newpassword2, 403);
		String getresult2=IAMInterfaceTestUtils.GetLoginProfile(userak2, usersk2, userName, 403);
		String delresult2=IAMInterfaceTestUtils.DeleteLoginProfile(userak2, usersk2, userName, 403);

		//给用户添加allow策略
		String policyNameallow="loginprofileperssion";
		UseraboutPolicies(accessKey,secretKey,"loginprofileperssion",userName1,policyNameallow);
		String createresult3=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 403);
		String updateresult3=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 403);
		String getresult3=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 403);
		String delresult3=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 403);

		//移除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		
		//删除用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyNameallow, 200);
		//移除组中策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}
	
	/**
	 * deny策略，deny策略中为不允许putgetupdatedelLoginProfile
	 * 如果策略匹配，访问拒绝
	 * 添加allow策略，deny策略优先级高于allow
	 * ***/
	@Test
	public void test_createGetUpdateDelLogionProfile_deny_match_notAction() throws Exception{
		String newpassword="password123";
		String newpassword2="password456";
		//给用户赋putgetdelUser权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Deny,policyName,"NotAction",Arrays.asList("iam:GetUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		String createresult=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 403);
		String updateresult=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 403);
		String getresult=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 403);
		String delresult=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 403);
		
		//给组添加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);

		String createresult2=IAMInterfaceTestUtils.CreateLoginProfile(userak2, usersk2, userName, newpassword, 403);
		String updateresult2=IAMInterfaceTestUtils.UpdateLoginProfile(userak2, usersk2, userName, newpassword2, 403);
		String getresult2=IAMInterfaceTestUtils.GetLoginProfile(userak2, usersk2, userName, 403);
		String delresult2=IAMInterfaceTestUtils.DeleteLoginProfile(userak2, usersk2, userName, 403);

		//给用户添加allow策略
		String policyNameallow="loginprofileperssion";
		UseraboutPolicies(accessKey,secretKey,"loginprofileperssion",userName1,policyNameallow);
		String createresult3=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 403);
		String updateresult3=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 403);
		String getresult3=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 403);
		String delresult3=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 403);
	
		//移除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		
		//删除用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyNameallow, 200);
		//移除组中策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}
	
	/**
	 * deny策略，deny策略中为不允许putgetupdatedelLoginProfile
	 * 如果策略匹配，访问拒绝
	 * 添加allow策略，deny策略优先级高于allow
	 * ***/
	@Test
	public void test_createGetUpdateDelLogionProfile_deny_match_notResource() throws Exception{
		String newpassword="password123";
		String newpassword2="password456";
		//给用户赋putgetdelUser权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Deny,policyName,"Action",Arrays.asList("iam:CreateLoginProfile","iam:GetLoginProfile","iam:UpdateLoginProfile","iam:DeleteLoginProfile"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:USER/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		String createresult=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 403);
		String updateresult=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 403);
		String getresult=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 403);
		String delresult=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 403);
		
		//给组添加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);

		String createresult2=IAMInterfaceTestUtils.CreateLoginProfile(userak2, usersk2, userName, newpassword, 403);
		String updateresult2=IAMInterfaceTestUtils.UpdateLoginProfile(userak2, usersk2, userName, newpassword2, 403);
		String getresult2=IAMInterfaceTestUtils.GetLoginProfile(userak2, usersk2, userName, 403);
		String delresult2=IAMInterfaceTestUtils.DeleteLoginProfile(userak2, usersk2, userName, 403);

		//给用户添加allow策略
		String policyNameallow="loginprofileperssion";
		UseraboutPolicies(accessKey,secretKey,"loginprofileperssion",userName1,policyNameallow);
		String createresult3=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 403);
		String updateresult3=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 403);
		String getresult3=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 403);
		String delresult3=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 403);
	
		//移除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		
		//删除用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyNameallow, 200);
		//移除组中策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}	
	
	/**
	 * deny策略，deny策略中为不允许putgetupdatedelLoginProfile
	 * 如果策略匹配，访问拒绝
	 * 添加allow策略，deny策略优先级高于allow
	 * ***/
	@Test
	public void test_createGetUpdateDelLogionProfile_deny_match_notActionNotResource() throws Exception{
		String newpassword="password123";
		String newpassword2="password456";
		//给用户赋putgetdelUser权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Deny,policyName,"NotAction",Arrays.asList("iam:Create","iam:Get"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:USER/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		String createresult=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 403);
		String updateresult=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 403);
		String getresult=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 403);
		String delresult=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 403);
		
		//给组添加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);

		String createresult2=IAMInterfaceTestUtils.CreateLoginProfile(userak2, usersk2, userName, newpassword, 403);
		String updateresult2=IAMInterfaceTestUtils.UpdateLoginProfile(userak2, usersk2, userName, newpassword2, 403);
		String getresult2=IAMInterfaceTestUtils.GetLoginProfile(userak2, usersk2, userName, 403);
		String delresult2=IAMInterfaceTestUtils.DeleteLoginProfile(userak2, usersk2, userName, 403);

		//给用户添加allow策略
		String policyNameallow="loginprofileperssion";
		UseraboutPolicies(accessKey,secretKey,"loginprofileperssion",userName1,policyNameallow);
		String createresult3=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 403);
		String updateresult3=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 403);
		String getresult3=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 403);
		String delresult3=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 403);
	
		//移除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		
		//删除用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyNameallow, 200);
		//移除组中策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}
	
	/**
	 * deny策略，deny策略中为不允许putgetupdatedelLoginProfile
	 * 如果策略不匹配，访问拒绝
	 * 添加allow策略，deny策略优先级高于allow
	 * ***/
	@Test
	public void test_createGetUpdateDelLogionProfile_deny_match_condition() throws Exception{
		String newpassword="password123";
		String newpassword2="password456";
		//给用户赋putgetdelUser权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		
		String policyName="createPolicyFormatch";
		List<Condition> conditions = new ArrayList<Condition>();
	    conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test01*")));
		
		createPolicy(Effect.Deny,policyName,"Action",Arrays.asList("iam:CreateLoginProfile","iam:GetLoginProfile","iam:UpdateLoginProfile","iam:DeleteLoginProfile"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),conditions);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		String createresult=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 403);
		String updateresult=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 403);
		String getresult=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 403);
		String delresult=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 403);
		
		//给组添加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);

		String createresult2=IAMInterfaceTestUtils.CreateLoginProfile(userak2, usersk2, userName, newpassword, 403);
		String updateresult2=IAMInterfaceTestUtils.UpdateLoginProfile(userak2, usersk2, userName, newpassword2, 403);
		String getresult2=IAMInterfaceTestUtils.GetLoginProfile(userak2, usersk2, userName, 403);
		String delresult2=IAMInterfaceTestUtils.DeleteLoginProfile(userak2, usersk2, userName, 403);

		//给用户添加allow策略
		String policyNameallow="loginprofileperssion";
		UseraboutPolicies(accessKey,secretKey,"loginprofileperssion",userName1,policyNameallow);
		String createresult3=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 403);
		String updateresult3=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 403);
		String getresult3=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 403);
		String delresult3=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 403);
	
		//移除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		
		//删除用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyNameallow, 200);
		//移除组中策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}		

	/**
	 * 与deny策略不匹配，隐式拒绝
	 * 添加allow策略，验证是否与allow策略匹配
	 * 如果匹配则允许访问，若不匹配则隐式拒绝
	 * **/
	@Test
	public void test_createGetUpdateDelLogionProfile_deny_notmatch_condition() throws Exception{
		String newpassword="password123";
		String newpassword2="password456";
		//给用户赋putgetdelUser权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		
		String policyName="createPolicyFormatch";
		List<Condition> conditions = new ArrayList<Condition>();
	    conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("TEST01*")));
	    
		createPolicy(Effect.Deny,policyName,"Action",Arrays.asList("iam:CreateLoginProfile","iam:GetLoginProfile","iam:UpdateLoginProfile","iam:DeleteLoginProfile"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),conditions);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		String createresult=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 403);
		String updateresult=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 403);
		String getresult=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 403);
		String delresult=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 403);
		
		//给组添加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);

		String createresult2=IAMInterfaceTestUtils.CreateLoginProfile(userak2, usersk2, userName, newpassword, 403);
		String updateresult2=IAMInterfaceTestUtils.UpdateLoginProfile(userak2, usersk2, userName, newpassword2, 403);
		String getresult2=IAMInterfaceTestUtils.GetLoginProfile(userak2, usersk2, userName, 403);
		String delresult2=IAMInterfaceTestUtils.DeleteLoginProfile(userak2, usersk2, userName, 403);

		//给用户添加allow策略
		String policyNameallow="loginprofileperssion";
		UseraboutPolicies(accessKey,secretKey,"loginprofileperssion",userName1,policyNameallow);
		String createresult3=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 200);
		String updateresult3=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 200);
		String getresult3=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 200);
		String delresult3=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 200);
	
		//移除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		
		//删除用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyNameallow, 200);
		//移除组中策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}
	
	/**
	 * 与deny策略不匹配，隐式拒绝
	 * 添加allow策略，验证是否与allow策略匹配
	 * 如果匹配则允许访问，若不匹配则隐式拒绝
	 * **/
	@Test
	public void test_createGetUpdateDelLogionProfile_deny_notmatch() throws Exception{
		String newpassword="password123";
		String newpassword2="password456";
		//给用户赋putgetdelUser权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		
		String policyName="createPolicyFormatch";
		List<Condition> conditions = new ArrayList<Condition>();
	    conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test01*")));
	    
		createPolicy(Effect.Deny,policyName,"Action",Arrays.asList("iam:GetUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),conditions);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		String createresult=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 403);
		String updateresult=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 403);
		String getresult=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 403);
		String delresult=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 403);
		
		//给组添加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);

		String createresult2=IAMInterfaceTestUtils.CreateLoginProfile(userak2, usersk2, userName, newpassword, 403);
		String updateresult2=IAMInterfaceTestUtils.UpdateLoginProfile(userak2, usersk2, userName, newpassword2, 403);
		String getresult2=IAMInterfaceTestUtils.GetLoginProfile(userak2, usersk2, userName, 403);
		String delresult2=IAMInterfaceTestUtils.DeleteLoginProfile(userak2, usersk2, userName, 403);

		//给用户添加allow策略
		String policyNameallow="loginprofileperssion";
		UseraboutPolicies(accessKey,secretKey,"loginprofileperssion",userName1,policyNameallow);
		String createresult3=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 200);
		String updateresult3=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 200);
		String getresult3=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 200);
		String delresult3=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 200);
	
		//移除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		
		//删除用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyNameallow, 200);
		//移除组中策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}

	/**
	 * 与deny策略不匹配，隐式拒绝
	 * 添加allow策略，验证是否与allow策略匹配
	 * 如果匹配则允许访问，若不匹配则隐式拒绝
	 * **/
	@Test
	public void test_createGetUpdateDelLogionProfile_deny_notmatch_resource() throws Exception{
		String newpassword="password123";
		String newpassword2="password456";
		//给用户赋putgetdelUser权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		
		String policyName="createPolicyFormatch";
		List<Condition> conditions = new ArrayList<Condition>();
	    conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test01*")));
	    
		createPolicy(Effect.Deny,policyName,"Action",Arrays.asList("iam:CreateLoginProfile","iam:GetLoginProfile","iam:UpdateLoginProfile","iam:DeleteLoginProfile"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:USER/*"),conditions);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		String createresult=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 403);
		String updateresult=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 403);
		String getresult=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 403);
		String delresult=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 403);
		
		//给组添加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);

		String createresult2=IAMInterfaceTestUtils.CreateLoginProfile(userak2, usersk2, userName, newpassword, 403);
		String updateresult2=IAMInterfaceTestUtils.UpdateLoginProfile(userak2, usersk2, userName, newpassword2, 403);
		String getresult2=IAMInterfaceTestUtils.GetLoginProfile(userak2, usersk2, userName, 403);
		String delresult2=IAMInterfaceTestUtils.DeleteLoginProfile(userak2, usersk2, userName, 403);

		//给用户添加allow策略
		String policyNameallow="loginprofileperssion";
		UseraboutPolicies(accessKey,secretKey,"loginprofileperssion",userName1,policyNameallow);
		String createresult3=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 200);
		String updateresult3=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 200);
		String getresult3=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 200);
		String delresult3=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 200);
	
		//移除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		
		//删除用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyNameallow, 200);
		//移除组中策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}
	
	/**
	 * 与deny策略不匹配，隐式拒绝
	 * 添加allow策略，验证是否与allow策略匹配
	 * 如果匹配则允许访问，若不匹配则隐式拒绝
	 * **/
	@Test
	public void test_createGetUpdateDelLogionProfile_deny_notmatch_allowpolicy() throws Exception{
		String newpassword="password123";
		String newpassword2="password456";
		//给用户赋putgetdelUser权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		
		String policyName="createPolicyFormatch";
		List<Condition> conditions = new ArrayList<Condition>();
	    conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test01*")));
	    
		createPolicy(Effect.Deny,policyName,"Action",Arrays.asList("iam:CreateLoginProfile","iam:GetLoginProfile","iam:UpdateLoginProfile","iam:DeleteLoginProfile"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:USER/*"),conditions);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		String createresult=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 403);
		String updateresult=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 403);
		String getresult=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 403);
		String delresult=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 403);
		
		//给组添加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);

		String createresult2=IAMInterfaceTestUtils.CreateLoginProfile(userak2, usersk2, userName, newpassword, 403);
		String updateresult2=IAMInterfaceTestUtils.UpdateLoginProfile(userak2, usersk2, userName, newpassword2, 403);
		String getresult2=IAMInterfaceTestUtils.GetLoginProfile(userak2, usersk2, userName, 403);
		String delresult2=IAMInterfaceTestUtils.DeleteLoginProfile(userak2, usersk2, userName, 403);

		//给用户添加allow策略,策略为不允许访问
		String policyNameallow="denyloginprofile";
		attacheUserallowedPolicy_deny(userName1,policyNameallow);
		String createresult3=IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newpassword, 403);
		String updateresult3=IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newpassword2, 403);
		String getresult3=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 403);
		String delresult3=IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 403);
	
		//移除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		
		//删除用户
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyNameallow, 200);
		//移除组中策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}
	
	
	/**
	 * 只有一个allow策略
	 * **/
	@Test
	public void test_ListUsers_allow() throws Exception{
		//给用户赋putgetdelUser权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName2,policyName1);
		//创建用户
		String userName="createbyuser";
		for(int i=0;i<10;i++){
			createUser(userName+i,userak1,usersk1);
		}
			
		String policyName="createPolicyFormatch";
		List<Condition> conditions = new ArrayList<Condition>();
	    conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test01*")));
	    
	    //allow策略匹配，resource为user/*，无condition
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:ListUsers"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		String listresult=IAMInterfaceTestUtils.ListUsers(userak1, usersk1, 200);
		
		//给组添加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		String listResult=IAMInterfaceTestUtils.ListUsers(userak2, usersk2, 200);
		
		//修改allow策略，allow策略匹配，resource为*，无condition		
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:ListUsers"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"),null);		
		String listresult2=IAMInterfaceTestUtils.ListUsers(userak1, usersk1, 200);		
		String listResult2=IAMInterfaceTestUtils.ListUsers(userak2, usersk2, 200);
		
		//修改allow策略，allow策略匹配，resource为user/userName
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:ListUsers"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/"+userName1,"arn:ctyun:iam::0000000gc0uy9:user/"+userName2),null);		
		String listresult6=IAMInterfaceTestUtils.ListUsers(userak1, usersk1, 403);		
		String listResult6=IAMInterfaceTestUtils.ListUsers(userak2, usersk2, 403);
		
		//修改allow策略，allow策略匹配，resource为*，有condition		
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:ListUsers"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"),conditions);		
		String listresult3=IAMInterfaceTestUtils.ListUsers(userak1, usersk1, 200);		
		String listResult3=IAMInterfaceTestUtils.ListUsers(userak2, usersk2, 200);
		
		//修改allow策略，NotAction
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:GetUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"),null);		
		String listresult4=IAMInterfaceTestUtils.ListUsers(userak1, usersk1, 200);
		String listResult4=IAMInterfaceTestUtils.ListUsers(userak2, usersk2, 200);
		attachPolicyToUser(userName3,policyArn);
		String getUserresult=IAMInterfaceTestUtils.GetUser(userak3, usersk3, userName, 403);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName3, policyName, 200);
		
		//修改allow策略，NotAction
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:ListUsers"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"),null);		
		String listresult5=IAMInterfaceTestUtils.ListUsers(userak1, usersk1, 403);
		String listResult5=IAMInterfaceTestUtils.ListUsers(userak2, usersk2, 403);
		
		//修改allow策略NotResource
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:ListUsers"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/"+userName),null);		
		String listresult7=IAMInterfaceTestUtils.ListUsers(userak1, usersk1, 200);
		String listResult7=IAMInterfaceTestUtils.ListUsers(userak2, usersk2, 200);
		
		//修改allow策略NotResource
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:ListUsers"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);		
		String listresult8=IAMInterfaceTestUtils.ListUsers(userak1, usersk1, 403);
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:ListUsers"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"),null);
		String listResult8=IAMInterfaceTestUtils.ListUsers(userak2, usersk2, 403);
		
		//修改allow策略，NotAction，NotResource
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:GetUser"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/"+userName),null);		
		String listresult9=IAMInterfaceTestUtils.ListUsers(userak1, usersk1, 200);
		String listResult9=IAMInterfaceTestUtils.ListUsers(userak2, usersk2, 200);
		
		//修改allow策略,NotAction,NotResource
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:ListUsers"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);		
		String listresult10=IAMInterfaceTestUtils.ListUsers(userak1, usersk1, 403);
		createPolicy(Effect.Allow,policyName,"NotAction",Arrays.asList("iam:ListUsers"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"),null);
		String listResult10=IAMInterfaceTestUtils.ListUsers(userak2, usersk2, 403);	
		
		//修改allow策略，allow策略匹配，resource为*，有condition,condition不匹配		
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:ListUsers"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"),conditions);	
		attachPolicyToUser(userName21,policyArn);
		String listresult11=IAMInterfaceTestUtils.ListUsers(userak21, usersk21, 403);		

		//移除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		
		//删除用户
		for(int i=0;i<10;i++)
			IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName+i, 200);
		
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName2, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName21, policyName1, 200);
		//移除组中策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
	}	
	
	/**
	 * deny策略
	 * 添加allow策略
	 * ***/
	@Test
	public void test_listUsers_deny() throws Exception{
		//给用户赋putgetdelUser权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName2,policyName1);
		//创建用户
		String userName="createbyuser";
		for(int i=0;i<10;i++)
			createUser(userName+i,userak1,usersk1);
		
					
		String policyName="createPolicyFormatch";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test01*")));
			    
		//deny策略匹配
		createPolicy(Effect.Deny,policyName,"Action",Arrays.asList("iam:ListUsers"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		String listresult=IAMInterfaceTestUtils.ListUsers(userak1, usersk1, 403);
		
		String policyName2="listusersperssion";
		UseraboutPolicies(accessKey,secretKey,"listusersperssion",userName1,policyName2);
		
		//添加策略到用户组
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		String listResult=IAMInterfaceTestUtils.ListUsers(userak2, usersk2, 403);
		
		//修改deny策略，deny策略匹配，NotAction
		createPolicy(Effect.Deny,policyName,"NotAction",Arrays.asList("iam:List"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);
		String listresult2=IAMInterfaceTestUtils.ListUsers(userak1, usersk1, 403);
		createPolicy(Effect.Deny,policyName,"NotAction",Arrays.asList("iam:List"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"),null);
		String listResult2=IAMInterfaceTestUtils.ListUsers(userak2, usersk2, 403);
		
		//deny策略，NotResource
		createPolicy(Effect.Deny,policyName,"Action",Arrays.asList("iam:ListUsers"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:USER/*"),null);
		String listresult3=IAMInterfaceTestUtils.ListUsers(userak1, usersk1, 403);
		
		//deny策略，NotActionNotResource
		createPolicy(Effect.Deny,policyName,"NotAction",Arrays.asList("iam:List"),"NotResource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:USER/*"),null);
		String listresult4=IAMInterfaceTestUtils.ListUsers(userak1, usersk1, 403);
		
		//deny策略，conditions，不匹配
		createPolicy(Effect.Deny,policyName,"Action",Arrays.asList("iam:ListUsers"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),conditions);
		attachPolicyToUser(userName21,policyArn);
		String listresult5=IAMInterfaceTestUtils.ListUsers(userak21, usersk21, 403);
		UseraboutPolicies(accessKey,secretKey,"listusersperssion",userName21,policyName2);
		String listResult5=IAMInterfaceTestUtils.ListUsers(userak21, usersk21, 200);
	
		//deny策略，conditions匹配，action不匹配
		createPolicy(Effect.Deny,policyName,"Action",Arrays.asList("iam:GetUsers"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),conditions);
		String listresult6=IAMInterfaceTestUtils.ListUsers(userak1, usersk1, 200);
		
		//deny策略，resource不匹配
		createPolicy(Effect.Deny,policyName,"Action",Arrays.asList("iam:ListUsers"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:USER/*"),conditions);
		String listresult7=IAMInterfaceTestUtils.ListUsers(userak1, usersk1, 200);
		
		//移除allow允许策略，添加allow拒绝策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		String policyName3="allowPolicyNotMatch";
		attacheUserallowedPolicy_deny(userName1,policyName3);
		String listresult8=IAMInterfaceTestUtils.ListUsers(userak1, usersk1, 403);

		//移除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		//删除用户
		for(int i=0;i<10;i++)
			IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName+i, 200);
		
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName21, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName21, policyName2, 200);
		//移除组中策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
	}
	
	/**
	 * 同一账户下的普通用户只要有权限（policy允许），可以操作该账户下的用户
	 * 
	 * **/
	@Test
	public void test_userauthority() throws Exception{
		//用户有创建获取删除用户的权限
		String policyName1="permitputgetdelUser";
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName1,policyName1);
		UseraboutPolicies(accessKey,secretKey,"creategetdeluserperssion",userName2,policyName1);
		//创建用户
		String userName="createbyuser";
		createUser(userName,userak1,usersk1);
		String userName02="createbyuser02";
		createUser(userName02,userak2,usersk2);
		
		String test=IAMInterfaceTestUtils.GetUser(userak1, usersk1, userName02, 200);
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName02, 200);
		
		//user3没有添加策略，无限权
		IAMInterfaceTestUtils.GetUser(userak3, userak3, userName, 403);
		
		//删除用户，并移除策略
		IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName2, policyName1, 200);
	}
	

	/**
	 * action不区分大小写
	 * iam:CreateUser与IAM:createuser相同
	 * 
	 * 测试未通过，区分大小写，注意因为使用的MatchUtils.isMatch()是与resources公用的，如果修改的话需要看一下resources
	 * 与产品确认，需求变更，待需求确定中
	 * 需求修改为actions的前缀和操作为严格匹配，前缀为小写
	 * ***/
	@Test
	public void test_actionsCaseMatch()throws Exception{
		String userName="testforCaseMatch";
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser","iam:ListGroupsForUser","iam:ListGroupsForUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		
		String createUserResult=IAMInterfaceTestUtils.CreateUser(userak1, usersk1, userName, 403);		
		System.out.print(createUserResult);
		JSONObject resultcreateAssert=IAMTestUtils.ParseErrorToJson(createUserResult);
		assertEquals("AccessDenied",resultcreateAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",resultcreateAssert.get("Message"));
		
		String getuserResult=IAMInterfaceTestUtils.GetUser(userak1, usersk1, userName,403);
		System.out.println(getuserResult);
		JSONObject getresultAssert=IAMTestUtils.ParseErrorToJson(getuserResult);
		assertEquals("AccessDenied",getresultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",getresultAssert.get("Message"));
		
		String deluserResult=IAMInterfaceTestUtils.DeleteUser(userak1, usersk1, userName, 403);
		System.out.println(deluserResult);
		JSONObject delresultAssert=IAMTestUtils.ParseErrorToJson(deluserResult);
		assertEquals("AccessDenied",delresultAssert.get("Code"));
		assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName1+" is not authorized to perform: iam:DeleteUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+userName+".",delresultAssert.get("Message"));
		
		//修改策略为严格匹配
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateUser","iam:DeleteUser"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);
		
		//将用户user2添加到组，组附加策略
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
			
		//user2有创建用户的权限
		String userName02="CreateUserbyUser02";
		String createResult=IAMInterfaceTestUtils.CreateUser(userak2, usersk2, userName02, 200);		
		JSONObject createAssert=ParseXmlToJson("CreateUser",createResult);
		assertEquals(userName02,createAssert.get("UserName"));
		assertEquals("arn:ctyun:iam::0000000gc0uy9:user/"+userName02,createAssert.get("Arn"));
		assertNotNull(createAssert.get("UserId"));
		//删除用户
		String delResult=IAMInterfaceTestUtils.DeleteUser(userak2, usersk2, userName02, 200);
		
		//移除用户中的策略
		detachPolicyFromUser(userName1,policyArn);
		//移除组中的策略
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);		
	}	
	

	/**
	 * actions使用通配符
	 * 
	 * */
	@Test
	public void test_actionsUsewildcard() throws Exception{
		User user=new User();
		user.accountId=accountId;
		user.userName=userName2;
		user=HBaseUtils.get(user);
		if(user.password !=null)
			IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, userName2, 200);
		String policyName="createPolicyFormatch";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:Get*"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"),null);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName1,policyArn);
		//给user2创建loginProfile
		IAMInterfaceTestUtils.CreateLoginProfile(accessKey, secretKey, userName2, "password123", 200);
		//满足action为Get*,且resource为user/*的操作为：GetLoginProfile，GetUser，GetAccessKeyLastUsed，其他操作不允许
		String getuserresult=IAMInterfaceTestUtils.GetUser(userak1, usersk1, userName2, 200);
		String getloginprofile=IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName2, 200);
		//GetAccessKeyLastUsed该接口删除
//		String getlastusedresult=IAMInterfaceTestUtils.GetAccessKeyLastUsed(userak1, usersk1, userak2, 200);

		//移除策略
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
	}
	
	
	/**
	 * 未匹配策略的用户
	 * */
	@Test
	public void test_nopolicy()throws Exception{
		
		//发送CreateUser请求，因与策略匹配，CreateUser失败
		String userName="createUserbyUser";
		String newPassword="newpassword123";
		String user1bxmlString=IAMInterfaceTestUtils.CreateUser(userak2, usersk2,userName,403);
		JSONObject error2=IAMTestUtils.ParseErrorToJson(user1bxmlString);
	    assertEquals("AccessDenied", error2.get("Code"));
	    assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:CreateUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+ userName+".", error2.get("Message"));
	    assertEquals("createUserbyUser", error2.get("Resource"));	
	    
	    String  listresult=IAMInterfaceTestUtils.ListGroupsForUser(userak2, usersk2,userName,403);
	    
		String user1get=IAMInterfaceTestUtils.GetUser(userak2, usersk2,userName,403);
		JSONObject errorget=IAMTestUtils.ParseErrorToJson(user1get);
	    assertEquals("AccessDenied", errorget.get("Code"));
	    assertEquals("User: arn:ctyun:iam::0000000gc0uy9:user/"+userName2+" is not authorized to perform: iam:GetUser on resource: arn:ctyun:iam::0000000gc0uy9:user/"+ userName +".", errorget.get("Message"));
	    assertEquals("createUserbyUser", errorget.get("Resource"));

		String bodydel="Action=DeleteUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, userak1, usersk1);
		assertEquals(403, resultdel.first().intValue());
		
		List<Pair<String, String>> tags=new ArrayList<>();
		Pair<String,String> tag1=new Pair<>();
		tag1.first("tag1Key");
		tag1.second("tag1Value");
		Pair<String,String> tag2=new Pair<>();
		tag2.first("tag2Key");
		tag2.second("tag2Value");
		tags.add(tag1);
		tags.add(tag2);
		List<String> tagKeys=new ArrayList<>();
		tagKeys.add(tag1.first());
		tagKeys.add(tag2.first());
		IAMInterfaceTestUtils.TagUser(userak2, usersk2, userName, tags, 403);
		IAMInterfaceTestUtils.UntagUser(userak1, usersk1, userName, tagKeys, 403);
		IAMInterfaceTestUtils.ListUserTags(userak1, usersk1, userName, 403);
		
		IAMInterfaceTestUtils.CreateLoginProfile(userak1, usersk1, userName, newPassword, 403);
		IAMInterfaceTestUtils.GetLoginProfile(userak1, usersk1, userName, 403);
		IAMInterfaceTestUtils.UpdateLoginProfile(userak1, usersk1, userName, newPassword, 403);
		IAMInterfaceTestUtils.DeleteLoginProfile(userak1, usersk1, userName, 403);		
		IAMInterfaceTestUtils.ListUsers(userak1, usersk1, 403);

	}

	
//	@Test
	public void test_createUser()throws Exception{
		createUser(userName3);
		//createUser(userName1);
	}
	
	//创建
	public void UseraboutPolicies(String ak, String sk,String action,String userName,String policyName) throws Exception{

		if(action.equals("creategetdeluserperssion")){
			//创建允许createUser的policy
			createPolicy(ak, sk, Effect.Allow, policyName, "Action", Arrays.asList("iam:CreateUser","iam:DeleteUser","iam:GetUser","iam:ListGroupsForUser"), "Resource", Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"), null);
			String policyArn="arn:ctyun:iam::"+ accountId +":policy/"+policyName;
//			attachPolicyToUser(userName,policyArn);
			IAMInterfaceTestUtils.AttachUserPolicy(ak, sk, accountId, userName, policyName, 200);
		}
//		if(action.equals("cancelputgetdeluserpersion")){
//			IAMInterfaceTestUtils.DetachUserPolicy(ak, sk, accountId, userName, policyName, 200);
//		}
		
		if(action.equals("tagUntagListperssion")){
			createPolicy(ak,sk,Effect.Allow,policyName,"Action",Arrays.asList("iam:TagUser","iam:UntagUser","iam:ListUserTags"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
			String policyArn="arn:ctyun:iam::"+ accountId +":policy/"+policyName;
			IAMInterfaceTestUtils.AttachUserPolicy(ak, sk, accountId, userName, policyName, 200);
		}
		if(action.equals("loginprofileperssion")){
			createPolicy(ak,sk,Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateLoginProfile","iam:GetLoginProfile","iam:UpdateLoginProfile","iam:DeleteLoginProfile"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
			String policyArn="arn:ctyun:iam::"+ accountId +":policy/"+policyName;
			IAMInterfaceTestUtils.AttachUserPolicy(ak, sk, accountId, userName, policyName, 200);
		}
		if(action.equals("listusersperssion")){
			createPolicy(ak,sk,Effect.Allow,policyName,"Action",Arrays.asList("iam:ListUsers"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":*"),null);
			String policyArn="arn:ctyun:iam::"+ accountId +":policy/"+policyName;
			IAMInterfaceTestUtils.AttachUserPolicy(ak, sk, accountId, userName, policyName, 200);
		}
	}
	
	//通用allow策略，有权限
	public static String attacheUserallowedPolicy_allow(String userName,String policyName, List<String> actions, List<String> resources)throws Exception{
		List<Condition> conditions = new ArrayList<Condition>();
	    conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test01*")));	        		
		createPolicy(Effect.Allow,policyName,"Action",actions,"Resource",resources,conditions);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName,policyArn);
		return policyArn;
	}
	//通用allow，无权限
	public static String attacheUserallowedPolicy_deny(String userName,String policyName)throws Exception{
		List<Condition> conditions = new ArrayList<Condition>();
	    conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test01*")));
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:Create","iam:Delete","iam:Get"),"Resource",Arrays.asList("arn:ctyun:iam::0000000gc0uy9:notMatch"),conditions);
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		attachPolicyToUser(userName,policyArn);
		return policyArn;
	}
	
	//创建策略
	public static void createPolicy(Effect effect,String policyName,String actionEffect,List<String> actions,String resourceEffect,List<String> resources,List<Condition> conditions)throws Exception{
		String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(effect,null, null, actionEffect, actions, resourceEffect, resources, conditions);
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName="+URLEncoder.encode(policyName)+"&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=test_des";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
	}
	public static void createPolicy(String ak, String sk,Effect effect,String policyName,String actionEffect,List<String> actions,String resourceEffect,List<String> resources,List<Condition> conditions)throws Exception{
		String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(effect,null, null, actionEffect, actions, resourceEffect, resources, conditions);
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName="+URLEncoder.encode(policyName)+"&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=test_des";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
	}
		
	//策略添加到用户
	public static void attachPolicyToUser(String userName,String policyArn)throws Exception{
		String bodyAttach="Action=AttachUserPolicy&Version=2010-05-08&UserName="+ userName +"&PolicyArn="+URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
	}
	public static void attachPolicyToUser(String userName,String policyArn,String ak, String sk)throws Exception{
		String bodyAttach="Action=AttachUserPolicy&Version=2010-05-08&UserName="+ userName +"&PolicyArn="+URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
	}
	
	public void detachPolicyFromUser(String userName,String policyArn)throws Exception{		
		//从组中删除策略
		String body="Action=DetachUserPolicy&Version=2010-05-08&UserName="+ userName+"&PolicyArn=" + URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
	}
	
	//创建子用户
	public static void createUser(String userName)throws Exception{
		//创建用户
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		System.out.print(resultPair.second());
		//给用户创建aksk
		String body2="Action=CreateAccessKey&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> result=IAMTestUtils.invokeHttpsRequest(body2, accessKey, secretKey);
		assertEquals(200, result.first().intValue());
		System.out.print(result.second());
		
		
	}
	public static void createUser(String userName,String ak,String sk)throws Exception{
		//创建用户
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
		assertEquals(200, resultPair.first().intValue());
		System.out.print(resultPair.second());
	}
	
	public static JSONObject ParseXmlToJson(String action ,String xml) {
		try {
			StringReader sr = new StringReader(xml);
	        InputSource is = new InputSource(sr);
	        Document doc = (new SAXBuilder()).build(is);
	        Element root = null ;
	        if("CreateUser".equals(action))
	        	root = doc.getRootElement().getChild("CreateUserResult").getChild("User");
	        if("GetUser".equals(action))
	        	root = doc.getRootElement().getChild("GetUserResult").getChild("User");
	        List<Element> children=root.getChildren();
	        Iterator<Element> iterator=children.iterator();
	        JSONObject jObject= new JSONObject();
	        while(iterator.hasNext()){
	        	Element root2 = iterator.next();
	        	String key=root2.getName();
	        	if(key.equals("Tags")){
	        		List<Element> tags=root2.getChildren("member");
	        		Iterator<Element> tagiterator=tags.iterator();
	        		int i=1;
	        		while(tagiterator.hasNext()){	        			
        	        	Element roottag = tagiterator.next();
        	        	String tagkey=roottag.getChild("Key").getValue();
        	        	String tagvalue=roottag.getChild("Value").getValue();
        	        	Map<String,String> map=new HashMap<String,String>();
        	        	map.put("Key", tagkey);
        	        	map.put("Value", tagvalue);
        	        	i++;        	        	
        	        }
	        			
	        	}else{
	        		String value=root2.getValue();		        	
		        	jObject.put(key, value);
	        	}
	        }
	        return jObject;
	        
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
        return null;
        
	}
	
	
}
