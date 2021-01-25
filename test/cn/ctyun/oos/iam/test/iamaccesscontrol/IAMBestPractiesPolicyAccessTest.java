package cn.ctyun.oos.iam.test.iamaccesscontrol;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;
import org.eclipse.jetty.util.UrlEncoded;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import cn.ctyun.oos.hbase.HBaseUtil;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.Condition;
import cn.ctyun.oos.iam.accesscontroller.util.IAMStringUtils;
import cn.ctyun.oos.iam.server.action.Action;
import cn.ctyun.oos.iam.server.action.ActionMethod;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.action.IAMActions;
import cn.ctyun.oos.iam.server.entity.MFADevice;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.server.util.ClasspathPackageScanner;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.metadata.OwnerMeta;
import common.tuple.Pair;


/**
 * 添加预设策略（需求文档21）/示例策略（需求文档22）中的case
 * 最佳实践
 * **/
public class IAMBestPractiesPolicyAccessTest {
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
	public static String userak1="720856c72a3a7fd9d956";
	public static String usersk1="221cb03e64315bac85f6f0ad3c1b4a071ce96018";
	
	//用户策略未添加到用户，但是添加到用户所在的组
	public static String userName2="test01_subUser02";
	public static String userak2="ef215b15446753d0128b";
	public static String usersk2="1af660f75d449ce9b1730dd8e02c714a59bfb4ae";
	
	//未添加任何策略，未加入组
	public static String userName3="test01_subUser03";
	public static String userak3="96af715c31bf9e6870c2";
	public static String usersk3="68b343f734169dc7bfac631dded3533e6addd97e";
	
	//conditon中不满足条件的userName
	public static String userName21="test02_subUser01";
	public static String userak21="de0248dcea98337e488e";
	public static String usersk21="02bb31faa74aa77460425b4589bcf98724a10119";
	
	public static MetaClient metaClient = MetaClient.getGlobalClient();
	public static String groupName="createGroupForTest";
	public static String userName="createUserForTest";
	public static String policyName="createforTest";
	
	
	String oldPassword="password123";
	static String virtualMFADeciveName="createVirtualMFADeciveNameForTest";
	static String akId=null;




	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		//有create Group权限
		String createpolicy="createpolicyfortest";
		createPolicy(Effect.Allow,createpolicy,"Action",Arrays.asList("iam:CreateGroup","iam:CreateUser","iam:CreateAccessKey","iam:CreatePolicy","iam:TagUser","iam:CreateVirtualMFADevice"),"Resource",Arrays.asList("*"),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, createpolicy, 200);
		IAMInterfaceTestUtils.CreateGroup(userak1, usersk1, groupName, 200);
		IAMInterfaceTestUtils.CreateUser(userak1, usersk1, userName, 200);
		IAMInterfaceTestUtils.CreateAccessKey(userak1, usersk1, userName, 200);
		IAMInterfaceTestUtils.CreateMFADevice(userak1, usersk1, virtualMFADeciveName, 200);
		createPolicy(userak1, usersk1,Effect.Allow, policyName,"Action",Arrays.asList("iam:create"),"Resource",Arrays.asList("arn:ctyun:iam::000000:*"),null);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, createpolicy, 200);
	
	}

//	@Before
	public void setUp() throws Exception {
		
	}
	@AfterClass
	public static void afterClass()throws Exception{
		User user=new User();
		user.accountId=accountId;
		user.userName=userName;
		user=HBaseUtils.get(user);
		if (user.accessKeys!=null && user.accessKeys.size()>0){
			for(int i=0;i<user.accessKeys.size();i++){
				IAMInterfaceTestUtils.DeleteAccessKey(accessKey, secretKey, user.accessKeys.get(i), userName, 200);
			}
		}
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, virtualMFADeciveName, 200);
		IAMInterfaceTestUtils.DeleteGroup(accessKey, secretKey, groupName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, "createpolicyfortest", 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DeleteUser(accessKey, secretKey, userName, 200);
	}
	
	/**
	 * 预设策略AdministratorAccess
	 * 用户只可使用，不可修改,策略类型是：系统策略(因本期不做系统策略，系统策略类型全部按照自定义策略类型来设置)
	 * */
	@Test
	public void createPolicy_AdministratorAccess() throws Exception{
		String policyName="AdministratorAccess";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("*"),"Resource",Arrays.asList("*"),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		List<String> actions=getActionsName(Arrays.asList("AccessKey","Account","Group","User","MFA","Policy"));
		validateInterface(actions,userak1,usersk1);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}

	/**
	 * 预设策略IAMFullAccess
	 * */
	@Test
	public void test_iamFullAccess() throws Exception{
		String policyName="iamFullAccess";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("*"),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		List<String> actions=getActionsName(Arrays.asList("AccessKey","Account","Group","User","MFA","Policy"));
		validateInterface(actions,userak1,usersk1);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	
	/**
	 *预设策略IAMReadOnlyAccess
	 * */
	@Test
	public void test_iamReadOnlyAccess() throws Exception{
		String policyName="iamReadOnlyAccess";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:Get*","iam:List*"),"Resource",Arrays.asList("*"),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		List<String> actions=getActionsName(Arrays.asList("Get","List"));
		validateInterface(actions,userak1,usersk1);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
		
	/**
	 *预设策略 更改密码，获取passwordpolicy策略
	 * **/
	@Test
	public void test_IAMUserChangePassword() throws Exception{
		String policyName="IAMUserChangePassword";
		String newPassword="newpassword123";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:ChangePassword","iam:GetAccountPasswordPolicy"),"Resource",Arrays.asList("*"),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.GetAccountPasswordPolicy(userak1, usersk1, 200);
		
		IAMInterfaceTestUtils.CreateLoginProfile(accessKey, secretKey, userName1, oldPassword, 200);
		IAMInterfaceTestUtils.ChangePassword(userak1, usersk1, userName1, oldPassword, newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, userName1, 200);
		
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	/**
	 * 示例策略：允许在特定日期内访问
	 * **/
	@Test
	public void test_allowAccessInSpecialdate()throws Exception{
		String policyName="allowAccessInSpecialDate";
		List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("DateGreaterThan","ctyun:CurrentTime",Arrays.asList("2019-01-01T00:00:00Z")));
        conditions.add(IAMTestUtils.CreateCondition("DateLessThan","ctyun:CurrentTime",Arrays.asList("2019-09-12T00:00:00Z")));
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:GetUser"),"Resource",Arrays.asList("*"),conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.GetUser(userak1, usersk1, userName, 200);
		
		List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("DateGreaterThan","ctyun:CurrentTime",Arrays.asList("2019-01-01T00:00:00Z")));
        conditions2.add(IAMTestUtils.CreateCondition("DateLessThan","ctyun:CurrentTime",Arrays.asList("2019-09-11T00:00:00Z")));
        createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:GetUser"),"Resource",Arrays.asList("*"),conditions2);
        IAMInterfaceTestUtils.GetUser(userak1, usersk1, userName, 403);
		
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	
	/**
	 * 示例策略：基于源IP拒绝对OOS的访问
	 * **/
	@Test
	public void test_denyAccessBasedOnIpAddress()throws Exception{
		String policyName="denyAccessBasedOnIpAddress";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("NotIpAddress","ctyun:SourceIp",Arrays.asList("192.0.2.0/24","203.0.113.0/24")));
		createPolicy(Effect.Deny,policyName,"Action",Arrays.asList("*"),"Resource",Arrays.asList("*"),conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		
		String body="Action=GetUser&Version=2010-05-08&UserName="+userName;
		List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
		Pair<String, String>  param1= new Pair<String, String>();
	    param1.first("X-Forwarded-For");
	    param1.second("192.168.2.101");
	    params.add(param1);
	    Pair<Integer,String> getresult=IAMTestUtils.invokeHttpsRequest2(body, userak1, usersk1,params);
	    assertEquals(403, getresult.first().intValue());
	    
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	
	
	/**
	 * 示例策略：允许在特定日期内使用MFA进行特定访问
	 * **/
	@Test
	public void test_allowAccessUseMFAInSpecialdate()throws Exception{
		String policyName="allowAccessInSpecialDate";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("Bool","ctyun:MultiFactorAuthPresent",Arrays.asList("true")));
        conditions.add(IAMTestUtils.CreateCondition("DateGreaterThan","ctyun:CurrentTime",Arrays.asList("2019-01-01T00:00:00Z")));
        conditions.add(IAMTestUtils.CreateCondition("DateLessThan","ctyun:CurrentTime",Arrays.asList("2019-09-12T00:00:00Z")));
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("*"),conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		
		IAMInterfaceTestUtils.GetUser(userak1, usersk1, userName1, 403);

		String body="Action=GetUser&Version=2010-05-08&UserName="+userName;
		List<Pair<String, String>> params=new ArrayList<Pair<String,String>>();
		Pair<String, String>  param1= new Pair<String, String>();
	    param1.first("Multi-Factor-Auth-Present");
	    param1.second("true");
	    params.add(param1);
	    Pair<Integer,String> getresult=IAMTestUtils.invokeHttpsRequest2(body, userak1, usersk1,params);
	    assertEquals(200,getresult.first().intValue());
		
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	
	
	/**
	 * 涉及到策略变量，本期没有，下一期（11月）进行测试
	 * **/
	public void test_()throws Exception{
		 List<Statement> statements= new ArrayList<Statement>();
	     Statement s1=IAMTestUtils.CreateStatement(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListUsers","iam:ListVirtualMFADevices"),"Resource",Arrays.asList("*"),null);
	     statements.add(s1);
	    
	     Statement s2=IAMTestUtils.CreateStatement(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListMFADevices"),"Resource",Arrays.asList("arn:ctyun:iam::*:mfa/*","arn:ctyun:iam::*:user/${ctyun:username}"),null);
	     statements.add(s2);
	     
	     Statement s3=IAMTestUtils.CreateStatement(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateVirtualMFADevice","iam:DeleteVirtualMFADevice","iam:EnableMFADevice"),"Resource",Arrays.asList("arn:ctyun:iam::*:mfa/${ctyun:username}","arn:ctyun:iam::*:user/${ctyun:username}"),null);
	     statements.add(s3);
	     
	     List<Condition> conditions = new ArrayList<Condition>();
	     conditions.add(IAMTestUtils.CreateCondition("Bool","ctyun:MultiFactorAuthPresent",Arrays.asList("true")));
	     Statement s4=IAMTestUtils.CreateStatement(Effect.Allow,null,null,"Action",Arrays.asList("iam:DeactivateMFADevice"),"Resource",Arrays.asList("arn:ctyun:iam::*:mfa/${ctyun:username}","arn:ctyun:iam::*:user/${ctyun:username}"),conditions);
	     statements.add(s4);
	     
	     List<Condition> conditions2 = new ArrayList<Condition>();
	     conditions2.add(IAMTestUtils.CreateCondition("BoolIfExists","ctyun:MultiFactorAuthPresent",Arrays.asList("false")));
	     Statement s5=IAMTestUtils.CreateStatement(Effect.Deny,null,null,"NotAction",Arrays.asList("iam:CreateVirtualMFADevice","iam:EnableMFADevice","iam:ListMFADevices","iam:ListUsers","iam:ListVirtualMFADevices"),"Resource",Arrays.asList("*"),null);
	     statements.add(s5);
	     
	     String policyString=IAMTestUtils.CreateMoreStatement(statements);
	     IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
	     
	     
	     //
	        
	}
	
	//验证
	public void validateInterface(List<String> actions, String ak, String sk)throws Exception{
		//actionsList所有Actions
		List<String> actionsList=new LinkedList<>();
		actionsList=getActionsName(Arrays.asList("Access","Account","Group","User","Policy","MFA"));
        Iterator<String> iterator=actionsList.iterator();
        Integer expectedCode;
        String action=null;
        String result=null;
        while(iterator.hasNext()){
        	action=iterator.next();
        	//后续有需要，进行优化（只适用于action和resource正确且匹配）
        	expectedCode=actions.contains(action)?200:403;
        	switch(action){
        		case "CreateGroup":
        			result=IAMInterfaceTestUtils.CreateGroup(ak, sk, "createGroup1", expectedCode);
        			if(expectedCode==200)
        				IAMInterfaceTestUtils.DeleteGroup(accessKey, secretKey, "createGroup1", 200);
        			System.out.println("创建group"+result);
        			break;
        		case "GetGroup":
        			result=IAMInterfaceTestUtils.GetGroup(ak, sk, groupName, expectedCode);
        			System.out.println(result);
        			break;
        		case "ListGroups":
        			result=IAMInterfaceTestUtils.ListGroups(ak, sk, groupName, expectedCode);
        			System.out.println(result);
        			break;
        		case "DeleteGroup":
        			IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, "creategroupfortestdelgroup", 200);
        			result=IAMInterfaceTestUtils.DeleteGroup(ak, sk, "creategroupfortestdelgroup", expectedCode);
        			if(expectedCode==403)
        				IAMInterfaceTestUtils.DeleteGroup(accessKey, secretKey, "creategroupfortestdelgroup", 200);
        			System.out.println(result);
        			break;
        		case "AddUserToGroup":
        			result= IAMInterfaceTestUtils.AddUserToGroup(ak, sk, groupName, userName, expectedCode);
        			if(expectedCode==200)
        				IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName, 200);
        			System.out.println(result);
        			break;
        		case "RemoveUserFromGroup":
        			IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName, 200);
        			result=IAMInterfaceTestUtils.RemoveUserFromGroup(ak, sk, groupName, userName, expectedCode);
        			if(expectedCode==403)
        				IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName, 200);
        			System.out.println(result);
        			break;
        		case "CreateUser":
        			result=IAMInterfaceTestUtils.CreateUser(ak, sk, "createuser1", expectedCode);
        			if(expectedCode==200)
        				IAMInterfaceTestUtils.DeleteUser(accessKey, secretKey, "createuser1", 200);
        			System.out.println(result);
        			break;
        		case "GetUser":
        			result=IAMInterfaceTestUtils.GetUser(ak, sk, userName, expectedCode);
        			System.out.println(result);
        			break;
        		case "ListUsers":
        			result=IAMInterfaceTestUtils.ListUsers(ak, sk, expectedCode);
        			System.out.println(result);
        			break;
        		case "DeleteUser":
        			result=deleteUser(ak, sk,expectedCode);
        			System.out.println(result);
        			break;
        		case "ListUserTags":
        			result=IAMInterfaceTestUtils.ListUserTags(ak, sk, userName, expectedCode);
        			System.out.println(result);
        			break;
        		case "TagUser":
        			result=tagUser(ak, sk, userName, expectedCode);
        			if(expectedCode==200)
        				untagUser(accessKey,secretKey,userName,200);
        			System.out.println(result);
        			break;
        		case "UntagUser":
        			tagUser(accessKey,secretKey,userName,200);
        			result=untagUser(ak, sk, userName, expectedCode);
        			if (expectedCode==403)
        				untagUser(accessKey,secretKey,userName,200);
        			System.out.println(result);
        			break;
        		case "ListGroupsForUser":
        			result=IAMInterfaceTestUtils.ListGroupsForUser(ak, sk, userName, expectedCode);
        			System.out.println(result);
        			break;
        		case "CreateAccessKey":
        			User user=new User();
        			user.accountId=accountId;
        			user.userName=userName;
        			user=HBaseUtils.get(user);
        			if(user.accessKeys.size()>1)
        				IAMInterfaceTestUtils.DeleteAccessKey(accessKey, secretKey, user.accessKeys.get(0), userName, 200);
        			result=IAMInterfaceTestUtils.CreateAccessKey(ak, sk, userName, expectedCode);
        			System.out.println(result);
        			break;
        		case "DeleteAccessKey":
        			result=deleteaksk(ak, sk, expectedCode);
        			System.out.println(result);
        			break;
        		case "ListAccessKeys":
        			result=IAMInterfaceTestUtils.ListAccessKeys(ak, sk, userName, expectedCode);
        			System.out.println(result);
        			break;
        		case "UpdateAccessKey":
        			akId=getakId(userName);
        			result=IAMInterfaceTestUtils.UpdateAccessKey(ak, sk, akId, userName, "Active", expectedCode);
        			System.out.println(result);
        			break;
        		case "GetAccessKeyLastUsed":
        			akId=getakId(userName);
        			result=IAMInterfaceTestUtils.GetAccessKeyLastUsed(ak, sk, akId, expectedCode);
        			System.out.println(result);
        			break;
        		case "ChangePassword":
        			IAMInterfaceTestUtils.CreateLoginProfile(accessKey, secretKey, userName, oldPassword, 200);
        			result=IAMInterfaceTestUtils.ChangePassword(ak, sk, userName, oldPassword, "newpassword123", expectedCode);
        			System.out.println(result);
        			IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, userName, 200);
        			break;
        		case "CreateLoginProfile":
        			result=IAMInterfaceTestUtils.CreateLoginProfile(ak, sk, userName, "newpasswd123", expectedCode);
        			if (expectedCode==200)
        				IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, userName, 200);
        			System.out.println(result);
        			break;
        		case "UpdateLoginProfile":
        			IAMInterfaceTestUtils.CreateLoginProfile(accessKey, secretKey, userName, oldPassword, 200);
        			result=IAMInterfaceTestUtils.UpdateLoginProfile(ak, sk, userName, "updatepwd123", expectedCode);
        			IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, userName, 200);
        			System.out.println(result);
        			break;
        		case "GetLoginProfile":
        			IAMInterfaceTestUtils.CreateLoginProfile(accessKey, secretKey, userName, oldPassword, 200);
        			result=IAMInterfaceTestUtils.GetLoginProfile(ak, sk, userName, expectedCode);
        			IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, userName, 200);
        			System.out.println(result);
        			break;
        		case "DeleteLoginProfile":
        			IAMInterfaceTestUtils.CreateLoginProfile(accessKey, secretKey, userName, oldPassword, 200);
        			result=IAMInterfaceTestUtils.DeleteLoginProfile(ak, sk, userName, expectedCode);
        			if(expectedCode==403)
        				IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, userName, 200);
        			System.out.println(result);
        			break;
        		case "CreateVirtualMFADevice":
        			result=IAMInterfaceTestUtils.CreateVirtualMFADevice(ak, sk, "createvirtualMFADevice1", expectedCode);
        			if(expectedCode==200)
        				IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, "createvirtualMFADevice1", 200);
        			System.out.println(result);
        			break;
        		case "ListVirtualMFADevices":
        			result=IAMInterfaceTestUtils.ListVirtualMFADevices(ak, sk, expectedCode);
        			System.out.println(result);
        			break;
        		case "ListMFADevices":
        			result=IAMInterfaceTestUtils.ListMFADevices(ak, sk, userName, expectedCode);
        			System.out.println(result);
        			break;
        		case "EnableMFADevice":
        			result=virtualMFADeviceEnabled(ak, sk, userName,"createmfafortestenable", expectedCode);
        			if(expectedCode==200)
        				IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, "createmfafortestenable", 200);
        			IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, "createmfafortestenable", 200);        			
        			System.out.println(result);
        			break;
        		case "DeactivateMFADevice":
        			result=deactivateMFADevice(ak,sk,"createuserfordeactivedevice","createmfafortestenable1",expectedCode);
        			System.out.println(result);
        			break;
        		case "DeleteVirtualMFADevice":
        			IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, "createmfafortestdel", 200);
        			result=IAMInterfaceTestUtils.DeleteVirtualMFADevice(ak, sk, accountId, "createmfafortestdel", expectedCode);
        			if(expectedCode==403)
        				IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, "createmfafortestdel", 200);
        			System.out.println(result);
        			break;
        		case "UpdateAccountPasswordPolicy":
        			result=IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(ak, sk, expectedCode);
        			System.out.println(result);
        			break;
        		case "GetAccountPasswordPolicy":
        			IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(accessKey, secretKey, 200);
        			result=IAMInterfaceTestUtils.GetAccountPasswordPolicy(ak, sk, expectedCode);
        			System.out.println(result);
        			break;
        		case "DeleteAccountPasswordPolicy":
        			IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(accessKey, secretKey, 200);
        			result=IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(ak, sk, expectedCode);
        			System.out.println(result);
        			break;
        		case "CreatePolicy":
        			result=createPolicy(ak, sk, Effect.Allow,"cratepolicyfortestcreategroup","Action",Arrays.asList("iam:CreateGroup","iam:CreateUser","iam:CreateAccessKey"),"Resource",Arrays.asList("*"),null);
        			if(expectedCode==200)
        				IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, "cratepolicyfortestcreategroup", 200);
        			System.out.println(result);
        			break;
        		case "AttachGroupPolicy":
        			result=IAMInterfaceTestUtils.AttachGroupPolicy(ak, sk, accountId, groupName, policyName, expectedCode);
        			if(expectedCode==200)
        				IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
        			System.out.println(result);
        			break;
        		case "DeletePolicy":
        			result=deletePolicy(ak, sk, expectedCode);
        			System.out.println(result);
        			break;
        		case "AttachUserPolicy":
        			result=IAMInterfaceTestUtils.AttachUserPolicy(ak, sk, accountId, userName, policyName, expectedCode);
        			if(expectedCode==200)
        				IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
        			System.out.println(result);
        			break;
        		case "DetachGroupPolicy":
        			IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
        			result=IAMInterfaceTestUtils.DetachGroupPolicy(ak, sk, accountId, groupName, policyName, expectedCode);
        			if(expectedCode==403)
        				IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
        			System.out.println(result);
        			break;
        		case "DetachUserPolicy":
        			IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
        			result=IAMInterfaceTestUtils.DetachUserPolicy(ak, sk, accountId, userName, policyName, expectedCode);
        			if(expectedCode==403)
        				IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
        			System.out.println(result);
        			break;
        		case "GetPolicy":
        			result=IAMInterfaceTestUtils.GetPolicy(ak, sk, accountId, policyName, expectedCode);
        			System.out.println(result);
        			break;
        		case "ListAttachedGroupPolicies":
        			result=IAMInterfaceTestUtils.ListAttachedGroupPolicies(ak, sk, groupName, expectedCode);
        			System.out.println(result);
        			break;
        		case "ListAttachedUserPolicies":
        			result=IAMInterfaceTestUtils.ListAttachedUserPolicies(ak, sk, userName, expectedCode);
        			System.out.println(result);
        			break;
        		case "ListEntitiesForPolicy":
        			result=IAMInterfaceTestUtils.ListEntitiesForPolicy(ak, sk, accountId, policyName, expectedCode);
        			System.out.println(result);
        			break;
        		case "ListPolicies":
        			result=IAMInterfaceTestUtils.ListPolicies(ak, sk, expectedCode);
        			System.out.println(result);
        			break;

        	}
        				
        }
        
	}
	
	//获取方法名
	public List<String> getActionsName(List<String> actions)throws Exception{
		List<String> actionsList=new ArrayList<>();
		 // 获取指定包下的Action注解的类
        ClasspathPackageScanner packageScanner = new ClasspathPackageScanner(IAMActions.class.getClassLoader());
        List<Class<?>> actionClasses = packageScanner.getClasses("cn.ctyun.oos.iam.server.action.api", Action.class);
        // 加载Action处理类
        for (Class<?> clazz : actionClasses) {
            // 获取action中的所有方法
            for (Method method : clazz.getMethods()) {
                // 获取方法名，首字符转大写
                String methodKey = IAMStringUtils.firstCharUpperCase(method.getName());
                for(String action:actions){
                	if (methodKey.contains(action)&& !methodKey.contains("Class")){
                		actionsList.add(methodKey);
                	}           		
                }
            }
        }
        return actionsList;
	}
	
	//获取akId
	public String getakId(String userName)throws Exception{
		User user=new User();
		user.accountId=accountId;
		user.userName=userName;
		user=HBaseUtils.get(user);
		akId=user.accessKeys.get(0);
		return akId;
	}
	//创建策略
	public static String createPolicy(Effect effect,String policyName,String actionEffect,List<String> actions,String resourceEffect,List<String> resources,List<Condition> conditions)throws Exception{
		String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(effect,null, null, actionEffect, actions, resourceEffect, resources, conditions);
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName="+URLEncoder.encode(policyName)+"&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=test_des";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
//		System.out.println(result.second());
		return result.second();
	}
	//创建策略
	public static String createPolicy(String ak,String sk,Effect effect,String policyName,String actionEffect,List<String> actions,String resourceEffect,List<String> resources,List<Condition> conditions)throws Exception{
		String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(effect,null, null, actionEffect, actions, resourceEffect, resources, conditions);
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName="+URLEncoder.encode(policyName)+"&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=test_des";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
//		System.out.println(result.second());
		return result.second();
	}
	
	
	//deletepolicy
	public String deletePolicy(String ak, String sk, int expectedCode)throws Exception{
		String policyName="createpolicyfortestdelpolicy";
		createPolicy(Effect.Allow,policyName,"Action",Arrays.asList("iam:CreateGroup","iam:CreateUser","iam:CreateAccessKey","iam:TagUser","iam:CreateVirtualMFADevice"),"Resource",Arrays.asList("*"),null);
		String result=IAMInterfaceTestUtils.DeletePolicy(ak, sk, accountId, policyName, expectedCode);
		if(expectedCode==403)
			IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		return result;
	}
	//删除用户
	public String deleteUser(String ak, String sk, int expectedCode)throws Exception{
		String userName="createuserfortestdeluser";
		IAMInterfaceTestUtils.CreateUser(accessKey, secretKey, userName, 200);
		String result=IAMInterfaceTestUtils.DeleteUser(ak, sk, userName, expectedCode);
		if(expectedCode==403)
			IAMInterfaceTestUtils.DeleteUser(accessKey, secretKey, userName, 200);
		return result;
	}
	//删除组
	public String deleteGroup(String ak,String sk, int expectedCode)throws Exception{
		String groupName="creategroupfortestdelgroup";
		IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
		String result=IAMInterfaceTestUtils.DeleteGroup(ak, sk, groupName, expectedCode);
		if(expectedCode==403)
			IAMInterfaceTestUtils.DeleteGroup(accessKey, secretKey, groupName, 200);
		return result;
	}
	
	//给用户添加标签
	public String tagUser(String ak, String sk, String userName, int expectedCode)throws Exception{
		List<Pair<String, String>> tags=new ArrayList<>();
		Pair<String,String> tag1=new Pair<>();
		tag1.first("tag1Key");
		tag1.second("tag1Value");
		Pair<String,String> tag2=new Pair<>();
		tag2.first("tag2Key");
		tag2.second("tag2Value");
		tags.add(tag1);
		tags.add(tag2);
		
		String tagString="";
	    for (int i = 1; i < tags.size()+1; i++) {
	          tagString+="&Tags.member."+i+".Key="+tags.get(i-1).first()+"&Tags.member."+i+".Value="+tags.get(i-1).second();
	    }
	    String body="Action=TagUser&Version=2010-05-08&UserName="+userName+tagString;
	    Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
	    assertEquals(expectedCode, result.first().intValue());
	    return result.second(); 		
	}	
	//删除指定标签
	public String untagUser(String ak, String sk, String userName, int expectedCode)throws Exception{
		tagUser(accessKey, secretKey, userName, 200);
		User user=new User();
		user.accountId=accountId;
		user.userName=userName;
		user=HBaseUtils.get(user);
		String untagString="";
        for (int i = 1; i < 2; i++) {
            untagString+="&TagKeys.member."+i+"="+user.tags.get(i-1).key;
        }
        String body="Action=UntagUser&Version=2010-05-08&UserName="+userName+untagString;
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
		
	}
	
	//删除aksk
	public String deleteaksk(String ak, String sk, int expectedCode) throws Exception{
		String userName="createuserfortestdelaksk";
		//创建user
		IAMInterfaceTestUtils.CreateUser(accessKey, secretKey, userName, 200);
		//创建aksk
		IAMInterfaceTestUtils.CreateAccessKey(accessKey, secretKey, userName, 200);
		akId=getakId(userName);
		//删除
		String result=IAMInterfaceTestUtils.DeleteAccessKey(ak, sk, akId, userName, expectedCode);
		if (expectedCode==403)
			IAMInterfaceTestUtils.DeleteAccessKey(accessKey, secretKey, akId, userName, 200);
			
		IAMInterfaceTestUtils.DeleteUser(accessKey, secretKey, userName, 200);	
		return result;
	}
	
	//用户移除MFA
	public String deactivateMFADevice(String ak, String sk, String userName, String deviceName, int expectedCode)throws Exception{
		User user=new User();
		user.accountId=accountId;
		user.userName=userName;
		user=HBaseUtils.get(user);
		if(user==null)
			IAMInterfaceTestUtils.CreateUser(accessKey, secretKey, userName, 200);		
		virtualMFADeviceEnabled(accessKey,secretKey,userName,deviceName,200);
		String result=IAMInterfaceTestUtils.DeactivateMFADevice(ak, sk, userName, accountId, deviceName, expectedCode);
		if(expectedCode==403)
			IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, deviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, deviceName, 200);
		IAMInterfaceTestUtils.DeleteUser(accessKey, secretKey, userName, 200);
		return result;
		
	}
	
	//给用户启用指定的MFA
	public String virtualMFADeviceEnabled(String ak, String sk,String userName,String deviceName,int expectedCode) throws IOException {
		MFADevice mFADevice=new MFADevice();
		mFADevice.accountId=accountId;
		mFADevice.virtualMFADeviceName=deviceName;
		mFADevice.serialNumber="arn:ctyun:iam::" + accountId + ":mfa/" + deviceName;
		mFADevice=HBaseUtils.get(mFADevice);
		if(mFADevice==null)
			IAMInterfaceTestUtils.CreateMFADevice(accessKey, secretKey, deviceName, 200);
		MFADevice mfa=new MFADevice();
		mfa.accountId=accountId;
		mfa.virtualMFADeviceName=deviceName;
		mfa=HBaseUtils.get(mfa);
		String base32StringSeed=mfa.base32StringSeed;
		Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
		String result=IAMInterfaceTestUtils.EnableMFADevice(ak, sk, userName, accountId, deviceName, codesPair.first(), codesPair.second(), expectedCode);
		return result;
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
            codePair.first(String.valueOf(hash1));
            codePair.second(String.valueOf(hash2));
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
	
	
	
}
