package cn.ctyun.oos.iam.test;

import static org.junit.Assert.*;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.URL;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.io.IOUtils;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.xml.sax.InputSource;

import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import common.tuple.Pair;

public class PolicyActionAPITest {
	public static final String OOS_IAM_DOMAIN="https://oos-xl-iam.ctyunapi.cn:9460/";
	public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
	public static final String regionName="xl";
	
	public static final String accessKey="65dd530d67f7f88e222f";
	public static final String secretKey="bee6a1d024e999bdf72e04d6a37d85bba789c5d3";
	
	public static final String accessKeyother="122aa530d67f7f88e222f";
	public static final String secretKeyother="aac6a1d024e999bdf72e04d6a37d85bba789c225";
	public static String arnPrefix = "arn:ctyun:iam::";
	public static final String accountId="0000000gc0uy9";
	public static String publicpolicyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\"],\"Resource\":[\"Arn:aws:s3:::EXAMPLE-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";
	

//	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		IAMTestUtils.TrancateTable("iam-accountSummary-huxl");
//		IAMTestUtils.TrancateTable("iam-group-huxl");
//		IAMTestUtils.TrancateTable("iam-user-huxl");
//		IAMTestUtils.TrancateTable("iam-policy-huxl");
	}

	@Before
	public void setUp() throws Exception {
		IAMTestUtils.TrancateTable("iam-accountSummary-huxl");
	}

	//创建policy，
	@SuppressWarnings("deprecation")
	@Test
	public void test_createPolicy() throws Exception{
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\",\"s3:Putt*\"],\"Resource\":[\"Arn:aws:s3:::EXAMPLE-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";
		String policyname = "Testcreatepolicy";
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName="+policyname+"&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=test_des";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		JSONObject response= new JSONObject();
        response = ParseXmlToJson(result.second(), "CreatePolicy");
        System.out.print(response);
        assertEquals(policyname,response.get("PolicyName"));
        assertEquals(arnPrefix + accountId + ":policy/" +policyname, response.get("Arn"));
        assertEquals("true",response.get("IsAttachable"));
        assertEquals("test_des",response.get("Description"));
        assertEquals("0",response.get("AttachmentCount"));
        assertNotNull(response.get("CreateDate"));
        assertNotNull(response.get("UpdateDate")); 
        assertNotNull(response.get("PolicyId")); 
	}
	
	//createPolicy:Action，Version正确，PolicyName为必填项，无PolicyName时400异常
//	@Test
	public void test_createPolicy_requiredPolicyName() throws Exception {
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\"],\"Resource\":[\"Arn:aws:s3:::EXAMPLE-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=test_des";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'policyName' failed to satisfy constraint: Member must not be null",error.get("Message"));
		
	}	
	//CreatePolicy:PolicyName唯一性校验，policyName与已存在的PolicypName重复且path不同，409异常,因本版本没有path，所以Policy Name相同的时候只会更新
	@Ignore
	public void test_createpolicy_uniqPolicyName() throws Exception {
			
	}

	//CreatePolicy:PolicyName不区分大小写
	@Test
	public void test_createpolicy_distigush() throws Exception {
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\"],\"Resource\":[\"Arn:aws:s3:::POLICYTEST-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";;
		String policyName = "TESTCreatepolicy";
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName="+policyName+"&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=test_des";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		JSONObject response= new JSONObject();
        response = ParseXmlToJson(result.second(), "CreatePolicy");
        System.out.print(response);
        assertEquals(policyName,response.get("PolicyName"));
        
		String body2="Action=CreatePolicy&Version=2010-05-08&PolicyName="+policyName.toLowerCase()+"&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=test_des";
		Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest(body2, accessKey, secretKey);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		JSONObject response2= new JSONObject();
        response2 = ParseXmlToJson(result2.second(), "CreatePolicy");
        System.out.print(response2);
        assertEquals(policyName.toLowerCase(),response2.get("PolicyName"));
		
		
				
	}	
	
	//CreatePOlicy:PolicyName相同，修改policyDocument，更新策略
//	@Test
	public void test_createpolicy_updatePolicy() throws Exception {
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\",\"s3:Put*\"],\"Resource\":[\"Arn:aws:s3:::POLICYTEST-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";;
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName=TESTCreatepolicy&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=test_des";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
				
	}
	
	//CreatePolicy:修改desc，更新策略
	@Test
	public void test_createpolicy_updatePolicy2() throws Exception {
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\",\"s3:Put*\"],\"Resource\":[\"Arn:aws:s3:::POLICYTEST-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName=TESTCreatepolicy&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=testdes";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		JSONObject response= new JSONObject();
		response = ParseXmlToJson(result.second(), "CreatePolicy");
		assertEquals("testdes",response.get("Description"));
		
		String body2="Action=CreatePolicy&Version=2010-05-08&PolicyName=TESTCreatepolicy&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=test_des";
		Pair<Integer,String> result2=IAMTestUtils.invokeHttpsRequest(body2, accessKey, secretKey);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());		
		response = ParseXmlToJson(result2.second(), "CreatePolicy");
        System.out.print(response);
        assertEquals("test_des",response.get("Description"));		
	}

	//createPolicy:Policyname规则校验,大小写，数字特殊字符组合
//	@Test
	public void test_createpolicy_validPolicyName() throws Exception {
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\",\"s3:Put*\"],\"Resource\":[\"Arn:aws:s3:::POLICYTEST-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";
		String policyName=URLEncoder.encode("TEstcreatePOlicy++=,.@-001");
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName="+policyName+"&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=testdes";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
			
	}
	//createPolicy:PolicyName合法性校验，PolicyName长度限制在128之内，设置PolicyName长度为128
	@Test
	public void test_createpolicy_validPolicyName_128() throws Exception {
		StringBuilder sb=new StringBuilder();
		for(int i=0;i<128;i++)
			sb.append("a");
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\",\"s3:Put*\"],\"Resource\":[\"Arn:aws:s3:::POLICYTEST-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName="+sb.toString()+"&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=testdes";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
	}
	//createPolicy:PolicyName合法性校验，PolicyName长度为1
	@Test
	public void test_createpolicy_validPolicyName_1() throws Exception {
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\",\"s3:Put*\"],\"Resource\":[\"Arn:aws:s3:::POLICYTEST-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName=1&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=testdes";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
	}
	
	//createPolicy:Policyname规则校验,不合法特殊字符
//	@Test
	public void test_createpolicy_invalidPolicyName() throws Exception {
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\",\"s3:Put*\"],\"Resource\":[\"Arn:aws:s3:::POLICYTEST-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";
		String policyName=URLEncoder.encode("TEstcreatePOlicy*&");
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName="+policyName+"&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=testdes";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'policyName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",error.get("Message"));
	}
	//createPolicy:PolicyName合法性校验，设置PolicyName为空
	@Test
	public void test_createPolicy_invalidPolicyName_length1() throws Exception {
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\"],\"Resource\":[\"Arn:aws:s3:::EXAMPLE-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName=&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=test_des";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'policyName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",error.get("Message"));
	
	}		
	//createPolicy:PolicyName合法性校验，PolicyName长度限制在128之内，设置PolicyName长度为129
	@Test
	public void test_createpolicy_invalidPolicyName_length() throws Exception {
		StringBuilder sb=new StringBuilder();
		for(int i=0;i<129;i++)
			sb.append("a");
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\",\"s3:Put*\"],\"Resource\":[\"Arn:aws:s3:::POLICYTEST-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName="+sb.toString()+"&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=testdes";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value '"+sb.toString()+"' at 'policyName' failed to satisfy constraint: Member must have length less than or equal to 128",error.get("Message"));
		
	}	
	
	//createPolicy:PolicyDocument校验，必填项校验
	@Test
	public void test_createPolicy_requiredPolicyDocument() throws Exception {
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName=createPolicyForPD&Description=test_des";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'policyDocument' failed to satisfy constraint: Member must not be null",error.get("Message"));
	}
	//createPolicy:PolicyDocument校验,policyDocument添加格式校验，长度不能为1
	@Test
	public void test_createPolicy_policyDocument_length1() throws Exception {
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName=policyforTestlength&PolicyDocument="+URLEncoder.encode("a")+"&Description=testdes";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("MalformedPolicyDocument",error.get("Code"));
		assertEquals("Syntax errors in policy.",error.get("Message"));
	
	}
	
	//createPolicy:PolicyDocument校验，长度检验1-131072，必须符合格式校验
//	@Test
	public void test_createPolicy_policyDocument_length131072() throws Exception {
		StringBuilder sb=new StringBuilder();
		File file = new File(".\\test\\cn\\ctyun\\oos\\iam\\test\\policyDocument.txt");
		BufferedReader reader=new BufferedReader(new FileReader(file));
		String linetxt;
		while((linetxt=reader.readLine())!=null){
			sb.append(linetxt);
		}
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName=policyforTestlength&PolicyDocument="+URLEncoder.encode(sb.toString())+"&Description=testdes";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
	}
	
	//createPolicy:PolicyDocument校验，policyDocument为空
	@Test
	public void test_createPolicy_invalidPolicyDocument() throws Exception {
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName=createPolicyForPD&PolicyDocument=&Description=test_des";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value at 'policyDocument' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\u0009\\u000A\\u000D\\u0020-\\u00FF]+",error.get("Message"));
	
	}
	
	//createPolicy:PolicyDocument校验，长度检验1-131072,131073时报400异常
	@Test
	public void test_createPolicy_policyDocument_invalidlength() throws Exception {
		StringBuilder sb=new StringBuilder();
		for(int i=0;i<131073;i++)
			sb.append("a");
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName=policyforTestlength&PolicyDocument="+URLEncoder.encode(sb.toString())+"&Description=testdes";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value '"+sb.toString()+"' at 'policyDocument' failed to satisfy constraint: Member must have length less than or equal to 131072",error.get("Message"));
				
	}
	
//	@Test
//	public void test_createPolicy_policyAttached() throws Exception{
//		String groupname = "createfortestpolicy";
//		createGroup(groupname);
//		String username = "createuserfortestpolicy";
//		createUser(username);
//		String policyname = "testcreatepolicy";
//		String policyarn = arnPrefix +accountId+":policy/"+policyname;
//		//策略附加到组和用户
//		attachPolicyToGroup(groupname,policyarn);
//		attachPolicyToUser(username,policyarn);
//		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\"],\"Resource\":[\"Arn:aws:s3:::EXAMPLE-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";
//		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName="+policyname+"&PolicyDocument="+URLEncoder.encode(policyDocument);
//		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
//		assertEquals(200,result.first().intValue());
//		System.out.println(result.second());
//		JSONObject response= new JSONObject();
//        response = ParseXmlToJson(result.second(), "CreatePolicy");
//        System.out.print(response);
//        assertEquals(policyname,response.get("PolicyName"));
//        assertEquals(arnPrefix + accountId + ":policy/" +policyname, response.get("Arn"));
//        assertEquals("true",response.get("IsAttachable"));
//        assertEquals("test_des",response.get("Description"));
//        assertEquals("2",response.get("AttachmentCount"));
//        assertNotNull(response.get("CreateDate"));
//        assertNotNull(response.get("UpdateDate")); 
//        assertNotNull(response.get("PolicyId")); 
//	}	
	
	//createPolicy:PolicyDes不输入
	@Test
	public void test_createPolicy_nopolicyDesc() {
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\"],\"Resource\":[\"Arn:aws:s3:::EXAMPLE-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName=testcreatepolicy_nodesc&PolicyDocument="+URLEncoder.encode(policyDocument);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
	}	
	
	//createPolicy:PolicyDes长度不能超过1000
//	@Test
	public void test_createPolicy_policydesc_invalidlength() throws Exception {
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\"],\"Resource\":[\"Arn:aws:s3:::EXAMPLE-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";
		StringBuilder sb=new StringBuilder();
		for(int i=0;i<1001;i++)
			sb.append("a");
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName=testcreatepolicy_nodesc&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description="+sb.toString();
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value '"+sb.toString()+"' at 'description' failed to satisfy constraint: Member must have length less than or equal to 1000",error.get("Message"));
		
	}		
	
	//账户中最多创建150策略
	@Test
	public void test_createpolicy_limitpolicies() throws Exception {
//		IAMTestUtils.TrancateTable("iam-policy-huxl");
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\",\"s3:Put*\"],\"Resource\":[\"Arn:aws:s3:::POLICYTEST-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";
		String policyName="testPolicy";
		for(int i=0;i<150;i++){
			policyName=URLEncoder.encode("testPolicy"+i);
			String body="Action=CreatePolicy&Version=2010-05-08&PolicyName="+policyName+"&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=testdes";
			Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
			assertEquals(200,result.first().intValue());
			System.out.println(result.second());
			
		}
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName="+policyName+"&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=testdes";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(409,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("LimitExceeded",error.get("Code"));
		assertEquals("Cannot exceed quota for PoliciesPerAccount: 150.",error.get("Message"));
	
	}
	
	//创建策略时，版本错误，400异常
	@Test
	public void test_createPolicy_policyDocument_errorVersion() throws Exception {
		String policyDocument="{\"Version\":\"2012-11-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\",\"s3:Put*\"],\"Resource\":[\"Arn:aws:s3:::POLICYTEST-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";
		
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName=policyforTestlength&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=testdes";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("MalformedPolicyDocument",error.get("Code"));
		assertEquals("The policy must contain a valid version string.",error.get("Message"));
				
	}
		
	
	//创建策略时，策略没有Effect，400异常
//	@Test
	public void test_createPolicy__policyDocument_noEffect() throws Exception {
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\",\"s3:Put*\"],\"Resource\":[\"Arn:aws:s3:::POLICYTEST-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";
		
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName=policyforTestlength&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=testdes";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("MalformedPolicyDocument",error.get("Code"));
		assertEquals("Missing required field Effect.",error.get("Message"));
				
	}
	
	//创建策略时，Effect错误(allowed)，400异常
//	@Test
	public void test_createPolicy_policyDocument_errorEfffect() throws Exception {
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"allowed\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\",\"s3:Put*\"],\"Resource\":[\"Arn:aws:s3:::POLICYTEST-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";
		
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName=policyforTestlength&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=testdes";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("MalformedPolicyDocument",error.get("Code"));
		assertEquals("Invalid effect: allowed.",error.get("Message"));
				
	}
	
	//创建策略时，没有Action，400异常
	@Test
	public void test_createPolicy_policyDocument_noAction() throws Exception {
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Resource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\",\"s3:Put*\"],\"Resource\":[\"Arn:aws:s3:::POLICYTEST-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";
		
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName=policyforTestlength&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=testdes";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("MalformedPolicyDocument",error.get("Code"));
		assertEquals("Missing required field Action.",error.get("Message"));
				
	}
	
	//创建策略时，Action和NotAction同时存在，400异常
	@Test
	public void test_createPolicy_policyDocument_actionAndNotAction() throws Exception {
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"NotAction\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\",\"s3:Put*\"],\"Resource\":[\"Arn:aws:s3:::POLICYTEST-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";
		
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName=policyforTestlength&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=testdes";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("MalformedPolicyDocument",error.get("Code"));
		assertEquals("Statement/policy already has instance of Action.",error.get("Message"));
				
	}
	
	//创建策略时，没有resource，400异常
	@Test
	public void test_createPolicy_policyDocument_noResource() throws Exception {
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\",\"s3:Put*\"],\"Resource\":[\"Arn:aws:s3:::POLICYTEST-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";
		
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName=policyforTestlength&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=testdes";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("MalformedPolicyDocument",error.get("Code"));
		assertEquals("Missing required field Resource.",error.get("Message"));
				
	}
	//创建策略时，resource和NotResource都有
//	@Test
	public void test_createPolicy_policyDocument_resourceAndNotResource() throws Exception {
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\",\"NotResource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\",\"s3:Put*\"],\"Resource\":[\"Arn:aws:s3:::POLICYTEST-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";
		
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName=policyforTestlength&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=testdes";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("MalformedPolicyDocument",error.get("Code"));
		assertEquals("Statement/policy already has instance of Resource.",error.get("Message"));
				
	}
	
	//创建策略时，条件运算符或者条件键错误
	@Test
	public void test_createPolicy_policyDocument_operator() throws Exception {
		//条件运算符错误DateGreaterThan错误为dateGreaterThan
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\",\"s3:Put*\"],\"Resource\":[\"Arn:aws:s3:::POLICYTEST-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"],\"Condition\":{\"dateGreaterThan\":{\"ctyun:CurrentTime\": \"2017-07-01T00:00:00Z\"}}}]}";
		
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName=policyforTestlength&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=testdes";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("MalformedPolicyDocument",error.get("Code"));
		assertEquals("Invalid Condition type : dateGreaterThan.",error.get("Message"));
				
	}
	
	//创建策略时，policy格式错误，不是json格式
	@Test
	public void test_createPolicy_policyDocument_Malformed() throws Exception {
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":{{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\",\"NotResource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\",\"s3:Put*\"],\"Resource\":[\"Arn:aws:s3:::POLICYTEST-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}}}";
		
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName=policyforTestlength&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=testdes";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("MalformedPolicyDocument",error.get("Code"));
		assertEquals("Syntax errors in policy.",error.get("Message"));
				
	}

	
	//deletePolicy:删除已存在的policy（ARNUtils.generatePolicyArn(getAccountId(), '*')）
//	@Test
	public void test_deletePolicy() throws Exception {
		String policyName="createPolicyForDelete";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String body="Action=DeletePolicy&Version=2010-05-08&PolicyArn="+policyArn;
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
	}
	
	
	//deletePolicy:删除不存在的policy
//	@Test
	public void test_deletePolicyNotExist() throws Exception {
		String policyName="policyNotExist";
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String body="Action=DeletePolicy&Version=2010-05-08&PolicyArn="+policyArn;
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(404,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("NoSuchEntity",error.get("Code"));
		assertEquals("Policy "+policyArn+" does not exist or is not attachable.",error.get("Message"));
	
	}
	
	//deletePolicy:错误的POlicyArn
//	@Test
	public void test_deletePolicy_invalidPolicyArn() throws Exception {
		String policyName="policyNotExist";
		String policyArn="arn:ctyun:iam::"+accountId+":"+policyName;
		String body="Action=DeletePolicy&Version=2010-05-08&PolicyArn="+policyArn;
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("InvalidInput",error.get("Code"));
		assertEquals("ARN "+policyArn+" is not valid.",error.get("Message"));
	
	}	
	
	//deletePolicy:删除其他用户的policy,policy存在，但是为其他用户的policy
//	@Test
	public void test_deletePolicybelongtoOther() throws Exception {
		//另一用户创建policy
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\"],\"Resource\":[\"Arn:aws:s3:::EXAMPLE-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName=otherAccountPolicy&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=test_des";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKeyother, secretKeyother);
		assertEquals(200,result.first().intValue());
		System.out.print(result.second());
		
		String policyArn="arn:ctyun:iam::0000000ehvd2i:policy/otherAccountPolicy";
		String bodydel="Action=DeletePolicy&Version=2010-05-08&PolicyArn="+policyArn;
		Pair<Integer,String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, accessKey, secretKey);
		assertEquals(403,resultdel.first().intValue());
		System.out.println(resultdel.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(resultdel.second());
		assertEquals("AccessDenied",error.get("Code"));
		assertEquals("Policy is outside your own account.",error.get("Message"));
	
	}
	
	//deletePolicy:policyArn为必填项，如为空，400异常
	@Test
	public void test_deletePolicy_requiredpolicyArn()throws Exception{
		String body="Action=DeletePolicy&Version=2010-05-08";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'policyArn' failed to satisfy constraint: Member must not be null",error.get("Message"));
		
	}	
	
	//deletePolicy:policyArn为“”
	@Test
	public void test_deletePolicy_invalidpolicyArn()throws Exception{
		String body="Action=DeletePolicy&Version=2010-05-08&PolicyArn=";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value '' at 'policyArn' failed to satisfy constraint: Member must have length greater than or equal to 20",error.get("Message"));
		
	}
	
	//deletePolicy:删除存在的policy时，policyArn的长度不超过2048，（代码中对长度的校验20-2048）,设置为2049，400异常
//	@Test
	public void test_deletePolicy_policyArn_invalidlength() throws Exception{
		StringBuilder sb=new StringBuilder();
		for(int i=0;i<2049;i++)
			sb.append("a");
		String body="Action=DeletePolicy&Version=2010-05-08&PolicyArn="+sb.toString();
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value '"+sb.toString()+"' at 'policyArn' failed to satisfy constraint: Member must have length less than or equal to 2048",error.get("Message"));
		
	}
	
	
	//deletePolicy:删除存在的policy时，policy附加到用户，删除时409
	@Test
	public void test_deletePolicy_AttachUser() throws Exception {
		//创建用户
		String userName="createUserFortestdeletePolicy";
		createUser(userName);
		//创建policy
		String policyName="createpolicyfordelete";
		createPolicy(policyName);
		//将策略加入到用户中
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		attachPolicyToUser(userName,policyArn);
		//删除策略
		String body="Action=DeletePolicy&Version=2010-05-08&PolicyArn="+policyArn;
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(409,result.first().intValue());
		System.out.println(result.second());
		
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("DeleteConflict",error.get("Code"));
		assertEquals("Cannot delete a policy attached to entities.", error.get("Message"));
	}
	
	//删除存在的policy时，policy附加到组删除时409
	@Test
	public void test_deletePolicy_AttachGroup() throws Exception {
		//创建组
		String groupName="creategroupFortestdeletePolicy";
		createGroup(groupName);
		//创建policy
		String policyName="createpolicyfordelete";
		createPolicy(policyName);
		//将策略加入到组中
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		attachPolicyToGroup(groupName,policyArn);
		//删除策略
		String body="Action=DeletePolicy&Version=2010-05-08&PolicyArn="+policyArn;
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(409,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("DeleteConflict",error.get("Code"));
		assertEquals("Cannot delete a policy attached to entities.", error.get("Message"));
	}
	
	//deleetPolicy:删除的策略为系统策略,403异常(不允许删除系统策略)
//	@Test（本期无OOS系统策略）
	public void test_deletePolicy_OOS()throws Exception{
		//创建Scope类型为OOS的策略（目前需要修改代码进行创建）
		String policyName="createOOSPolicyfortestlistPolicies1";
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"oos:*\",\"Resource\":\"Arn:aws:oos:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"oos:Get*\",\"oos:List*\"],\"Resource\":[\"Arn:aws:oos:::EXAMPLE-BUCKET\",\"Arn:aws:oos:::EXAMPLE-BUCKET/*\"]}]}";
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName="+ URLEncoder.encode(policyName) +"&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=test_des";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		
		String policyArn="arn:ctyun:iam::OOS:policy/"+policyName;
		String bodydel="Action=DeletePolicy&Version=2010-05-08&PolicyArn="+policyArn;
		Pair<Integer,String> resultdel=IAMTestUtils.invokeHttpsRequest(bodydel, accessKey, secretKey);
		assertEquals(403,resultdel.first().intValue());
		System.out.println(resultdel.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(resultdel.second());
		assertEquals("AccessDenied",error.get("Code"));
		assertEquals("Policy is outside your own account.",error.get("Message"));		
			
	}
	
	
	//attachPolicy：添加策略到组
//	@Test
	public void test_attachPolicyToGroup()throws Exception{
		String groupName="creategroupFortestPolicy";
		createGroup(groupName);
		String policyName="createPolicyFortestaddtoGroup";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String bodyAttach="Action=AttachGroupPolicy&Version=2010-05-08&GroupName="+ groupName +"&PolicyArn="+URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
	}
	
	//attachPolicy：添加系统策略到组
//	@Test(本期不做OOS系统策略)
	public void test_attachOOSPolicyToGroup()throws Exception{
		String groupName="creategroupFortestOOSPolicy";
		createGroup(groupName);
		String policyName="createOOSPolicyFortestaddtoGroup";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::OOS:policy/"+policyName;
		String bodyAttach="Action=AttachGroupPolicy&Version=2010-05-08&GroupName="+ groupName +"&PolicyArn="+URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
	}
	
	//attachPolicy：添加策略到组，必填项校验--groupName
	@Test
	public void test_attachPolicyToGroup_requireGroupName()throws Exception{
		String policyName="createPolicyFortestaddtoGroup";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String bodyAttach="Action=AttachGroupPolicy&Version=2010-05-08&PolicyArn="+URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'groupName' failed to satisfy constraint: Member must not be null",error.get("Message"));
	}	
	

	//attachPolicy：添加策略到组，必填项校验--policyArn
	@Test
	public void test_attachPolicyToGroup_requirePolicyArn()throws Exception{
		String groupName="creategroupFortestPolicy";
		createGroup(groupName);
		String bodyAttach="Action=AttachGroupPolicy&Version=2010-05-08&GroupName="+ groupName ;
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'policyArn' failed to satisfy constraint: Member must not be null",error.get("Message"));
	}
	
	//attachPolicy：添加策略到组，groupName校验
//	@Test
	public void test_attachPolicyToGroup_invalidgroupName() throws Exception {
		String policyName="cratepolicyfortestinvalidgroup";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;;
		String body="Action=AttachGroupPolicy&Version=2010-05-08&GroupName="+"&PolicyArn="+policyArn;
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'groupName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",error.get("Message"));
	
	}	
	
	//attachPolicy：添加策略到组，policyArn为空
	@Test
	public void test_attachPolicyToGroup_invalidPolicyName_length1() throws Exception {
		String groupName="creategroupfortestinvalidpolicy";
		createGroup(groupName);
		String body="Action=AttachGroupPolicy&Version=2010-05-08&GroupName="+ groupName +"&PolicyArn=";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value '' at 'policyArn' failed to satisfy constraint: Member must have length greater than or equal to 20",error.get("Message"));
	
	}	
	
	//attachPolicy：添加策略到组时，policyArn的字符串长度限制为2048,长度为2049，400异常
	@Test
	public void test_attachPolicyToGroup_policyArnlength()throws Exception{
		String groupName="creategroupFortestPolicyARN";
		createGroup(groupName);
		StringBuilder sb=new StringBuilder();
		for(int i=0;i<2049;i++)
			sb.append("a");
		String body="Action=AttachGroupPolicy&Version=2010-05-08&GroupName="+ groupName +"&PolicyArn="+sb.toString();
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value '"+sb.toString()+"' at 'policyArn' failed to satisfy constraint: Member must have length less than or equal to 2048",error.get("Message"));
				
	}
	
	//attachPolicy：添加策略到组，group不存在
	@Test
	public void test_attachPolicyToGroup_GroupNameNotExist()throws Exception{
		String policyName="createPolicyFortestaddtoGroup";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String bodyAttach="Action=AttachGroupPolicy&Version=2010-05-08&GroupName=groupNotExist&PolicyArn="+URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(404,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("NoSuchEntity",error.get("Code"));
		assertEquals("The group with name groupNotExist cannot be found.",error.get("Message"));
	}	
	//attachPolicy：添加策略到组，policyArn不存在
	@Test
	public void test_attachPolicyToGroup_PolicyNotExist()throws Exception{
		String groupName="creategroupFortestPolicy";
//		createGroup(groupName);
		String bodyAttach="Action=AttachGroupPolicy&Version=2010-05-08&GroupName="+ groupName +"&PolicyArn="+URLEncoder.encode("arn:ctyun:iam::"+accountId+":policy/policyNotExist");
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(404,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("NoSuchEntity",error.get("Code"));
		assertEquals("Policy arn:ctyun:iam::"+accountId+":policy/policyNotExist does not exist or is not attachable.",error.get("Message"));
	}
	
	//attachPolicy：添加到组中的策略数，最多为10，超出后报409异常
//	@Test
	public void test_attachPolicyToGroup_limitedPolicyNum()throws Exception{
		String groupName="creategroupFortestPolicyNum";
		createGroup(groupName);
		String policyName="policyFortestNum";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		for(int i=0;i<10;i++){
			createPolicy(policyName+i);
			attachPolicyToGroup(groupName,policyArn+i);
		}
		String bodyAttach="Action=AttachGroupPolicy&Version=2010-05-08&GroupName="+ groupName +"&PolicyArn="+URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(409,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("LimitExceeded",error.get("Code"));
		assertEquals("Cannot exceed quota for PoliciesPerGroup: 10.",error.get("Message"));
	}
	
	//attachPolicy:添加策略到组，添加到的组不为本账户创建
//	@Test
	public void test_attachPolicyToGroup_groupbelongtoOther()throws Exception{
		//使用其他用户创建组
		String groupName="groupbelongtoOther";
		String body="Action=CreateGroup&Version=2010-05-08&GroupName="+groupName;
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKeyother, secretKeyother);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		
		//创建策略
		String policyName="attachepolicytoother";
		createPolicy(policyName);
		//将策略添加到组
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String bodyAttach="Action=AttachGroupPolicy&Version=2010-05-08&GroupName="+ groupName +"&PolicyArn="+URLEncoder.encode(policyArn);
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(404,resultatt.first().intValue());
		System.out.println(resultatt.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(resultatt.second());
		assertEquals("NoSuchEntity",error.get("Code"));
		assertEquals("The group with name groupbelongtoOther cannot be found.",error.get("Message"));
	
	}
	
	//attachPolicy:添加策略到组，添加到组的策略不为本账户创建
	@Test
	public void test_attachPolicyToGroup_policybelongtoOther()throws Exception{
		//创建组
		String groupName="testforpolicybelongtoOther";
		createGroup(groupName);
		
		//使用其他用户创建策略
		String policyName="policybelongtoOther";
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\"],\"Resource\":[\"Arn:aws:s3:::EXAMPLE-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName="+ URLEncoder.encode(policyName) +"&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=test_des";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKeyother, secretKeyother);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		
		//将策略添加到组中
		String policyArn="arn:ctyun:iam::0000000ehvd2i:policy/"+policyName;
		String bodyatt="Action=AttachGroupPolicy&Version=2010-05-08&GroupName="+ groupName +"&PolicyArn="+URLEncoder.encode(policyArn);
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(bodyatt, accessKey, secretKey);
		assertEquals(403,resultatt.first().intValue());
		System.out.println(resultatt.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(resultatt.second());
		assertEquals("AccessDenied",error.get("Code"));
		assertEquals("Policy is outside your own account.",error.get("Message"));		

	}
	
	//attachPolicytoUser：添加策略到用户
//	@Test
	public void test_attachPolicyToUser()throws Exception{
		String userName="createUserFortestPolicy";
		createUser(userName);
		String policyName="createPolicyFortestaddtoUser";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String bodyAttach="Action=AttachUserPolicy&Version=2010-05-08&UserName="+ userName +"&PolicyArn="+URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
	}	
	
	//attachPolicytoUser：添加策略到用户，userName为必填项
//	@Test
	public void test_attachPolicyToUser_requireUserName()throws Exception{
		String policyName="createPolicyFortestaddtoUser";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String bodyAttach="Action=AttachUserPolicy&Version=2010-05-08&PolicyArn="+URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null",error.get("Message"));
	}
	
	//attachPolicytoUser：添加策略到用户，必填项校验--policyArn
	@Test
	public void test_attachPolicyToUser_requirePolicyArn()throws Exception{
		String userName="createuserFortestPolicy";
		createGroup(userName);
		String bodyAttach="Action=AttachUserPolicy&Version=2010-05-08&UserName="+ userName ;
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'policyArn' failed to satisfy constraint: Member must not be null",error.get("Message"));
	
	}	
	
	//attachPolicy：添加策略到用户时，policyArn的字符串长度限制为2048,长度为2049，400异常
	@Test
	public void test_attachPolicyToUser_policyArnlength()throws Exception{
		String userName="createuserFortestPolicyARN";
		createUser(userName);
		StringBuilder sb=new StringBuilder();
		for(int i=0;i<2049;i++)
			sb.append("a");
		String body="Action=AttachUserPolicy&Version=2010-05-08&UserName="+ userName +"&PolicyArn="+sb.toString();
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value '"+sb.toString()+"' at 'policyArn' failed to satisfy constraint: Member must have length less than or equal to 2048",error.get("Message"));
				
	}	
	
	//attachPolicytoUser:添加策略到用户，User校验
	@Test
	public void test_attachPolicyToUser_invalidUserName()throws Exception{
		String policyName="createPolicyFortestaddtoUser";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String bodyAttach="Action=AttachUserPolicy&Version=2010-05-08&UserName=&PolicyArn="+URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'userName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",error.get("Message"));
	
	}	
	
	//attachPolicytoUser:添加策略到用户，User不存在
	@Test
	public void test_attachPolicyToUser_UserNameNotExist()throws Exception{
		String policyName="createPolicyFortestaddtoUser";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String bodyAttach="Action=AttachUserPolicy&Version=2010-05-08&UserName=userNotExist&PolicyArn="+URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(404,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("NoSuchEntity",error.get("Code"));
		assertEquals("The user with name userNotExist cannot be found.",error.get("Message"));
	
	}

	//attachPolicyToUser：添加策略到用户，policyArn为空字符串
	@Test
	public void test_attachPolicyToUser_invalidPolicyArn()throws Exception{
		String userName="createuserFortestinvalidPolicyArn";
		createUser(userName);
		String bodyAttach="Action=AttachUserPolicy&Version=2010-05-08&UserName="+ userName +"&PolicyArn=";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value '' at 'policyArn' failed to satisfy constraint: Member must have length greater than or equal to 20",error.get("Message"));
	
	}
	//policyArn的组成不为"arn:ctyun:iam::accountId:policy/policyName"
	@Test
	public void test_attachPolicyToUser_invalidPolicyArn2()throws Exception{
		String userName="createuserFortestinvalidPolicyArn";
		createUser(userName);
		String bodyAttach="Action=AttachUserPolicy&Version=2010-05-08&UserName="+ userName +"&PolicyArn="+URLEncoder.encode("arn:ctyun:iam::"+accountId+"/policyNotExist");
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("InvalidInput",error.get("Code"));
		assertEquals("ARN arn:ctyun:iam::"+accountId+"/policyNotExist is not valid.",error.get("Message"));
	
	}
	
	//attachPolicyToUser：添加策略到用户，policyArn不存在
	@Test
	public void test_attachPolicyToUser_PolicyNotExist()throws Exception{
		String userName="createuserFortestPolicynotExist";
		createUser(userName);
		String bodyAttach="Action=AttachUserPolicy&Version=2010-05-08&UserName="+ userName +"&PolicyArn="+URLEncoder.encode("arn:ctyun:iam::"+accountId+":policy/policyNotExist");
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(404,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("NoSuchEntity",error.get("Code"));
		assertEquals("Policy arn:ctyun:iam::"+accountId+":policy/policyNotExist does not exist or is not attachable.",error.get("Message"));
	
	}
	
	//attachPolicyUser:添加策略到用户时，策略数量限制为10，超出则报409
	@Test
	public void test_attachPolicyToUser_limitedPolicyNum()throws Exception{
		String userName="createuserFortestPolicyNum";
		createUser(userName);
		String policyName="policyFortestNum";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/" +policyName;
		for(int i=0;i<10;i++){
			createPolicy(policyName+i);
			attachPolicyToUser(userName,policyArn+i);
		}
		String bodyAttach="Action=AttachUserPolicy&Version=2010-05-08&UserName="+ userName +"&PolicyArn="+URLEncoder.encode("arn:ctyun:iam::"+accountId+":policy/"+policyName);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(409,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("LimitExceeded",error.get("Code"));
		assertEquals("Cannot exceed quota for PoliciesPerUser: 10.",error.get("Message"));
	
	}
	
	//attachPolicyUser:添加策略到用户时，同一策略重复加到用户中
	@Test
	public void test_attachPolicyToUser_limitedPolicyNum2()throws Exception{
		String userName="createuserFortestPolicyNum2";
		createUser(userName);
		String policyName="policyFortestNum";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/" +policyName;
		for(int i=0;i<10;i++){
			attachPolicyToUser(userName,policyArn);
		}
		String bodyAttach="Action=AttachUserPolicy&Version=2010-05-08&UserName="+ userName +"&PolicyArn="+URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
	}
	
	//attachPolicytoUser:添加策略到用户，添加到的用户不为本账户创建
//	@Test
	public void test_attachPolicyToUser_UserbelongtoOther()throws Exception{
		//使用其他账户创建用户
		String userName="userbelongtoOther";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKeyother, secretKeyother);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		
		//创建策略
		String policyName="attachepolicytoother";
		createPolicy(policyName);
		//将策略添加到用户
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String bodyAttach="Action=AttachUserPolicy&Version=2010-05-08&UserName="+ userName +"&PolicyArn="+URLEncoder.encode(policyArn);
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(404,resultatt.first().intValue());
		System.out.println(resultatt.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(resultatt.second());
		assertEquals("NoSuchEntity",error.get("Code"));
		assertEquals("The user with name "+userName+" cannot be found.",error.get("Message"));		
			
	}
	
	//attachPolicy:添加策略到用户，添加到用户的策略不为本账户创建
	@Test
	public void test_attachPolicyToUser_policybelongtoOther()throws Exception{
		//创建用户
		String userName="testforpolicybelongtoOther";
		createUser(userName);
		
		//使用其他用户创建策略
		String policyName="policybelongtoOther";
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\"],\"Resource\":[\"Arn:aws:s3:::EXAMPLE-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName="+ URLEncoder.encode(policyName) +"&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=test_des";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKeyother, secretKeyother);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		
		//将策略添加到用户中
		String policyArn="arn:ctyun:iam::0000000ehvd2i:policy/"+policyName;
		String bodyatt="Action=AttachUserPolicy&Version=2010-05-08&UserName="+ userName +"&PolicyArn="+URLEncoder.encode(policyArn);
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(bodyatt, accessKey, secretKey);
		assertEquals(403,resultatt.first().intValue());
		System.out.println(resultatt.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(resultatt.second());
		assertEquals("AccessDenied",error.get("Code"));
		assertEquals("Policy is outside your own account.",error.get("Message"));		
					
	}	
	
	//detachGroupPolicy：从组中删除策略
//	@Test
	public void test_detachPolicyFromGroup()throws Exception{
		String policyName="createPolicyForDetach";
		String groupName="creategroupfortestDetach";
		createGroup(groupName);
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		//添加策略到组
		attachPolicyToGroup(groupName,policyArn);
		
		//从组中删除策略
		String body="Action=DetachGroupPolicy&Version=2010-05-08&GroupName="+ groupName+"&PolicyArn=" + URLEncoder.encode(policyArn);
//		String body="Action=DetachGroupPolicy&Version=2010-05-08&GroupName=creategroupfortestpolicyNum&PolicyArn=" + URLEncoder.encode("arn:ctyun:iam::"+accountId+":policy/policyFortestNum0");
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
	}
	
	//detachGroupPolicy：从组中删除策略，groupName校验
	@Test
	public void test_detachPolicyFromGroup_invalidGroupName()throws Exception{
		String policyName="createPolicyFortestdetachfromGroup";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String body="Action=DetachGroupPolicy&Version=2010-05-08&GroupName=&PolicyArn="+URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'groupName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",error.get("Message"));		
		
	}	
	
	//detachGroupPolicy：从组中删除策略，必填项校验--groupName
	@Test
	public void test_detachPolicyFromGroup_requireGroupName()throws Exception{
		String policyName="createPolicyFortestdetachfromGroup";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String body="Action=DetachGroupPolicy&Version=2010-05-08&PolicyArn="+URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'groupName' failed to satisfy constraint: Member must not be null",error.get("Message"));		
		
	}
	
	//attachPolicy：从组中删除策略，policyArn校验
//	@Test
	public void test_detachPolicyFromGroup_invalidPolicyArn()throws Exception{
		String groupName="creategroupFortestdetachinvalidArn";
		createGroup(groupName);
		String body="Action=DetachGroupPolicy&Version=2010-05-08&GroupName="+ groupName +"&PolicyArn=";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value '' at 'policyArn' failed to satisfy constraint: Member must have length greater than or equal to 20",error.get("Message"));		
		
	}		
	
	//attachPolicy：从组中删除策略，必填项校验--policyArn
//	@Test
	public void test_detachPolicyFromGroup_requirePolicyArn()throws Exception{
		String groupName="creategroupFortestdetachrequireArn";
		createGroup(groupName);
		String body="Action=DetachGroupPolicy&Version=2010-05-08&GroupName="+ groupName ;
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'policyArn' failed to satisfy constraint: Member must not be null",error.get("Message"));		
		
	}	
	
	//detachGroupPolicy：从组中删除策略,策略不存在
//	@Test
	public void test_detachPolicyFromGroup_policyNotExist()throws Exception{
		String groupName="creategroupfortestDetachpolicyNotExist";
		createGroup(groupName);

		//从组中删除策略
		String body="Action=DetachGroupPolicy&Version=2010-05-08&GroupName="+ groupName+"&PolicyArn=" + URLEncoder.encode("arn:ctyun:iam::"+accountId+":policy/policyNotExist");
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(404,result.first().intValue());
		System.out.println(result.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("NoSuchEntity",error.get("Code"));
		assertEquals("Policy arn:ctyun:iam::"+accountId+":policy/policyNotExist does not exist or is not attachable.",error.get("Message"));		
		
	}
	
	//detachGroupPolicy：从组中删除策略,组中未添加策略
//	@Test
	public void test_detachPolicyFromGroup_policyNotExist2()throws Exception{
		String groupName="creategroupfortestDetachpolicyNotExist2";
		createGroup(groupName);
		String policyName="cratepolicyfortestpolicynotattachgroup";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;

		//从组中删除策略
		String body="Action=DetachGroupPolicy&Version=2010-05-08&GroupName="+ groupName+"&PolicyArn=" + URLEncoder.encode(policyArn);
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
	}
	
	//detachGroupPolicy：从组中删除策略,组不存在，404异常
	@Test
	public void test_detachPolicyFromGroup_groupNotExist()throws Exception{
		String groupName="groupNotExist";
		String policyName="cratepolicyfortestgroupnotExist";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		//从组中删除策略
		String body="Action=DetachGroupPolicy&Version=2010-05-08&GroupName="+ groupName+"&PolicyArn=" + URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(404,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("NoSuchEntity",error.get("Code"));
		assertEquals("The group with name groupNotExist cannot be found.",error.get("Message"));
	}
	
	//detachGroupPolicy：从组中删除策略,策略属于其他用户，403异常
	@Test
	public void test_detachPolicyFromGroup_policybelongtoOther()throws Exception{
		//创建组
		String groupName="testforpolicybelongtoOther";
//		createGroup(groupName);
		
		//使用其他用户创建策略
		String policyName="policybelongtoOther";
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\"],\"Resource\":[\"Arn:aws:s3:::EXAMPLE-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName="+ URLEncoder.encode(policyName) +"&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=test_des";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKeyother, secretKeyother);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		
		//将策略从组中移除
		String policyArn="arn:ctyun:iam::0000000ehvd2i:policy/"+policyName;
		String bodyatt="Action=DetachGroupPolicy&Version=2010-05-08&GroupName="+ groupName +"&PolicyArn="+URLEncoder.encode(policyArn);
		Pair<Integer,String> resultdet=IAMTestUtils.invokeHttpsRequest(bodyatt, accessKey, secretKey);
		assertEquals(403,resultdet.first().intValue());
		System.out.println(resultdet.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(resultdet.second());
		assertEquals("AccessDenied",error.get("Code"));
		assertEquals("Policy is outside your own account.",error.get("Message"));
	}	
		
				
	
	//detachUserPolicy：从用户中删除策略
//	@Test
	public void test_detachPolicyFromUser()throws Exception{
		String policyName="createPolicyForDetachfromuser";
		String userName="createUserfortestDetachfromuser";
		createUser(userName);
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		//添加策略到组
		attachPolicyToUser(userName,policyArn);
		
		//从组中删除策略
		String body="Action=DetachUserPolicy&Version=2010-05-08&UserName="+ userName+"&PolicyArn=" + URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
	}
	
	//detachUserPolicy：从用户中删除策略，必填项校验--userName
	@Test
	public void test_detachPolicyFromUser_requireUserName()throws Exception{
		String policyName="createPolicyFortestdetachfromUser";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String body="Action=DetachUserPolicy&Version=2010-05-08&PolicyArn="+URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null",error.get("Message"));
	}
	
	//detachUserPolicy：从用户中删除策略，userName为空字符串
	@Test
	public void test_detachPolicyFromUser_invalidUserName()throws Exception{
		String policyName="createPolicyFortestdetachfromUser";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String body="Action=DetachUserPolicy&Version=2010-05-08&UserName=&PolicyArn="+URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'userName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",error.get("Message"));
	}
	
	//detachUserPolicy：从用户中删除策略，必填项校验--policyArn
	@Test
	public void test_detachPolicyFromUser_requirePolicyArn()throws Exception{
		String userName="createuserFortestdetach";
//		createUser(userName);
		String body="Action=DetachUserPolicy&Version=2010-05-08&UserName="+ userName;
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'policyArn' failed to satisfy constraint: Member must not be null",error.get("Message"));
	
	}	
	//detachUserPolicy：从用户中删除策略，policyArn为空字符串
	@Test
	public void test_detachPolicyFromUser_invalidPolicyArn()throws Exception{
		String userName="createuserFortestdetach";
//		createUser(userName);
		String body="Action=DetachUserPolicy&Version=2010-05-08&UserName="+ userName +"&PolicyArn=";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value '' at 'policyArn' failed to satisfy constraint: Member must have length greater than or equal to 20",error.get("Message"));
	
	}	
	
	//detachUserPolicy：从用户中删除策略,用户不存在，404异常
	@Test
	public void test_detachPolicyFromUser_userNotExist()throws Exception{
		String userName="userNotExist";
		String policyName="cratepolicyfortestusernotExist";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		//从组中删除策略
		String body="Action=DetachUserPolicy&Version=2010-05-08&UserName="+ userName+"&PolicyArn=" + URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(404,result.first().intValue());
		System.out.println(result.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("NoSuchEntity",error.get("Code"));
		assertEquals("The user with name userNotExist cannot be found.",error.get("Message"));
	
	}
	
	//detachUserPolicy：从用户中删除策略,策略不存在
	@Test
	public void test_detachPolicyFromUser_policyArnNotExist()throws Exception{
		String userName="createuserfortestDetachpolicyNotExist";
		createUser(userName);

		//从组中删除策略
		String body="Action=DetachUserPolicy&Version=2010-05-08&UserName="+ userName+"&PolicyArn=" + URLEncoder.encode("arn:ctyun:iam::"+accountId+":policy/policyfortestdetachNotExist");
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(404,result.first().intValue());
		System.out.println(result.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("NoSuchEntity",error.get("Code"));
		assertEquals("Policy arn:ctyun:iam::"+accountId+":policy/policyfortestdetachNotExist does not exist or is not attachable.",error.get("Message"));
	
	}	
	//detachUserPolicy：从用户中删除策略，用户中未添加策略
	@Test
	public void test_detachPolicyFromUser_policyArnNotExist2()throws Exception{
		String userName="createuserfortestDetachpolicyNotExist2";
		createUser(userName);
		String policyName="cratepolicyfortestpolicynotattachgroup";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		
		//从用户中删除策略
		String body="Action=DetachUserPolicy&Version=2010-05-08&UserName="+ userName+"&PolicyArn=" + URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
	}

	//detachUserPolicy:添加策略到用户，从用户的移除的策略不为本账户创建
	@Test
	public void test_detachPolicyFromUser_policybelongtoOther()throws Exception{
		//创建用户
		String userName="testforpolicybelongtoOther";
//		createUser(userName);
		
		//使用其他用户创建策略
		String policyName="policybelongtoOther";
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\"],\"Resource\":[\"Arn:aws:s3:::EXAMPLE-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName="+ URLEncoder.encode(policyName) +"&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=test_des";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKeyother, secretKeyother);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		
		//将策略添加到用户中
		String policyArn="arn:ctyun:iam::0000000ehvd2i:policy/"+policyName;
		String bodydet="Action=DetachUserPolicy&Version=2010-05-08&UserName="+ userName +"&PolicyArn="+URLEncoder.encode(policyArn);
		Pair<Integer,String> resultdet=IAMTestUtils.invokeHttpsRequest(bodydet, accessKey, secretKey);
		assertEquals(403,resultdet.first().intValue());
		System.out.println(resultdet.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(resultdet.second());
		assertEquals("AccessDenied",error.get("Code"));
		assertEquals("Policy is outside your own account.",error.get("Message"));		
					
	}
	
	//getPolicy:策略添加到用户和组中进行获取
	@Test
	public void test_getPolicy()throws Exception{
		IAMTestUtils.TrancateTable("iam-accountSummary-huxl");
		String policyName="attacheUserAndGroupPolicy";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String groupName="attachGroupPolicy";
		createGroup(groupName);
		String userName="attachUserPolicy";
		createUser(userName);
		attachPolicyToUser(userName,policyArn);
		attachPolicyToGroup(groupName,policyArn);
		
		//获取策略
		String body = "Action=GetPolicy&Version=2010-05-08&PolicyArn=" + URLEncoder.encode(policyArn);
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
		JSONObject response= new JSONObject();
        response = ParseXmlToJson(resultatt.second(), "GetPolicy");
        System.out.print(response);
        assertEquals(policyName,response.get("PolicyName"));
        assertEquals(policyArn, response.get("Arn"));
        assertEquals("true",response.get("IsAttachable"));
        assertEquals("test_des",response.get("Description"));
        assertEquals("2",response.get("AttachmentCount"));
        assertEquals("Local",response.get("Scope"));
        assertEquals(URLEncoder.encode(publicpolicyDocument),response.get("Document"));
        assertNotNull(response.get("CreateDate"));
        assertNotNull(response.get("UpdateDate")); 
        assertNotNull(response.get("PolicyId")); 
	}
	
	//getPolicy:策略仅添加到用户中
	@Test
	public void test_getPolicy_attacheUserPolicy() throws Exception{
		String policyName="attacheUserPolicy";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String userName="attachUserpolicy2";
		createUser(userName);
		attachPolicyToUser(userName,policyArn);
		
		//获取策略
		String body = "Action=GetPolicy&Version=2010-05-08&PolicyArn=" + URLEncoder.encode(policyArn);
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
	}
	
	//getPolicy:策略添加到多个用户中
//	@Test
	public void test_getPolicy_attacheUserPolicy2() throws Exception{
		String policyName="attacheUserPolicy2";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String userName="attacheuserpolicytest2";
		for(int i=0;i<15;i++){
			createUser(userName+i);
			attachPolicyToUser(userName+i,policyArn);
		}
		
		//获取策略
		String body = "Action=GetPolicy&Version=2010-05-08&PolicyArn=" + URLEncoder.encode(policyArn);
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
	}	
	//getPolicy:策略仅添加到组中
//	@Test
	public void test_getPolicy_attacheGroup()throws Exception{
		String policyName="attacheGroupPolicy";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String groupName="attachGroupPolicy2";
		createGroup(groupName);
		attachPolicyToGroup(groupName,policyArn);
		
		//获取策略
		String body = "Action=GetPolicy&Version=2010-05-08&PolicyArn=" + URLEncoder.encode(policyArn);
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
	}
	//getPolicy:策略添加到多个组中
//	@Test
	public void test_getPolicy_attacheGroup2()throws Exception{
		String policyName="attacheGroupPolicytest2";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String groupName="attachGroupPolicytest2";
		for(int i=0;i<15;i++){
			createGroup(groupName+i);
			attachPolicyToGroup(groupName+i,policyArn);			
		}

		//获取策略
		String body = "Action=GetPolicy&Version=2010-05-08&PolicyArn=" + URLEncoder.encode(policyArn);
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
	}	
	//getPolicy:策略存在但未添加到任何用户和组中
//	@Test
	public void test_getPolicy_notattache()throws Exception{
		String policyName="createPolicyfortestnotattached";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		//获取策略
		String body = "Action=GetPolicy&Version=2010-05-08&PolicyArn=" + URLEncoder.encode(policyArn);
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
	}	
	//getPolicy:策略不存在
	@Test
	public void test_getPolicy_policyNotExist()throws Exception{
		String policyName="createPolicyfortestPolicynotexist";
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		//获取策略
		String body = "Action=GetPolicy&Version=2010-05-08&PolicyArn=" + URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(404,result.first().intValue());
		System.out.println(result.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("NoSuchEntity",error.get("Code"));
		assertEquals("Policy "+policyArn+" does not exist or is not attachable.",error.get("Message"));		
		
	}	
	
	//getPolicy:获取策略--必填项检验
	@Test
	public void test_getPolicy_requiredpolicArn()throws Exception{
		String body = "Action=GetPolicy&Version=2010-05-08";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'policyArn' failed to satisfy constraint: Member must not be null",error.get("Message"));		
		
	}	
		
	//getPolicy:获取策略--policyArn为空字符串
//	@Test
	public void test_getPolicy_invalidpolicArn()throws Exception{
		String body = "Action=GetPolicy&Version=2010-05-08&PolicyArn=";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value '' at 'policyArn' failed to satisfy constraint: Member must have length greater than or equal to 20",error.get("Message"));
	
	}	
	
	//getPolicy:使用其他账户获取策略
	@Test
	public void test_getPolicy_otheraccount()throws Exception{
		String policyName="createforothersgetpolicy";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String groupName="createGroupforothersgetPolicy";
		createGroup(groupName);
		attachPolicyToGroup(groupName,policyArn);
		
		//获取策略
		String body = "Action=GetPolicy&Version=2010-05-08&PolicyArn=" + URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKeyother, secretKeyother);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("AccessDenied",error.get("Code"));
		assertEquals("Policy is outside your own account.",error.get("Message"));		
			
	}	
	
	//ListAttachedUserPolicies：列出附加到用户的policies，测试方便设置MaxItems为10；只传入参数UserName
//	@Test
	public void test_listAttachedUserPolicies()throws Exception{
		String userName="createforListAttachedUserPolicies";
		createUser(userName);
		String policyName="forlistattachedUser";
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		for(int i=0;i<10;i++){
			createPolicy(policyName+i);
			attachPolicyToUser(userName,policyArn+i);
			
		}
		String body = "Action=ListAttachedUserPolicies&Version=2010-05-08&UserName=" + userName;
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
		JSONObject response= new JSONObject();
        response = ParseXmlToJson2(resultatt.second(), "ListAttachedUserPolicies");
        System.out.print(response);
        JSONObject policies = response.getJSONObject("AttachedPolicies").getJSONObject("member1");
        assertEquals(policyName+0,policies.get("PolicyName"));
        assertEquals(policyArn+0, policies.get("PolicyArn"));
        assertEquals("false",response.get("IsTruncated"));
        assertEquals("test_des",policies.get("Description"));
        assertEquals("Local",policies.get("Scope"));
	}		

	//ListAttachedUserPolicies：列出附加到用户内的policies，设置MaxItems为5
	@Test
	public void test_listAttachedUserPolicies_setMaxItems()throws Exception{
		String userName="createforListAttachedUserPolicies";
		createUser(userName);
		String policyName="forlistattachedUser";
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		for(int i=0;i<10;i++){
			createPolicy(policyName+i);
			attachPolicyToUser(userName,policyArn+i);
			
		}
		String body = "Action=ListAttachedUserPolicies&Version=2010-05-08&UserName="+userName+"&MaxItems=5";
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
		JSONObject response= new JSONObject();
        response = ParseXmlToJson2(resultatt.second(), "ListAttachedUserPolicies");
        System.out.print(response);
        assertEquals("true",response.get("IsTruncated"));
        assertEquals("policy|"+accountId+"|"+userName.toLowerCase()+"|Local|forlistattacheduser4",response.get("Marker"));
	}
	
	//ListAttachedUserPolicies：列出附加到用户内的policies,设置Marker
	@Test
	public void test_listAttachedUserPolicies_setMarker()throws Exception{
		String userName="createforListAttachedUserPolicies";
		createUser(userName);
		String policyName="forlistattachedUser";
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		for(int i=0;i<9;i++){
			createPolicy(policyName+i);
			attachPolicyToUser(userName,policyArn+i);
			
		}
		String body = "Action=ListAttachedUserPolicies&Version=2010-05-08&UserName="+userName+"&Marker=" + "policy|"+accountId+"|createforListAttachedUserPolicies|Local|forlistattachedUser4";
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
	}			

	//ListAttachedUserPolicies：列出附加到用户内的policies,设置Marker,MaxIterms
	@Test
	public void test_listAttachedUserPolicies2()throws Exception{
		String userName="createforListAttachedUserPolicies";
		createUser(userName);
		String policyName="forlistattachedUser";
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		for(int i=0;i<10;i++){
			createPolicy(policyName+i);
			attachPolicyToUser(userName,policyArn+i);
			
		}
		String body = "Action=ListAttachedUserPolicies&Version=2010-05-08&UserName="+ userName +"&MaxItems=2" + "&Marker=" + "policy|"+accountId+"|createforListAttachedUserPolicies|Local|forlistattachedUser4";
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
	}				

	//ListAttachedUserPolicies：必填项校验--userName,不传入UserName,400异常
//	@Test
	public void test_listAttachedUserPolicies_requiredUserName()throws Exception{
		String body = "Action=ListAttachedUserPolicies&Version=2010-05-08";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null",error.get("Message"));
	
	}
	
	//ListAttachedUserPolicies：用户不存在，400异常
	@Test
	public void test_listAttachedUserPolicies_UserNotExist()throws Exception{
		String body = "Action=ListAttachedUserPolicies&Version=2010-05-08&UserName=userNotExist";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(404,result.first().intValue());
		System.out.println(result.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("NoSuchEntity",error.get("Code"));
		assertEquals("The user with name userNotExist cannot be found.",error.get("Message"));
		
	}	
	
	//ListAttachedUserPolicies：用户存在，策略存在，用户未添加策略
	@Test
	public void test_listAttachedUserPolicies_noAttached()throws Exception{
		String userName="createfornoattachedPolicies";
		createUser(userName);
		String policyName="forlistattachedUser";
		createPolicy(policyName);

		String body = "Action=ListAttachedUserPolicies&Version=2010-05-08&UserName="+ userName;
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
	}
	
	//ListAttachedUserPolicies:用户存在但属于其他用户
//	@Test
	public void test_listAttachedUserPolicies_userbelongtoOther()throws Exception{
		//使用其他账户创建用户
		String userName="userbelongtoOther";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKeyother, secretKeyother);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());

		String bodylist="Action=ListAttachedUserPolicies&Version=2010-05-08&UserName="+ userName ;
		Pair<Integer,String> resultlist=IAMTestUtils.invokeHttpsRequest(bodylist, accessKey, secretKey);
		assertEquals(404,resultlist.first().intValue());
		System.out.println(resultlist.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(resultlist.second());
		assertEquals("NoSuchEntity",error.get("Code"));
		assertEquals("The user with name "+ userName +" cannot be found.",error.get("Message"));		
	}	
	
	
	//ListAttachedGroupPolicies：列出附加到组内的policies，测试方便设置MaxItems为10；只传入参数GroupName
	@Test
	public void test_listAttachedGroupPolicies()throws Exception{
		String groupName="createforListAttachedGroupPolicies";
		createGroup(groupName);
		String policyName="forlistattachedGroup";
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		for(int i=0;i<10;i++){
			createPolicy(policyName+i);
			attachPolicyToGroup(groupName,policyArn+i);
			
		}
		String body = "Action=ListAttachedGroupPolicies&Version=2010-05-08&GroupName=" + groupName;
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
		JSONObject response= new JSONObject();
        response = ParseXmlToJson2(resultatt.second(), "ListAttachedGroupPolicies");
        System.out.print(response);
        JSONObject policies = response.getJSONObject("AttachedPolicies").getJSONObject("member1");
        assertEquals(policyName+0,policies.get("PolicyName"));
        assertEquals(policyArn+0, policies.get("PolicyArn"));
        assertEquals("false",response.get("IsTruncated"));
        assertEquals("test_des",policies.get("Description"));
        assertEquals("Local",policies.get("Scope"));
	}		

	//ListAttachedGroupPolicies：列出附加到组内的policies，设置MaxItems为5
//	@Test
	public void test_listAttachedGroupPolicies_setMaxItems()throws Exception{
		String groupName="createforListAttachedGroupPolicies";
		createGroup(groupName);
		String policyName="forlistattachedgroup";
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		for(int i=0;i<10;i++){
			createPolicy(policyName+i);
			attachPolicyToGroup(groupName,policyArn+i);
			
		}
		String body = "Action=ListAttachedGroupPolicies&Version=2010-05-08&GroupName="+groupName+"&MaxItems=5";
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
		JSONObject response= new JSONObject();
        response = ParseXmlToJson2(resultatt.second(), "ListAttachedGroupPolicies");
        System.out.print(response);
        assertEquals("true",response.get("IsTruncated"));
        assertEquals("policy|"+accountId+"|"+groupName.toLowerCase()+"|Local|forlistattachedgroup4",response.get("Marker"));
	}
	
	//ListAttachedGroupPolicies：列出附加到组内的policies,设置Marker
	@Test
	public void test_listAttachedGroupPolicies_setMarker()throws Exception{
		String groupName="createforListAttachedGroupPolicies";
		createGroup(groupName);
		String policyName="forlistattachedGroup";
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		for(int i=0;i<10;i++){
			createPolicy(policyName+i);
			attachPolicyToGroup(groupName,policyArn+i);
			
		}
		String body = "Action=ListAttachedGroupPolicies&Version=2010-05-08&GroupName="+groupName+"&Marker=" + "policy|"+accountId+"|createforListAttachedGroupPolicies|Local|forlistattachedGroup4";
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
	}			

	//ListAttachedGroupPolicies：列出附加到组内的policies,设置Marker,MaxIterms
//	@Test
	public void test_listAttachedGroupPolicies2()throws Exception{
		String groupName="createforListAttachedGroupPolicies";
		createGroup(groupName);
		String policyName="forlistattachedGroup";
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		for(int i=0;i<10;i++){
			createPolicy(policyName+i);
			attachPolicyToGroup(groupName,policyArn+i);
			
		}
		String body = "Action=ListAttachedGroupPolicies&Version=2010-05-08&GroupName="+ groupName +"&MaxItems=2" + "&Marker=" + "policy|"+accountId+"|createforListAttachedGroupPolicies|Local|forlistattachedGroup4";
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
	}				

	//ListAttachedGroupPolicies：必填项校验--groupName,不传入GroupName,400异常
	@Test
	public void test_listAttachedGroupPolicies_requiredGroupName()throws Exception{
		String body = "Action=ListAttachedGroupPolicies&Version=2010-05-08";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'groupName' failed to satisfy constraint: Member must not be null",error.get("Message"));
	
	}
	
	//ListAttachedGroupPolicies：组不存在，400异常
//	@Test
	public void test_listAttachedGroupPolicies_groupNotExist()throws Exception{
		String body = "Action=ListAttachedGroupPolicies&Version=2010-05-08&GroupName=groupNotExist";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(404,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("NoSuchEntity",error.get("Code"));
		assertEquals("The group with name groupNotExist cannot be found.",error.get("Message"));
	
	}	
	
	//ListAttachedGroupPolicies：组存在，策略存在，组内未添加策略
	@Test
	public void test_listAttachedGroupPolicies_noAttached()throws Exception{
		String groupName="createfornoattachedPolicies";
		createGroup(groupName);
		String policyName="forlistattachedGroup";
		createPolicy(policyName);

		String body = "Action=ListAttachedGroupPolicies&Version=2010-05-08&GroupName="+ groupName;
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
	}
	
	//ListAttachedGroupPolicies:组存在但属于其他用户
//	@Test
	public void test_listAttachedGroupPolicies_groupbelongtoOther()throws Exception{
		//使用其他用户创建组
		String groupName="groupbelongtoOther";
		String body="Action=CreateGroup&Version=2010-05-08&GroupName="+groupName;
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKeyother, secretKeyother);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());

		String bodylist="Action=ListAttachedGroupPolicies&Version=2010-05-08&GroupName="+ groupName ;
		Pair<Integer,String> resultlist=IAMTestUtils.invokeHttpsRequest(bodylist, accessKey, secretKey);
		assertEquals(404,resultlist.first().intValue());
		System.out.println(resultlist.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(resultlist.second());
		assertEquals("NoSuchEntity",error.get("Code"));
		assertEquals("The group with name "+groupName+" cannot be found.",error.get("Message"));
	
	}


	//ListEntitiesForPolicy:前提：策略添加到用户和组中,列出策略附加的用户和组
//	@Test
	public void test_listEntitiesForPolicy()throws Exception{
		IAMTestUtils.TrancateTable("iam-accountSummary-huxl");
		String policyName="attacheUserAndGroupPolicy";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String groupName="attachGroupPolicy";
		createGroup(groupName);
		String userName="attachUserPolicy";
		createUser(userName);
		attachPolicyToUser(userName,policyArn);
		attachPolicyToGroup(groupName,policyArn);
		
		//获取策略
		String body = "Action=ListEntitiesForPolicy&Version=2010-05-08&PolicyArn=" + URLEncoder.encode(policyArn);
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
		JSONObject response= new JSONObject();
        response = ParseXmlToJson2(resultatt.second(), "ListEntitiesForPolicy");
        System.out.print(response);
        JSONObject policyUser = response.getJSONObject("PolicyUsers").getJSONObject("member1");
        JSONObject policyGroup = response.getJSONObject("PolicyGroups").getJSONObject("member1");
        assertEquals("false",response.get("IsTruncated"));
        assertEquals(userName,policyUser.get("UserName"));
        assertEquals(groupName, policyGroup.get("GroupName"));
        assertNotNull(policyUser.get("UserId"));
        assertNotNull(policyGroup.get("GroupId"));
	}
	
	//ListEntitiesForPolicy:前提:策略添加到用户和组中进行获取,设置EntityFilter为User获取该策略下的用户
//	@Test
	public void test_listEntitiesForPolicy_setEntityFilter1()throws Exception{
		IAMTestUtils.TrancateTable("iam-accountSummary-huxl");
		String policyName="attacheUserAndGroupPolicy";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String groupName="attachGroupPolicy";
		for(int i=0;i<15;i++){
			createGroup(groupName+i);
			attachPolicyToGroup(groupName+i,policyArn);			
		}
		String userName="attachUserPolicy";
		for(int i=0;i<15;i++){
			createUser(userName+i);
			attachPolicyToUser(userName+i,policyArn);
		}
		
		//获取策略
		String body = "Action=ListEntitiesForPolicy&Version=2010-05-08&EntityFilter=User&PolicyArn=" + URLEncoder.encode(policyArn);
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
		JSONObject response= new JSONObject();
        response = ParseXmlToJson2(resultatt.second(), "ListEntitiesForPolicy");
        System.out.print(response);
        JSONObject policyUser = response.getJSONObject("PolicyUsers").getJSONObject("member1");
        JSONObject policyGroup = response.getJSONObject("PolicyGroups");
        assertEquals("true",response.get("IsTruncated"));
        assertEquals(userName+0,policyUser.get("UserName"));
        assertNotNull(policyUser.get("UserId"));
        assertEquals("{}", policyGroup.toString());
	}
	
	//ListEntitiesForPolicy:前提:策略添加到用户和组中进行获取,设置EntityFilter为Group获取该策略下的组
//	@Test
	public void test_listEntitiesForPolicy_setEntityFilter2()throws Exception{
		IAMTestUtils.TrancateTable("iam-accountSummary-huxl");
		String policyName="attacheUserAndGroupPolicy";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String groupName="attachGroupPolicy";
		for(int i=0;i<15;i++){
			createGroup(groupName+i);
			attachPolicyToGroup(groupName+i,policyArn);			
		}
		String userName="attachUserPolicy";
		for(int i=0;i<15;i++){
			createUser(userName+i);
			attachPolicyToUser(userName+i,policyArn);
		}
		
		//获取策略
		String body = "Action=ListEntitiesForPolicy&Version=2010-05-08&EntityFilter=Group&PolicyArn=" + URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		JSONObject response= new JSONObject();
        response = ParseXmlToJson2(result.second(), "ListEntitiesForPolicy");
        System.out.print(response);
        JSONObject policyUser = response.getJSONObject("PolicyUsers");
        JSONObject policyGroup = response.getJSONObject("PolicyGroups").getJSONObject("member1");
        assertEquals("true",response.get("IsTruncated"));
        assertEquals(groupName+0,policyGroup.get("GroupName"));
        assertNotNull(policyGroup.get("GroupId"));
        assertEquals("{}", policyUser.toString());
	}
	
	//ListEntitiesForPolicy:前提:策略添加到用户和组中进行获取(为测试方便MaxIterms默认值为10),设置MaxItems为16获取该策略下的用户和组
//	@Test
	public void test_listEntitiesForPolicy_setMaxItems()throws Exception{
		IAMTestUtils.TrancateTable("iam-accountSummary-huxl");
		String policyName="attacheUserAndGroupPolicy";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String groupName="attachGroupPolicy";
		for(int i=0;i<15;i++){
			createGroup(groupName+i);
			attachPolicyToGroup(groupName+i,policyArn);			
		}
		String userName="attachUserPolicy";
		for(int i=0;i<15;i++){
			createUser(userName+i);
			attachPolicyToUser(userName+i,policyArn);
		}
		
		//获取策略
		String body = "Action=ListEntitiesForPolicy&Version=2010-05-08&MaxItems=16&PolicyArn=" + URLEncoder.encode(policyArn);
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
	}
	
	//ListEntitiesForPolicy:前提:策略添加到用户和组中进行获取(为测试方便MaxIterms默认值为10),设置Marker获取该策略下的用户和组
	@Test
	public void test_listEntitiesForPolicy_setMarker()throws Exception{
		IAMTestUtils.TrancateTable("iam-accountSummary-huxl");
		String policyName="attacheUserAndGroupPolicy";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String groupName="attachGroupPolicy";
		for(int i=0;i<15;i++){
			createGroup(groupName+i);
			attachPolicyToGroup(groupName+i,policyArn);			
		}
		String userName="attachUserPolicy";
		for(int i=0;i<15;i++){
			createUser(userName+i);
			attachPolicyToUser(userName+i,policyArn);
		}
		
		//获取策略
		String body = "Action=ListEntitiesForPolicy&Version=2010-05-08&PolicyArn=" + URLEncoder.encode(policyArn) + "&Marker=entity|"+accountId+"|Local|attacheUserAndGroupPolicy|Group|attachGroupPolicy4";
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
	}
	
	//ListEntitiesForPolicy:前提:策略添加到用户和组中进行获取(为测试方便MaxIterms默认值为10),设置Marker和maxIterms获取该策略下的用户和组
	@Test
	public void test_listEntitiesForPolicy2()throws Exception{
		IAMTestUtils.TrancateTable("iam-accountSummary-huxl");
		String policyName="attacheUserAndGroupPolicy";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String groupName="attachGroupPolicy";
		for(int i=0;i<15;i++){
			createGroup(groupName+i);
			attachPolicyToGroup(groupName+i,policyArn);			
		}
		String userName="attachUserPolicy";
		for(int i=0;i<15;i++){
			createUser(userName+i);
			attachPolicyToUser(userName+i,policyArn);
		}
		
		//获取策略
		String body = "Action=ListEntitiesForPolicy&Version=2010-05-08&MaxItems=5&PolicyArn=" + URLEncoder.encode(policyArn) + "&Marker=entity|"+accountId+"|Local|attacheUserAndGroupPolicy|Group|attachGroupPolicy7";
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
	}		
	
	//ListEntitiesForPolicy:前提：策略存在但未添加到任何用户和组中
	@Test
	public void test_listEntitiesForPolicy_notattache()throws Exception{
		String policyName="createPolicyfortestnotattached";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		//获取策略
		String body = "Action=ListEntitiesForPolicy&Version=2010-05-08&PolicyArn=" + URLEncoder.encode(policyArn);
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
		JSONObject response= new JSONObject();
        response = ParseXmlToJson2(resultatt.second(), "ListEntitiesForPolicy");
        System.out.print(response);
        JSONObject policyUser = response.getJSONObject("PolicyUsers");
        JSONObject policyGroup = response.getJSONObject("PolicyGroups");
        assertEquals("false",response.get("IsTruncated"));
        assertEquals("{}", policyGroup.toString());
        assertEquals("{}", policyUser.toString());
	}	
	//ListEntitiesForPolicy:策略不存在
//	@Test
	public void test_listEntitiesForPolicy_policyNotExist()throws Exception{
		String policyName="createPolicyfortestPolicynotexist";
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		//获取策略
		String body = "Action=ListEntitiesForPolicy&Version=2010-05-08&PolicyArn=" + URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(404,result.first().intValue());
		System.out.println(result.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("NoSuchEntity",error.get("Code"));
		assertEquals("Policy "+ policyArn +" does not exist or is not attachable.",error.get("Message"));		
		
	}	
	
	//ListEntitiesForPolicy:获取策略--必填项检验
//	@Test
	public void test_listEntitiesForPolicy_requiredpolicArn()throws Exception{
		String body = "Action=ListEntitiesForPolicy&Version=2010-05-08";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'policyArn' failed to satisfy constraint: Member must not be null",error.get("Message"));		
		
	}	
		
	//ListEntitiesForPolicy:获取策略--policyArn为空字符串
//	@Test
	public void test_listEntitiesForPolicy_invalidpolicArn()throws Exception{
		String body = "Action=ListEntitiesForPolicy&Version=2010-05-08&PolicyArn=";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value '' at 'policyArn' failed to satisfy constraint: Member must have length greater than or equal to 20",error.get("Message"));		
		
	}
	
	@Test
	public void test_listEntitiesForPolicy_invalidpolicArn2()throws Exception{
		String body = "Action=ListEntitiesForPolicy&Version=2010-05-08&PolicyArn=arn:ctyun:iam::"+accountId+"/policyname";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("InvalidInput",error.get("Code"));
		assertEquals("ARN arn:ctyun:iam::"+accountId+"/policyname is not valid.",error.get("Message"));		
		
	}	
	
	//ListEntitiesForPolicy:获取策略--invalidEntityFilter为user/group
	@Test
	public void test_listEntitiesForPolicy_InvalidEntityFilter()throws Exception{
//		IAMTestUtils.TrancateTable("iam-accountSummary-huxl");
		String policyName="attacheUserAndGroupPolicy";
//		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
//		String groupName="attachGroupPolicy";
//		createGroup(groupName);
//		String userName="attachUserPolicy";
//		createUser(userName);
//		attachPolicyToUser(userName,policyArn);
//		attachPolicyToGroup(groupName,policyArn);
		
		//获取策略
		String body = "Action=ListEntitiesForPolicy&Version=2010-05-08&PolicyArn=" + URLEncoder.encode(policyArn) + "&EntityFilter=user";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value 'user' at 'entityFilter' failed to satisfy constraint: Member must satisfy enum value set: [User, Group]",error.get("Message"));		
				
		//获取策略
		String bodylist = "Action=ListEntitiesForPolicy&Version=2010-05-08&PolicyArn=" + URLEncoder.encode(policyArn) + "&EntityFilter=group";
		Pair<Integer,String> resultlist=IAMTestUtils.invokeHttpsRequest(bodylist, accessKey, secretKey);
		assertEquals(400,resultlist.first().intValue());
		System.out.println(resultlist.second());		
		JSONObject  errorlist=IAMTestUtils.ParseErrorToJson(resultlist.second());
		assertEquals("ValidationError",errorlist.get("Code"));
		assertEquals("1 validation error detected: Value 'group' at 'entityFilter' failed to satisfy constraint: Member must satisfy enum value set: [User, Group]",errorlist.get("Message"));		
		
	}
	
	
	
	
	//ListEntitiesForPolicy:使用其他账户获取策略,403异常
//	@Test
	public void test_listEntitiesForPolicy_otheraccount()throws Exception{
		String policyName="createforothersgetpolicy12121";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		String groupName="createGroupforothersgetPolicy";
		createGroup(groupName);
		attachPolicyToGroup(groupName,policyArn);
		
		//获取策略
		String body = "Action=ListEntitiesForPolicy&Version=2010-05-08&PolicyArn=" + URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKeyother, secretKeyother);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("AccessDenied",error.get("Code"));
		assertEquals("Policy is outside your own account.",error.get("Message"));		
			
	}	
		
	//ListPolicies:存在策略添加到用户和组中，策略未加到任何组/用户中
	@Test
	public void test_listPolicies()throws Exception{	
		IAMTestUtils.TrancateTable("iam-accountSummary-huxl");
		String policyName="listPolicies";
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		createPolicy(policyName);
		String groupName="attachGroupPolicy";
		createGroup(groupName);
		String userName="attachUserPolicy";
		createUser(userName);
		//创建8个策略，加到同一个组attachGroupPolicy中
		for(int i=0;i<8;i++){
			createPolicy(policyName+i);
			attachPolicyToGroup(groupName,policyArn+i);
		}
		//创建3个组，每个组中加入策略listPolicies
		for(int i=0;i<3;i++){
			createGroup(groupName+i);
			attachPolicyToGroup(groupName+i,policyArn);
		}
		//创建3个用户，每个用户中加入策略listPolicies
		for(int i=0;i<3;i++){
			createUser(userName+i);
			attachPolicyToUser(userName+i,policyArn);
		}
		//将listPolicies1附加到用户attachUserPolicy和组attachGroupPolicy中
		attachPolicyToUser(userName,policyArn+1);
		attachPolicyToGroup(groupName,policyArn+1);
		
		//策略未添加到任何组和用户中
		createPolicy("listPolicies9");
		createPolicy("listPolicies10");
		
		//获取策略
		String body = "Action=ListPolicies&Version=2010-05-08";
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
		
		JSONObject response= new JSONObject();
        response = ParseXmlToJson2(resultatt.second(), "ListPolicies");
        System.out.print(response);
        JSONObject policies = response.getJSONObject("Policies").getJSONObject("member1");
        assertEquals("true",response.get("IsTruncated"));
        assertEquals("0000000gc0uy9|listpolicies7",response.get("Marker"));
        assertEquals(policyName,policies.get("PolicyName"));
        assertEquals(policyArn, policies.get("Arn"));
        assertEquals("true",policies.get("IsAttachable"));
        assertEquals("test_des",policies.get("Description"));
        assertEquals("6",policies.get("AttachmentCount"));
        assertEquals("Local",policies.get("Scope"));
        assertNotNull(policies.get("CreateDate"));
        assertNotNull(policies.get("UpdateDate")); 
        assertNotNull(policies.get("PolicyId")); 
	}
	
	//ListPolicies:策略添加到用户和组中，策略未加到任何组合用户中,设置policyName，policyName为模糊查询
//	@Test
	public void test_listPolicies_setPolicyName()throws Exception{	
		IAMTestUtils.TrancateTable("iam-accountSummary-huxl");
		String policyName="listPolicies";
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		createPolicy(policyName);
		String groupName="attachGroupPolicy";
		createGroup(groupName);
		String userName="attachUserPolicy";
		createUser(userName);
		//创建8个策略，加到同一个组attachGroupPolicy中
		for(int i=0;i<8;i++){
			createPolicy(policyName+i);
			attachPolicyToGroup(groupName,policyArn+i);
		}
		//创建3个组，每个组中加入策略listPolicies
		for(int i=0;i<3;i++){
			createGroup(groupName+i);
			attachPolicyToGroup(groupName+i,policyArn);
		}
		//创建3个用户，每个用户中加入策略listPolicies
		for(int i=0;i<3;i++){
			createUser(userName+i);
			attachPolicyToUser(userName+i,policyArn);
		}
		//将listPolicies1附加到用户attachUserPolicy和组attachGroupPolicy中
		attachPolicyToUser(userName,policyArn+1);
		attachPolicyToGroup(groupName,policyArn+1);
		
		//策略未添加到任何组和用户中
		createPolicy("listPolicies9");
		createPolicy("listPolicies10");
		
		//获取策略
		String body = "Action=ListPolicies&Version=2010-05-08&PolicyName=listPolicies1";
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
		
		JSONObject response= new JSONObject();
        response = ParseXmlToJson2(resultatt.second(), "ListPolicies");
        System.out.print(response);
        JSONObject policy1 = response.getJSONObject("Policies").getJSONObject("member1");
        JSONObject policy2 = response.getJSONObject("Policies").getJSONObject("member2");
        assertEquals("false",response.get("IsTruncated"));
        assertEquals(policyName+1,policy1.get("PolicyName"));
        assertEquals("2",policy1.get("AttachmentCount"));
        assertEquals(policyName+10,policy2.get("PolicyName"));
        assertEquals("0",policy2.get("AttachmentCount"));
 
	}

	//ListPolicies:策略添加到用户和组中，策略未加到任何组合用户中（为测试方便，修改MaxIterms默认值为10）,设置MaxIterms=5
//	@Test
	public void test_listPolicies_setMaxItems()throws Exception{	
		IAMTestUtils.TrancateTable("iam-accountSummary-huxl");
		String policyName="listPolicies";
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		createPolicy(policyName);
		String groupName="attachGroupPolicy";
		createGroup(groupName);
		String userName="attachUserPolicy";
		createUser(userName);
		//创建8个策略，加到同一个组attachGroupPolicy中
		for(int i=0;i<8;i++){
			createPolicy(policyName+i);
			attachPolicyToGroup(groupName,policyArn+i);
		}
		//创建3个组，每个组中加入策略listPolicies
		for(int i=0;i<3;i++){
			createGroup(groupName+i);
			attachPolicyToGroup(groupName+i,policyArn);
		}
		//创建3个用户，每个用户中加入策略listPolicies
		for(int i=0;i<3;i++){
			createUser(userName+i);
			attachPolicyToUser(userName+i,policyArn);
		}
		//将listPolicies1附加到用户attachUserPolicy和组attachGroupPolicy中
		attachPolicyToUser(userName,policyArn+1);
		attachPolicyToGroup(groupName,policyArn+1);
		
		//策略未添加到任何组和用户中
		createPolicy("listPolicies9");
		createPolicy("listPolicies10");
		
		//获取策略
		String body = "Action=ListPolicies&Version=2010-05-08&MaxItems=5";
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
		
		JSONObject response= new JSONObject();
        response = ParseXmlToJson2(resultatt.second(), "ListPolicies");
        System.out.print(response);
        assertEquals("true",response.get("IsTruncated"));
        assertEquals("0000000gc0uy9|listpolicies2",response.get("Marker"));
	}	

	//ListPolicies:策略添加到用户和组中，策略未加到任何组合用户中（为测试方便，修改MaxIterms默认值为10）,设置MaxIterms=5
	@Test
	public void test_listPolicies_setMarker()throws Exception{	
		IAMTestUtils.TrancateTable("iam-accountSummary-huxl");
		String policyName="listPolicies";
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		createPolicy(policyName);
		String groupName="attachGroupPolicy";
		createGroup(groupName);
		String userName="attachUserPolicy";
		createUser(userName);
		//创建8个策略，加到同一个组attachGroupPolicy中
		for(int i=0;i<8;i++){
			createPolicy(policyName+i);
			attachPolicyToGroup(groupName,policyArn+i);
		}
		//创建3个组，每个组中加入策略listPolicies
		for(int i=0;i<3;i++){
			createGroup(groupName+i);
			attachPolicyToGroup(groupName+i,policyArn);
		}
		//创建3个用户，每个用户中加入策略listPolicies
		for(int i=0;i<3;i++){
			createUser(userName+i);
			attachPolicyToUser(userName+i,policyArn);
		}
		//将listPolicies1附加到用户attachUserPolicy和组attachGroupPolicy中
		attachPolicyToUser(userName,policyArn+1);
		attachPolicyToGroup(groupName,policyArn+1);
		
		//策略未添加到任何组和用户中
		createPolicy("listPolicies9");
		createPolicy("listPolicies10");
		
		//获取策略
		String body = "Action=ListPolicies&Version=2010-05-08&Marker="+accountId+"|listPolicies5";
		Pair<Integer,String> resultatt=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,resultatt.first().intValue());
		System.out.println(resultatt.second());
	}
	
	//ListPolicies:策略添加到用户和组中，策略未加到任何组合用户中（为测试方便，修改MaxIterms默认值为10）,设置OnlyAttached=true,只列出添加到用户/组的策略
	@Test
	public void test_listPolicies_setOnlyAttached()throws Exception{	
		IAMTestUtils.TrancateTable("iam-accountSummary-huxl");
		String policyName="listPolicies";
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		createPolicy(policyName);
		String groupName="attachGroupPolicy";
		createGroup(groupName);
		String userName="attachUserPolicy";
		createUser(userName);
		//创建8个策略，加到同一个组attachGroupPolicy中
		for(int i=0;i<8;i++){
			createPolicy(policyName+i);
			attachPolicyToGroup(groupName,policyArn+i);
		}
		//创建3个组，每个组中加入策略listPolicies
		for(int i=0;i<3;i++){
			createGroup(groupName+i);
			attachPolicyToGroup(groupName+i,policyArn);
		}
		//创建3个用户，每个用户中加入策略listPolicies
		for(int i=0;i<3;i++){
			createUser(userName+i);
			attachPolicyToUser(userName+i,policyArn);
		}
		//将listPolicies1附加到用户attachUserPolicy和组attachGroupPolicy中
		attachPolicyToUser(userName,policyArn+1);
		attachPolicyToGroup(groupName,policyArn+1);
		
		//策略未添加到任何组和用户中
		createPolicy("listPolicies9");
		createPolicy("listPolicies10");
		
		//获取策略，OnlyAttached为true
		String body = "Action=ListPolicies&Version=2010-05-08&OnlyAttached=true";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());

		//获取策略,OnlyAttached为false,所有策略
		String bodyall = "Action=ListPolicies&Version=2010-05-08&OnlyAttached=false";
		Pair<Integer,String> resultall=IAMTestUtils.invokeHttpsRequest(bodyall, accessKey, secretKey);
		assertEquals(200,resultall.first().intValue());
		System.out.println(resultall.second());		
		
	}
	
	//ListPolicies:创建oos和iam的不同托管策略，类型为OOS和Local，All
//	@Test(本期无OOS系统策略)
	public void test_listPolicies_setScope()throws Exception{		
		//创建Scope类型为OOS的策略（目前需要修改代码进行创建）
		String policyName="createOOSPolicyfortestlistPolicies";
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"oos:*\",\"Resource\":\"Arn:aws:oos:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"oos:Get*\",\"oos:List*\"],\"Resource\":[\"Arn:aws:oos:::EXAMPLE-BUCKET\",\"Arn:aws:oos:::EXAMPLE-BUCKET/*\"]}]}";
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName="+ URLEncoder.encode(policyName) +"&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=test_des";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		
		//附加策略到group上
		createGroup("creategroupfortestscope");
		attachPolicyToGroup("creategroupfortestscope","arn:ctyun:iam::OOS:policy/"+policyName);
		
		//获取策略,scope类型为OOS
		String bodylist = "Action=ListPolicies&Version=2010-05-08&Scope=OOS";
		Pair<Integer,String> resultlist=IAMTestUtils.invokeHttpsRequest(bodylist, accessKey, secretKey);
		assertEquals(200,resultlist.first().intValue());
		System.out.println(resultlist.second());
		
		//获取策略,scope类型为Local
		String bodylist2 = "Action=ListPolicies&Version=2010-05-08&Scope=Local";
		Pair<Integer,String> resultlist2=IAMTestUtils.invokeHttpsRequest(bodylist2, accessKey, secretKey);
		assertEquals(200,resultlist2.first().intValue());
		System.out.println(resultlist2.second());
		
		//获取策略,scope类型为All
		String bodylist3 = "Action=ListPolicies&Version=2010-05-08&MaxItems=30&Scope=All";
		Pair<Integer,String> resultlist3=IAMTestUtils.invokeHttpsRequest(bodylist3, accessKey, secretKey);
		assertEquals(200,resultlist3.first().intValue());
		System.out.println(resultlist3.second());		
	}	
	
	//ListPolicies:无效的PolicyName
	@Test
	public void test_listPolicies_invalidPolicyName()throws Exception{
		//获取策略
		String body = "Action=ListPolicies&Version=2010-05-08&PolicyName=";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'policyName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",error.get("Message"));		
						
	}
	//ListPolicies:不存在PolicyName,没有符合查询条件的Policies
//	@Test
	public void test_listPolicies_PolicyNotExist()throws Exception{
		//获取策略
		String body = "Action=ListPolicies&Version=2010-05-08&PolicyName=policyNotExist";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
						
	}
	
	//ListPolicies：无效的OnlyAttached
//	@Test
	public void test_listPolicies_invalidOnlyAttached() throws Exception{
		//获取策略
		String body = "Action=ListPolicies&Version=2010-05-08&OnlyAttached=boolean";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("MalformedInput",error.get("Code"));
		assertEquals("Invalid Argument.",error.get("Message"));		
					
	}
	
	//ListPolicies:无效的scope，因本期没有OOS类型，去除请求中的scope参数
//	@Ignore
	public void test_listPolicies_invalidscope() throws Exception{
		String body = "Action=ListPolicies&Version=2010-05-08&Scope=local";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject  error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value 'local' at 'scope' failed to satisfy constraint: Member must satisfy enum value set: [All, Local, OOS].",error.get("Message"));		
							
	}
	
	//ListPolicies：策略为其他账户创建
	@Test
	public void test_listPolicies_otheraccount()throws Exception{
		String policyName="createforotherslistpolicies";
		createPolicy(policyName);
		String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
		
		//获取策略
		String body = "Action=ListPolicies&Version=2010-05-08" ;
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKeyother, secretKeyother);
		System.out.println(result.second());
		assertEquals(200,result.first().intValue());
		
	}		
	

	//创建policy
	public void createPolicy(String policyName) {
		String policyDocument=publicpolicyDocument;
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName="+ URLEncoder.encode(policyName) +"&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=test_des";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
	}
	//创建user
	public void createUser(String userName) throws Exception {
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName+"&Tags.member.1.Key=test_key&Tags.member.1.Value=test_value";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
	}
	//创建group
	public void createGroup(String groupName)throws Exception{
		String body="Action=CreateGroup&Version=2010-05-08&GroupName="+groupName;
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
	}
	
	//添加策略到组
	public void attachPolicyToGroup(String groupName,String policyArn){
		String bodyAttach="Action=AttachGroupPolicy&Version=2010-05-08&GroupName="+ groupName +"&PolicyArn="+URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
	}
	//添加策略到用户
	public void attachPolicyToUser(String userName,String policyArn){
		String bodyAttach="Action=AttachUserPolicy&Version=2010-05-08&UserName="+ userName +"&PolicyArn="+URLEncoder.encode(policyArn);
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
	}
	
	
	public static JSONObject ParseXmlToJson(String xml, String actions) {
		
		try {
		
			StringReader sr = new StringReader(xml);
	        InputSource is = new InputSource(sr);
	        Document doc = (new SAXBuilder()).build(is);
	        Element root = null ;
	        JSONObject jObject= new JSONObject();
	        if(actions.equals("CreatePolicy"))
	        	root = doc.getRootElement().getChild("CreatePolicyResult").getChild("Policy");
	        if(actions.equals("GetPolicy"))
	        	root = doc.getRootElement().getChild("GetPolicyResult").getChild("Policy");		        		        
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
	
	public static JSONObject ParseXmlToJson2(String xml, String actions) {
		
		try {
		
			StringReader sr = new StringReader(xml);
	        InputSource is = new InputSource(sr);
	        Document doc = (new SAXBuilder()).build(is);
	        Element root = null ;
	        JSONObject jObject= new JSONObject();
	        
	        if(actions.equals("ListPolicies")){
	        	root = doc.getRootElement().getChild("ListPoliciesResult");
	        	String values = root.getChild("IsTruncated").getValue();
	        	jObject.put("IsTruncated", values);
	        	if(values.equals("true")){
	        		String value2 = root.getChild("Marker").getValue();
		        	jObject.put("Marker", value2);
	        	}
	        	
	        }
	        	
	        if(actions.equals("ListEntitiesForPolicy")){
	        	root = doc.getRootElement().getChild("ListEntitiesForPolicyResult");
	        	String values = root.getChild("IsTruncated").getValue();
	        	jObject.put("IsTruncated", values);
	        	if(values.equals("true")){
	        		String value2 = root.getChild("Marker").getValue();
		        	jObject.put("Marker", value2);
	        	}
	        	
	       }
	        
	       if(actions.equals("ListAttachedGroupPolicies")){
	        	root = doc.getRootElement().getChild("ListAttachedGroupPoliciesResult");
	        	String values = root.getChild("IsTruncated").getValue();
	        	jObject.put("IsTruncated", values);
	        	if(values.equals("true")){
	        		String value2 = root.getChild("Marker").getValue();
		        	jObject.put("Marker", value2);
	        	}
	        	
	       }
	       if(actions.equals("ListAttachedUserPolicies")){
	        	root = doc.getRootElement().getChild("ListAttachedUserPoliciesResult");
	        	String values = root.getChild("IsTruncated").getValue();
	        	jObject.put("IsTruncated", values);
	        	if(values.equals("true")){
	        		String value2 = root.getChild("Marker").getValue();
		        	jObject.put("Marker", value2);
	        	}
	        	
	       } 
	        		        		        
	        List<Element> result=root.getChildren();
	        System.out.println(result);
	        Iterator<Element> iterator=result.iterator();
	        
	        while(iterator.hasNext()){
	        	Element root2 = iterator.next();
	        	System.out.println(root2.getName());
	        	
	        	if(root2.getName().equals("Policies")){
	        		List<Element> groups=root2.getChildren("member");
	        		if(groups != null){
	        			Iterator<Element> groupsterator=groups.iterator();
	            		JSONObject jObject2= new JSONObject();
	            		int i=1;
	            		while(groupsterator.hasNext()){
	            			Element root3 = groupsterator.next();
	            			JSONObject jObject3= new JSONObject();
	        	        	Element PolicyName=root3.getChild("PolicyName");
	        	        	Element Arn=root3.getChild("Arn");
	        	        	Element PolicyId=root3.getChild("PolicyId");
	        	        	Element IsAttachable=root3.getChild("IsAttachable");
	        	        	Element CreateDate=root3.getChild("CreateDate");
	        	        	Element UpdateDate=root3.getChild("UpdateDate");
	        	        	Element AttachmentCount=root3.getChild("AttachmentCount");
	        	        	Element Scope=root3.getChild("Scope");
	        	        	Element Description=root3.getChild("Description");
	        	        	jObject3.put(PolicyName.getName(), PolicyName.getValue());
	        	        	jObject3.put(Arn.getName(), Arn.getValue());
	        	        	jObject3.put(PolicyId.getName(), PolicyId.getValue());
	        	        	jObject3.put(IsAttachable.getName(), IsAttachable.getValue());
	        	        	jObject3.put(CreateDate.getName(), CreateDate.getValue());
	        	        	jObject3.put(UpdateDate.getName(), UpdateDate.getValue());
	        	        	jObject3.put(AttachmentCount.getName(), AttachmentCount.getValue());
	        	        	jObject3.put(Scope.getName(), Scope.getValue());
	        	        	jObject3.put(Description.getName(), Description.getValue());
	        	        	
	        	        	jObject2.put("member"+i, jObject3);
	        	        	i++;
	    	        	}
	            		jObject.put("Policies", jObject2);
	        		}
	        	}
	        	
	        	if(root2.getName().equals("PolicyUsers")){
	        		List<Element> users=root2.getChildren("member");
	        		if(users != null){
	        			Iterator<Element> usersiterator=users.iterator();
	            		JSONObject jObject2= new JSONObject();
	            		int i=1;
	            		while(usersiterator.hasNext()){	            			
	        	        	Element root3 = usersiterator.next();
	        	        	System.out.println("root3:"+root3.getName());
	        	        	JSONObject jObject3= new JSONObject();
	        	        	Element userName=root3.getChild("UserName");
	        	        	Element UserId=root3.getChild("UserId");	        	        	
	        	        	jObject3.put(userName.getName(), userName.getValue());	        	        	
	        	        	jObject3.put(UserId.getName(), UserId.getValue());
	        	        	jObject2.put("member"+i, jObject3);	        	        	
	        	        	i++;	        	        	
	            		}
	            		jObject.put("PolicyUsers", jObject2);	
	        		}	        		
	        	}
	        	
	        	if(root2.getName().equals("PolicyGroups")){
	        		List<Element> users=root2.getChildren("member");
	        		if(users != null){
	        			Iterator<Element> usersiterator=users.iterator();
	            		JSONObject jObject2= new JSONObject();
	            		int i=1;
	            		while(usersiterator.hasNext()){	            			
	        	        	Element root3 = usersiterator.next();
	        	        	System.out.println("root3:"+root3.getName());
	        	        	JSONObject jObject3= new JSONObject();
	        	        	Element userName=root3.getChild("GroupName");
	        	        	Element UserId=root3.getChild("GroupId");	        	        	
	        	        	jObject3.put(userName.getName(), userName.getValue());	        	        	
	        	        	jObject3.put(UserId.getName(), UserId.getValue());
	        	        	jObject2.put("member"+i, jObject3);	        	        	
	        	        	i++;	        	        	
	            		}
	            		jObject.put("PolicyGroups", jObject2);	
	        		}	        		
	        	}
	        	if(root2.getName().equals("AttachedPolicies")){
	        		List<Element> users=root2.getChildren("member");
	        		if(users != null){
	        			Iterator<Element> usersiterator=users.iterator();
	            		JSONObject jObject2= new JSONObject();
	            		int i=1;
	            		while(usersiterator.hasNext()){	            			
	        	        	Element root3 = usersiterator.next();
	        	        	System.out.println("root3:"+root3.getName());
	        	        	JSONObject jObject3= new JSONObject();
	        	        	Element PolicyName=root3.getChild("PolicyName");
	        	        	Element PolicyArn=root3.getChild("PolicyArn");	
	        	        	Element Scope=root3.getChild("Scope");
	        	        	Element Description=root3.getChild("Description");
	        	        	jObject3.put(PolicyName.getName(), PolicyName.getValue());	        	        	
	        	        	jObject3.put(PolicyArn.getName(), PolicyArn.getValue());
	        	        	jObject3.put(Scope.getName(), Scope.getValue());	        	        	
	        	        	jObject3.put(Description.getName(), Description.getValue());
	        	        	jObject2.put("member"+i, jObject3);	        	        	
	        	        	i++;	        	        	
	            		}
	            		jObject.put("AttachedPolicies", jObject2);	
	        		}	        		
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
