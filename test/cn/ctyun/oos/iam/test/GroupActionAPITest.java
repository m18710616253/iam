package cn.ctyun.oos.iam.test;

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.io.IOUtils;
import org.apache.hadoop.hbase.TableName;
import org.apache.hadoop.hbase.client.HBaseAdmin;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.xml.sax.InputSource;

import cn.ctyun.common.conf.GlobalHHZConfig;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.Condition;
import cn.ctyun.oos.iam.server.internal.api.IAMInternalAPI;
import cn.ctyun.oos.iam.server.internal.api.LoginParam;
import cn.ctyun.oos.iam.server.internal.api.LoginResult;
import cn.ctyun.oos.iam.signer.Misc;
import cn.ctyun.oos.iam.test.iamaccesscontrol.IAMInterfaceTestUtils;
import common.tuple.Pair;


/****
 * 本版本，去除path参数
 * ****/
public class GroupActionAPITest {

	public static final String OOS_IAM_DOMAIN="https://oos-cd-iam.ctyunapi.cn:9460/";
	public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
	public static final String regionName="cd";
	
	public static final String accessKey="userak1";
	public static final String secretKey="usersk1";
	
	public static String iamGroupTable="iam-group-yx";
	public static String iamUserTable="iam-user-yx";
	public static String iamAccountSummaryTable="iam-accountSummary-yx";
	
	public static String arnPrefix = "arn:ctyun:iam::";
	public static String accountId = "3fdmxmc3pqvmp";
	
	
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
	}

	@Before
	public void setUp() throws Exception {
		cleanTable(iamGroupTable);
		cleanTable(iamUserTable);
		cleanTable(iamAccountSummaryTable);
	}

	//创建组，action，version，GroupName正确
	@Test
	public void test_createGroup() throws Exception {

		URL url = new URL(OOS_IAM_DOMAIN);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        
        String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                url, "POST", "sts", regionName);
        headers.put("Authorization", authorization);
        String groupname = "Testcreategroup";
        String body="Action=CreateGroup&Version=2010-05-08&GroupName="+URLEncoder.encode(groupname);
        
        HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
        OutputStream out = connection.getOutputStream();
        out.write(body.getBytes());
        out.flush();
        int code = connection.getResponseCode();
        assertEquals(200, code);
        String xml = IOUtils.toString(connection.getInputStream());
        JSONObject response= new JSONObject();
        response = ParseXmlToJson1(xml, "CreateGroup");
        System.out.print(response);
        assertEquals(groupname,response.get("GroupName"));
        assertEquals(arnPrefix + accountId + ":group/" +groupname, response.get("Arn"));
        assertNotNull(response.get("CreateDate"));
        assertNotNull(response.get("GroupId"));        
        out.close();        
        if (connection != null) {
            connection.disconnect();
        }	
	}

	//Action，Version正确，GroupName为必填项，不输入GroupName时400异常
	@Test
	public void test_createGroup_requiredGroupName() throws Exception {

		URL url = new URL(OOS_IAM_DOMAIN);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        
        String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                url, "POST", "sts", regionName);
        headers.put("Authorization", authorization);
        
        String body="Action=CreateGroup&Version=2010-05-08&";
        
        HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
        OutputStream out = connection.getOutputStream();
        out.write(body.getBytes());
        out.flush();
        int code = connection.getResponseCode();
        assertEquals(400, code);
        String xml = IOUtils.toString(connection.getErrorStream());
        System.out.print(xml);
        JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'groupName' failed to satisfy constraint: Member must not be null",error.get("Message"));
	
        out.close();        
        if (connection != null) {
            connection.disconnect();
        }	
	}
	//Groupname唯一性校验，groupName与已存在的groupName重复，409异常
	@Test
	public void test_createGroup_uniqGroupName() throws Exception {
		String groupName="GroupName01";
		createGroup(groupName);
		URL url = new URL(OOS_IAM_DOMAIN);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        
        String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                url, "POST", "sts", regionName);
        headers.put("Authorization", authorization);
        
        String body="Action=CreateGroup&Version=2010-05-08&GroupName=" + groupName;
        
        HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
        OutputStream out = connection.getOutputStream();
        out.write(body.getBytes());
        out.flush();
        int code = connection.getResponseCode();
        assertEquals(409, code);
        String xml = IOUtils.toString(connection.getErrorStream());
        System.out.print(xml);
        JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
        assertEquals("EntityAlreadyExists",error.get("Code"));
        assertEquals("Group with name "+groupName+" already exists.",error.get("Message"));
        out.close();        
        if (connection != null) {
            connection.disconnect();
        }	
	}
	//GroupName唯一性校验--GroupName不区分大小写，409异常
	@Test
	public void test_createGroup_uniqGroupName2() throws Exception {
		String groupName="GROUPNAME01";
		createGroup(groupName);
		
		URL url = new URL(OOS_IAM_DOMAIN);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                url, "POST", "sts", regionName);
        headers.put("Authorization", authorization);
        String body="Action=CreateGroup&Version=2010-05-08&GroupName="+groupName.toLowerCase();
        HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
        OutputStream out = connection.getOutputStream();
        out.write(body.getBytes());
        out.flush();
        int code = connection.getResponseCode();
        assertEquals(409, code);
        String xml = IOUtils.toString(connection.getErrorStream());
        System.out.print(xml);
        JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
        assertEquals("EntityAlreadyExists",error.get("Code"));
        assertEquals("Group with name "+groupName.toLowerCase()+" already exists.",error.get("Message"));
        out.close();        
        if (connection != null) {
            connection.disconnect();
        }	
	}
	
	//Groupname规则校验,只有大写字母
	@Test
	public void test_createGroup_validgroupName_upper() throws Exception {

		URL url = new URL(OOS_IAM_DOMAIN);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        
        String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                url, "POST", "sts", regionName);
        headers.put("Authorization", authorization);
        //GroupName只有大写
        String groupname="GROUPTESTD";
        String body="Action=CreateGroup&Version=2010-05-08&GroupName="+URLEncoder.encode(groupname);
        
        HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
        OutputStream out = connection.getOutputStream();
        out.write(body.getBytes());
        out.flush();
        int code = connection.getResponseCode();
        assertEquals(200, code);
        InputStream in=connection.getInputStream();
        String xml = IOUtils.toString(in);
        JSONObject response= new JSONObject();
        response = ParseXmlToJson1(xml, "CreateGroup");
        System.out.print(response);
        assertEquals(groupname,response.get("GroupName"));
        assertEquals(arnPrefix + accountId + ":group/" +groupname, response.get("Arn"));
        assertNotNull(response.get("CreateDate"));
        assertNotNull(response.get("GroupId")); 
        out.close();
       
        if (connection != null) {
            connection.disconnect();
        }	
	}
	
	//GroupName合法性校验，只有小写字母
	@Test
	public void test_createGroup_validgroupName_lower() throws Exception {

		URL url = new URL(OOS_IAM_DOMAIN);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        
        String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                url, "POST", "sts", regionName);
        headers.put("Authorization", authorization);
        //GroupName只有小写字母
        String groupname = "testesta";
        String body="Action=CreateGroup&Version=2010-05-08&GroupName=" + URLEncoder.encode(groupname);
        
        HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
        OutputStream out = connection.getOutputStream();
        out.write(body.getBytes());
        out.flush();
        int code = connection.getResponseCode();
        assertEquals(200, code);
        InputStream in=connection.getInputStream();
        String xml = IOUtils.toString(in);
        JSONObject response= new JSONObject();
        response = ParseXmlToJson1(xml, "CreateGroup");
        System.out.print(response);
        assertEquals(groupname,response.get("GroupName"));
        assertEquals(arnPrefix + accountId + ":group/" +groupname, response.get("Arn"));
        assertNotNull(response.get("CreateDate"));
        assertNotNull(response.get("GroupId")); 
        out.close();
        
        if (connection != null) {
            connection.disconnect();
        }	
	}
	
	//GroupName合法性校验，只有数字
	@Test
	public void test_createGroup_validgroupName_number() throws Exception {

		URL url = new URL(OOS_IAM_DOMAIN);
	    Map<String, String> headers = new HashMap<String, String>();
	    headers.put("Content-Type", "application/x-www-form-urlencoded");
	        
	    String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
	                url, "POST", "sts", regionName);
	    headers.put("Authorization", authorization);
	    //GroupName只有数字
	    String groupname = "111111";
	    String body="Action=CreateGroup&Version=2010-05-08&GroupName="+URLEncoder.encode(groupname);
	    
	    HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
	    OutputStream out = connection.getOutputStream();
	    out.write(body.getBytes());
	    out.flush();
	    int code = connection.getResponseCode();
	    assertEquals(200, code);
	    InputStream in=connection.getInputStream();
	    String xml = IOUtils.toString(in);
	    JSONObject response= new JSONObject();
        response = ParseXmlToJson1(xml, "CreateGroup");
        System.out.print(response);
        assertEquals(groupname,response.get("GroupName"));
        assertEquals(arnPrefix + accountId + ":group/" +groupname, response.get("Arn"));
        assertNotNull(response.get("CreateDate"));
        assertNotNull(response.get("GroupId")); 
	    out.close();
	        
	    if (connection != null) {
	         connection.disconnect();
	    }	
	}
	//GroupName为大小写字母数字合法特殊字符组成,注意：特殊字符需要做encode
	@Test
	public void test_createGroup_validgroupName() throws Exception {

		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
		        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
		                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		//groupName为大小写/数字/特殊字符的组合，TEst++=,.@-001
		String groupname = "TEst++=,.@-001";
		String body="Action=CreateGroup&Version=2010-05-08&GroupName="+URLEncoder.encode(groupname);
		        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(200, code); 
		String xml = IOUtils.toString(connection.getInputStream());
		JSONObject response= new JSONObject();
        response = ParseXmlToJson1(xml, "CreateGroup");
        System.out.print(response);
        assertEquals(groupname,response.get("GroupName"));
        assertEquals(arnPrefix + accountId + ":group/" +groupname, response.get("Arn"));
        assertNotNull(response.get("CreateDate"));
        assertNotNull(response.get("GroupId")); 
		out.close();
		        
		if (connection != null) {
		     connection.disconnect();
		}	
	}
	//GroupName合法性校验，只有合法的特殊字符
	@Test
	public void test_createGroup_validgroupName_specialChara() throws Exception {

		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
		        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
		                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);

		//GroupName只有合法特殊字符_ + =，.@ -
		String groupname="_+=,.@-";
		String body="Action=CreateGroup&Version=2010-05-08&GroupName="+URLEncoder.encode(groupname);
		        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(200, code); 
		String xml = IOUtils.toString(connection.getInputStream());
		JSONObject response= new JSONObject();
        response = ParseXmlToJson1(xml, "CreateGroup");
        System.out.print(response);
        assertEquals(groupname,response.get("GroupName"));
        assertEquals(arnPrefix + accountId + ":group/" +groupname, response.get("Arn"));
        assertNotNull(response.get("CreateDate"));
        assertNotNull(response.get("GroupId")); 
		out.close();
		        
		if (connection != null) {
		     connection.disconnect();
		}	
	}

	//GroupName合法性校验，GroupName不能为路径
	@Test
	public void test_createGroup_invalidgroupName1() throws Exception {
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
		        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
		                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		//groupName为路径
		String body="Action=CreateGroup&Version=2010-05-08&GroupName=%2ftestpath%2f";
		        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'groupName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",error.get("Message"));
	
		out.close();
		        
		if (connection != null) {
		     connection.disconnect();
		}	
	}

	//GroupName合法性校验，GroupName不能含其他非法字符例如*&,例如：testa&b.*+
	@Test
	public void test_createGroup_invalidgroupName2() throws Exception {
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
			        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);		
		String body="Action=CreateGroup&Version=2010-05-08&GroupName="+URLEncoder.encode("testa&b.*+");
//		String body="Action=CreateGroup&Version=2010-05-08&GroupName=testab.*";
		
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'groupName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",error.get("Message"));
	
		out.close();
			        
		if (connection != null) {
			  connection.disconnect();
		}	
	}

	//GroupName合法性校验，GroupName为空
	@Test
	public void test_createGroup_invalidgroupName4() throws Exception {

		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
			        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
		                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String body="Action=CreateGroup&Version=2010-05-08&GroupName=";
		System.out.println(body);
			        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'groupName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",error.get("Message"));
	
		out.close();
			        
		if (connection != null) {
			 connection.disconnect();
		}	
	}	
	
	//GroupName合法性校验，GroupName长度限制再128之内，长度为128，合法
		@Test
		public void test_createGroup_groupName_validlength() throws Exception {
			URL url = new URL(OOS_IAM_DOMAIN);
			Map<String, String> headers = new HashMap<String, String>();
			headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
			String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
			headers.put("Authorization", authorization);
			//groupName长度为128
			StringBuilder sb=new StringBuilder();
			
			for(int i=0;i<128;i++)
				sb.append("a");
			String groupname = sb.toString();
			String body="Action=CreateGroup&Version=2010-05-08&GroupName="+URLEncoder.encode(groupname);
				        
			HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
			OutputStream out = connection.getOutputStream();
			out.write(body.getBytes());
			out.flush();
			int code = connection.getResponseCode();
			assertEquals(200, code); 
			String xml = IOUtils.toString(connection.getInputStream());
			JSONObject response= new JSONObject();
	        response = ParseXmlToJson1(xml, "CreateGroup");
	        System.out.print(response);
	        assertEquals(groupname,response.get("GroupName"));
	        assertEquals(arnPrefix + accountId + ":group/" +groupname, response.get("Arn"));
	        assertNotNull(response.get("CreateDate"));
	        assertNotNull(response.get("GroupId")); 
			out.close();
				        
			if (connection != null) {
				 connection.disconnect();
			}	
		}	
	
	//GroupName合法性校验，GroupName长度限制再128之内，设置GroupName长度为129,400异常
	@Test
	public void test_createGroup_groupName_invalidlength() throws Exception {

		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
			        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
		                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		//groupName长度为129
		StringBuilder sb=new StringBuilder();
		
		for(int i=0;i<129;i++)
			sb.append("a");

		String body="Action=CreateGroup&Version=2010-05-08&GroupName="+sb.toString();
			        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value '"+sb.toString()+"' at 'groupName' failed to satisfy constraint: Member must have length less than or equal to 128",error.get("Message"));
	
		out.close();
			        
		if (connection != null) {
			 connection.disconnect();
		}	
	}
	
	//创建group，Action错误
	@Test
	public void test_createGroup_invalidAction() throws Exception {
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
			        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
		                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		//Action错误
		String body="Action=creategroup&Version=2010-05-08&GroupName=TESTGROUPAction";
			        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("InvalidAction",error.get("Code"));
		assertEquals("Could not find operation creategroup for version 2010-05-08.",error.get("Message"));
	
		out.close();
			        
		if (connection != null) {
			 connection.disconnect();
		}	
	}	
	
	//创建group，Action为空
	@Test
	public void test_createGroup_Actionmissing() throws Exception {

		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		//Action错误
		String body="Action=&Version=2010-05-08&GroupName=TESTGROUPAction";
				        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("InvalidAction",error.get("Code"));
		assertEquals("Could not find operation  for version 2010-05-08.",error.get("Message"));
	
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}	
	}
	//创建group，Action缺失
	@Test
	public void test_createGroup_Actionmissing2() throws Exception {

		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		//Action错误
		String body="Version=2010-05-08&GroupName=TESTGROUPAction";
				        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("MissingAction",error.get("Code"));
		assertEquals("Missing Action",error.get("Message"));
	
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}	
	}
	
	//创建group，Version错误
	//测试未通过，创建成功了，未校验Version
	@Test
	public void test_createGroup_invalidVersion() throws Exception {
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
			        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
		                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		//Version错误
		String body="Action=CreateGroup&Version=2010-07-30&GroupName=TESTGROUPVersion";
			        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("InvalidAction",error.get("Code"));
		assertEquals("Could not find operation CreateGroup for version 2010-07-30.",error.get("Message"));
	
		out.close();
			        
		if (connection != null) {
			 connection.disconnect();
		}	
	}	
	
	//创建group，Verison为空，
	//fail，测试未通过
	@Test
	public void test_createGroup_Versionmissing() throws Exception {

		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		//Action错误
		String body="Action=CreateGroup&Version=&GroupName=TESTGROUPVersion";
				        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("InvalidAction",error.get("Code"));
		assertEquals("Could not find operation CreateGroup for version .",error.get("Message"));
	
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}	
	}
	//创建group，Version缺失时，不做任何校验，无默认值
	@Test
	public void test_createGroup_Versionmissing2() throws Exception {

		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		//Action错误
		String body="Action=CreateGroup&GroupName=TESTGROUPVersion";
				        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(200, code); 
		String xml = IOUtils.toString(connection.getInputStream());
		System.out.println(xml);
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}	
	}
	
	//一个用户最多创建300个组，超出300，为侧式方便，将groupsQuota修改为30
	@Test
	public void test_createGroup_limitGroups() throws Exception {

		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String GroupName="TestGroupLimit";
		for(int i=0;i<30;i++){
			String body="Action=CreateGroup&Version=2010-05-08&GroupName="+GroupName+i;       
			HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
			OutputStream out = connection.getOutputStream();
			out.write(body.getBytes());
			out.flush();
			int code = connection.getResponseCode();
			assertEquals(200, code); 
			String xml = IOUtils.toString(connection.getInputStream());
			System.out.println(xml);
			out.close();
					        
			if (connection != null) {
				connection.disconnect();
			}	
		}
		String body="Action=CreateGroup&Version=2010-05-08&GroupName=TestGroupLimit300";
        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(409, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("LimitExceeded",error.get("Code"));
		assertEquals("Cannot exceed quota for GroupsPerAccount: 30.",error.get("Message"));
	
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}	
	}
	
	//删除已存在的group
	@Test
	public void test_deleteGroup() throws Exception {
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		//创建group用于删除
		String body="Action=CreateGroup&Version=2010-05-08&GroupName=TESTDeleteGROUP";
				        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(200, code); 
		String xml = IOUtils.toString(connection.getInputStream());
		System.out.println(xml);
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}
		
		//删除group
		String bodydelete="Action=DeleteGroup&Version=2010-05-08&GroupName=TESTDeleteGROUP";
						        
		HttpsURLConnection connection1 = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out1 = connection1.getOutputStream();
		out1.write(bodydelete.getBytes());
		out1.flush();
		int code1 = connection1.getResponseCode();
		assertEquals(200, code1); 
		String xml1 = IOUtils.toString(connection1.getInputStream());
		System.out.println(xml1);
		out1.close();
						        
		if (connection1 != null) {
			connection1.disconnect();
		}	
	}
	
	//deleteGroup:groupName合法长度为1-128，长度为129
	@Test
	public void test_deleteGroup_groupName_invalidlength() throws Exception{
		StringBuilder sb=new StringBuilder();
		for(int i=0;i<129;i++)
			sb.append("a");
		String body="Action=DeleteGroup&Version=2010-05-08&GroupName="+URLEncoder.encode(sb.toString());
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value '"+sb.toString()+"' at 'groupName' failed to satisfy constraint: Member must have length less than or equal to 128",error.get("Message"));
	
	}
	//deleteGroup：group为空,400异常
	@Test
	public void test_deleteGroup_invalidgroupName() throws Exception{
		String body="Action=DeleteGroup&Version=2010-05-08&GroupName=";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400,result.first().intValue());
		System.out.println(result.second());
		JSONObject error=IAMTestUtils.ParseErrorToJson(result.second());
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'groupName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",error.get("Message"));
	
	}
	
	//删除不存在的group
	@Test
	public void test_deleteGroupNotExist() throws Exception {
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		//创建group用于删除
		String body="Action=DeleteGroup&Version=2010-05-08&GroupName=TESTDeleteGroupNotExist";
				        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(404, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("NoSuchEntity",error.get("Code"));
		assertEquals("The group with name TESTDeleteGroupNotExist cannot be found.",error.get("Message"));
	
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}
	}
	
	//删除存在的group时，group内有用户
	@Test
	public void test_deleteGroupExistUser() throws Exception {
		//创建用户和user，将user添加到group
		String groupName="groupfordeletegroup";
		String userName="userfordeletegroup";
		createGroup(groupName);
		createUser(userName);
		
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");		        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization); 
		String body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+groupName+"&UserName="+userName; 	        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(200, code); 
		String xml = IOUtils.toString(connection.getInputStream());
		System.out.println(xml);
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}
		
		//删除group
		String bodydelete="Action=DeleteGroup&Version=2010-05-08&GroupName="+groupName;
						        
		HttpsURLConnection connection1 = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out1 = connection1.getOutputStream();
		out1.write(bodydelete.getBytes());
		out1.flush();
		int code1 = connection1.getResponseCode();
		assertEquals(409, code1); 
		String xml1 = IOUtils.toString(connection1.getErrorStream());
		System.out.println(xml1);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml1);
		assertEquals("DeleteConflict",error.get("Code"));
		assertEquals("Cannot delete entity, must remove users from group first.",error.get("Message"));
	
		out1.close();
						        
		if (connection1 != null) {
			connection1.disconnect();
		}
	}
	
	//删除组--组中已添加策略,删除组时必须移除策略，否则409
	@Test
	public void test_deleteGroupExistPolicy() throws Exception{
		//创建group和策略，并将策略添加到组
		String groupName="groupfordeletegroupP";
		createGroup(groupName);
		
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");		        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName=test_policy&PolicyDocument=%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22s3%3AListAllMyBuckets%22%2C%22Resource%22%3A%22Arn%3Aaws%3As3%3A%3A%3A*%22%7D%2C%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%5B%22s3%3AGet*%22%2C%22s3%3AList*%22%5D%2C%22Resource%22%3A%5B%22Arn%3Aaws%3As3%3A%3A%3AEXAMPLE-BUCKET%22%2C%22Arn%3Aaws%3As3%3A%3A%3AEXAMPLE-BUCKET%2F*%22%5D%7D%5D%7D&Description=test_des";
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(200, code); 
		String xml = IOUtils.toString(connection.getInputStream());
		System.out.println(xml);
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}
		//向组内添加策略
		String bodyAttach="Action=AttachGroupPolicy&Version=2010-05-08&GroupName="+ groupName +"&PolicyArn=arn%3Aaws%3Aiam%3A%3A"+accountId+"%3Apolicy%2Ftest_policy";
		System.out.println(bodyAttach);
		HttpsURLConnection connection1 = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out1 = connection1.getOutputStream();
		out1.write(bodyAttach.getBytes());
		out1.flush();
		int code1 = connection1.getResponseCode();
		assertEquals(200, code1); 
		String xml1 = IOUtils.toString(connection1.getInputStream());
		System.out.println(xml1);
		out1.close();
						        
		if (connection1 != null) {
			connection1.disconnect();
		}		
		
		
		//删除group
		String bodydelete="Action=DeleteGroup&Version=2010-05-08&GroupName="+groupName;
						        
		HttpsURLConnection connection2 = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out2 = connection2.getOutputStream();
		out2.write(bodydelete.getBytes());
		out2.flush();
		int code2 = connection2.getResponseCode();
		assertEquals(409, code2); 
		String xml2 = IOUtils.toString(connection2.getErrorStream());
		System.out.println(xml2);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml2);
		assertEquals("DeleteConflict",error.get("Code"));
		assertEquals("Cannot delete entity, must detach all policies first.",error.get("Message"));
	
		out2.close();
						        
		if (connection2 != null) {
			connection2.disconnect();
		}		
		
	} 
	
	//getGroup,group中存在用户(修改代码中分页默认显示100条为10条)
	@Test
	public void test_getGroup() throws Exception{
		String groupName="forgetGroup";
		createGroup(groupName);
		String userName="userforgetGroup";
		for(int i=0;i<20;i++){
			createUser(userName+i);
			addUserToGroup(groupName,userName+i);
		}
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		
		String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName;
				        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(200, code); 
		String xml = IOUtils.toString(connection.getInputStream());
		System.out.println(xml);
		JSONObject response= new JSONObject();
        response = ParseXmlToJson2(xml, "GetGroup");
        System.out.print(response);
        JSONObject group= response.getJSONObject("Group");
        JSONObject users= response.getJSONObject("Users").getJSONObject("member1");
        assertEquals(groupName,group.get("GroupName"));
        assertEquals(arnPrefix + accountId + ":group/" +groupName, group.get("Arn"));
        assertNotNull(group.get("CreateDate"));
        assertNotNull(group.get("GroupId"));
        assertEquals("true", response.get("IsTruncated"));
        assertEquals("user|"+accountId+"|forgetgroup|userforgetgroup17", response.get("Marker"));        
        assertEquals("userforgetGroup0", users.get("UserName"));
        assertEquals(arnPrefix + accountId + ":user/userforgetGroup0", users.get("Arn"));
        assertNotNull(users.get("CreateDate"));
        assertNotNull(users.get("JoinDate"));
        assertNotNull(users.get("UserId"));
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}		
	}
	/**
	 * getGroup的User信息中有PasswordLastUsed
	 * **/
	@Test
	public void test_getGroup_PasswordLastUsed() throws Exception{
		String groupName="forgetGroup";
		createGroup(groupName);
		String userName="userforgetGroup";
		createUser(userName);
		addUserToGroup(groupName,userName);
		// 用户设置密码
		String body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> setPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, setPasswd.first().intValue());
		// 用户登录
		LoginParam loginParam = new LoginParam();
		loginParam.accountId = accountId;
		loginParam.userName = userName;
		loginParam.passwordMd5 = Misc.getMd5("a12345678");
		loginParam.loginIp="192.168.1.1";
		        
		LoginResult loginResult = IAMInternalAPI.login(loginParam);

		//获取group信息
		body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName;
		Pair<Integer, String> getgroup=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, getgroup.first().intValue());		        

		String xml = getgroup.second();
		System.out.println(xml);
		JSONObject response= new JSONObject();
        response = ParseXmlToJson2(xml, "GetGroup");
        System.out.print(response);
        JSONObject group= response.getJSONObject("Group");
        JSONObject users= response.getJSONObject("Users").getJSONObject("member1");
        assertEquals(groupName,group.get("GroupName"));
        assertEquals(arnPrefix + accountId + ":group/" +groupName, group.get("Arn"));
        assertNotNull(group.get("CreateDate"));
        assertNotNull(group.get("GroupId"));
        assertEquals("false", response.get("IsTruncated"));
        
        assertEquals(userName, users.get("UserName"));
        assertEquals(arnPrefix + accountId + ":user/"+userName, users.get("Arn"));
        assertNotNull(users.get("CreateDate"));
        assertNotNull(users.get("JoinDate"));
        assertNotNull(users.get("UserId"));
        assertNotNull(users.get("PasswordLastUsed"));
        
        //删除用户密码
        body="Action=DeleteLoginProfile&UserName="+userName;
		Pair<Integer, String> deletePasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, deletePasswd.first().intValue());

	}

	//getgroup:组内不存在用户
	@Test
	public void test_getGroupnoUser() throws Exception{
		String groupName="forgetGroupnouser";
		createGroup(groupName);
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		
		String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName;
				        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(200, code); 
		String xml = IOUtils.toString(connection.getInputStream());
		System.out.println(xml);
		JSONObject response= new JSONObject();
        response = ParseXmlToJson2(xml, "GetGroup");
        System.out.print(response);
        JSONObject group= response.getJSONObject("Group");
        JSONObject users= response.getJSONObject("Users");
        assertEquals(groupName,group.get("GroupName"));
        assertEquals(arnPrefix + accountId + ":group/" +groupName, group.get("Arn"));
        assertNotNull(group.get("CreateDate"));
        assertNotNull(group.get("GroupId"));
        assertEquals("false", response.get("IsTruncated"));
        assertEquals("{}", users.toString());
        
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}		
	}	

	//getGroup：groupName不存在
	@Test
	public void test_getGroup_groupNamenotExist() throws Exception{
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		
		String body="Action=GetGroup&Version=2010-05-08&GroupName=groupNamenotExist";
				        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(404, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("NoSuchEntity",error.get("Code"));
		assertEquals("The group with name groupNamenotExist cannot be found.",error.get("Message"));
	
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}		
	}
	
	//getGroup：GroupName为必填项
	@Test
	public void test_getGroup_requiredGroupName() throws Exception{
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
					        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
				                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
			
		String body="Action=GetGroup&Version=2010-05-08&";
					        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'groupName' failed to satisfy constraint: Member must not be null",error.get("Message"));
		
		out.close();
					        
		if (connection != null) {
			connection.disconnect();
		}		
	}	
	
	//getGroup,设置marker
	@Test
	public void test_getGroup_setMarker() throws Exception{
		String groupName="forgetGroup";
		createGroup(groupName);
		String userName="userforgetgroup";
		for(int i=0;i<10;i++){
			createUser(userName+i);
			addUserToGroup(groupName,userName+i);
		}
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		
		String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName+"&Marker=user|"+accountId+"|"+groupName.toLowerCase()+"|"+userName.toLowerCase()+"5";
				        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(200, code); 
		String xml = IOUtils.toString(connection.getInputStream());
		System.out.println(xml);
		
		JSONObject response= new JSONObject();
        response = ParseXmlToJson2(xml, "GetGroup");
        System.out.print(response);
        JSONObject group= response.getJSONObject("Group");
        JSONObject users= response.getJSONObject("Users").getJSONObject("member1");
        assertEquals("false", response.get("IsTruncated"));        
        assertEquals(userName+"6", users.get("UserName"));
		
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}		
	}	

	//getGroup,设置marker，设置的maker不存在
	@Test
	public void test_getGroup_setMarker2() throws Exception{
		String groupName="forgetGroup";
		createGroup(groupName);
		String userName="userforgetGroup";
		for(int i=0;i<10;i++){
			createUser(userName+i);
			addUserToGroup(groupName,userName+i);
		}
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		
		String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName+"&Marker=user|0000000gc0uy9|forgetGroup|userforgetGroup25";
				        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(200, code); 
		String xml = IOUtils.toString(connection.getInputStream());
		System.out.println(xml);
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}		
	}	
	
	//getGroup,设置maxItems(修改代码中默认的maxItems为10)
	@Test
	public void test_getGroup_setmaxItems() throws Exception{
		String groupName="forgetGroup";
		createGroup(groupName);
		String userName="userforgetGroup";
		for(int i=0;i<10;i++){
			createUser(userName+i);
			addUserToGroup(groupName,userName+i);
		}
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		
		String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName+"&MaxItems=3";
//		String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName+"&MaxItems=20";
				        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(200, code); 
		String xml = IOUtils.toString(connection.getInputStream());
		System.out.println(xml);
		JSONObject response = ParseXmlToJson2(xml, "GetGroup");
		JSONObject group= response.getJSONObject("Group");
        JSONObject users= response.getJSONObject("Users").getJSONObject("member1");
        assertEquals(groupName,group.get("GroupName"));

        assertEquals("true", response.get("IsTruncated"));
        assertEquals("user|"+accountId+"|forgetgroup|userforgetgroup2", response.get("Marker"));        
        
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}		
	}		

	//设置maxItems为1
	@Test
	public void test_getGroup_setmaxItems1() throws Exception{
		String groupName="forgetGroup";
		createGroup(groupName);
		String userName="userforgetGroup";
		for(int i=0;i<10;i++){
			createUser(userName+i);
			addUserToGroup(groupName,userName+i);
		}
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		
		String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName+"&MaxItems=1";
				        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(200, code); 
		String xml = IOUtils.toString(connection.getInputStream());
		System.out.println(xml);
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}		
	}
	
	//设置maxItems为1000
		@Test
		public void test_getGroup_setmaxItems1000() throws Exception{
			String groupName="forgetGroup";
			createGroup(groupName);
			String userName="userforgetGroup";
			for(int i=0;i<10;i++){
				createUser(userName+i);
				addUserToGroup(groupName,userName+i);
			}
			URL url = new URL(OOS_IAM_DOMAIN);
			Map<String, String> headers = new HashMap<String, String>();
			headers.put("Content-Type", "application/x-www-form-urlencoded");
					        
			String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
				                url, "POST", "sts", regionName);
			headers.put("Authorization", authorization);
			
			String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName+"&MaxItems=1000";
					        
			HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
			OutputStream out = connection.getOutputStream();
			out.write(body.getBytes());
			out.flush();
			int code = connection.getResponseCode();
			assertEquals(200, code); 
			String xml = IOUtils.toString(connection.getInputStream());
			System.out.println(xml);
			out.close();
					        
			if (connection != null) {
				connection.disconnect();
			}		
		}
	
	//getGroup,设置maxItems,MaxIterm不在有效范围内，设置为0
	@Test
	public void test_getGroup_setInvalidmaxItems() throws Exception{
		String groupName="forgetGroup";
		createGroup(groupName);
		String userName="userforgetGroup";
		for(int i=0;i<10;i++){
			createUser(userName+i);
		}
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		
		String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName+"&MaxItems=0";
				        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value '0' at 'maxItems' failed to satisfy constraint: Member must have value greater than or equal to 1",error.get("Message"));
	
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}		
	}	

	//getGroup,设置maxItems,MaxIterm不在有效范围内，设置为1001
	@Test
	public void test_getGroup_setInvalidmaxItems2() throws Exception{
		String groupName="forgetGroup";
		createGroup(groupName);
		String userName="userforgetGroup";
		for(int i=0;i<10;i++){
			createUser(userName+i);
		}
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		
		String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName+"&MaxItems=1001";
				        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value '1001' at 'maxItems' failed to satisfy constraint: Member must have value less than or equal to 1000",error.get("Message"));
	
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}		
	}	

	//getGroup,设置maxItems,MaxIterm不在有效范围内，设置不为整数
	@Test
	public void test_getGroup_setInvalidmaxItems3() throws Exception{
		String groupName="forgetGroup";
		createGroup(groupName);
		
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		
		String body="Action=GetGroup&Version=2010-05-08&GroupName="+groupName+"&MaxItems=12.1";
				        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("MalformedInput",error.get("Code"));
		assertEquals("Invalid Argument.",error.get("Message"));
	
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}		
	}	
	
	//ListGroup:列出该用户下的组
	@Test
	public void test_ListGroups() throws Exception {

		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String groupName="TestListGroups";
		for(int i=0;i<10;i++)
			createGroup(groupName+i);
		String body="Action=ListGroups&Version=2010-05-08";
        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(200, code); 
		String xml = IOUtils.toString(connection.getInputStream());
		System.out.println(xml);
		JSONObject response= new JSONObject();
        response = ParseXmlToJson2(xml, "ListGroups");
        System.out.print(response);
        JSONObject group= response.getJSONObject("Groups").getJSONObject("member1");
        assertEquals(groupName+"0", group.get("GroupName"));
        assertEquals(arnPrefix + accountId + ":group/" +groupName+"0", group.get("Arn"));
        assertNotNull(group.get("CreateDate"));
        assertNotNull(group.get("GroupId"));
        assertEquals("0", group.get("Policies"));
        assertEquals("0", group.get("Users"));
        assertEquals("false", response.get("IsTruncated"));
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}	
	}	
	
	//该帐户下不存在组
	@Test
	public void test_ListGroups_nogroups() throws Exception {

		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String body="Action=ListGroups&Version=2010-05-08";
        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(200, code); 
		String xml = IOUtils.toString(connection.getInputStream());
		System.out.println(xml);
		JSONObject response= new JSONObject();
        response = ParseXmlToJson2(xml, "ListGroups");
        System.out.print(response);
        JSONObject group= response.getJSONObject("Groups");
        assertEquals("{}", group.toString());
        assertEquals("false", response.get("IsTruncated"));
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}	
	}	
	
	
	//ListGroup:设置groupName
	@Test
	public void test_ListGroups_setGroupName() throws Exception {

		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String groupName="TestListGroups";
		for(int i=0;i<20;i++)
			createGroup(groupName+i);
		String body="Action=ListGroups&Version=2010-05-08&GroupName=TestListGroups1";
        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(200, code); 
		String xml = IOUtils.toString(connection.getInputStream());
		System.out.println(xml);
		
		JSONObject response= new JSONObject();
        response = ParseXmlToJson2(xml, "ListGroups");
        System.out.print(response);
        JSONObject group1= response.getJSONObject("Groups").getJSONObject("member1");
        JSONObject group2= response.getJSONObject("Groups").getJSONObject("member2");
        assertEquals(groupName+"1", group1.get("GroupName"));
        assertEquals(groupName+"10", group2.get("GroupName"));
        assertEquals("false", response.get("IsTruncated"));
		
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}	
	}
	
	//ListGroup：groupName为模糊查询，输入groupName部分，可查出所有包含该参数的group
	@Test
	public void test_ListGroups_setGroupName2() throws Exception {

		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String groupName="TestListGroups";
		for(int i=0;i<20;i++)
			createGroup(groupName+i);
		String body="Action=ListGroups&Version=2010-05-08&GroupName=TestListGroups";
        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(200, code); 
		String xml = IOUtils.toString(connection.getInputStream());
		System.out.println(xml);
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}	
	}
	
	//ListGroup：groupName不合法
	@Test
	public void test_ListGroups_setGroupName_invalidName() throws Exception {

		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String body="Action=ListGroups&Version=2010-05-08&GroupName="+URLEncoder.encode("test***&&invalid");
        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'groupName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",error.get("Message"));
	
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}	
	}	
	
	//ListGroup:设置的groupName不存在
	@Test
	public void test_ListGroups_setGroupNameNotExist() throws Exception {

		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String groupName="TestListGroups";
		for(int i=0;i<20;i++)
			createGroup(groupName+i);
		String body="Action=ListGroups&Version=2010-05-08&GroupName=GroupNotExist00";
        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(200, code); 
		String xml = IOUtils.toString(connection.getInputStream());
		System.out.println(xml);
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}	
	}	
	
	//ListGroup:设置MaxItems，修改默认值为10
	@Test
	public void test_ListGroups_setMaxItems() throws Exception {

		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String groupName="TestListGroups";
		for(int i=0;i<20;i++)
			createGroup(groupName+i);
		
		String body="Action=ListGroups&Version=2010-05-08&MaxItems=5";
        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(200, code); 
		String xml = IOUtils.toString(connection.getInputStream());
		System.out.println(xml);
		JSONObject response= new JSONObject();
        response = ParseXmlToJson2(xml, "ListGroups");
        System.out.print(response);
        assertEquals("true", response.get("IsTruncated"));
        assertEquals(accountId + "|testlistgroups12", response.get("Marker"));
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}	
	}
	
	//ListGroups，设置MaxItems错误，为0
	@Test
	public void test_listGroups_setInvalidmaxItems() throws Exception{
		String groupName="forgetGroup";
		createGroup(groupName);
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		
		String body="Action=ListGroups&Version=2010-05-08&GroupName="+groupName+"&MaxItems=0";
				        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value '0' at 'maxItems' failed to satisfy constraint: Member must have value greater than or equal to 1",error.get("Message"));
	
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}		
	}

	//ListGroups，设置MaxItems错误,不为整数
	@Test
	public void test_listGroups_setInvalidmaxItems2() throws Exception{
		String groupName="forgetGroup";
		createGroup(groupName);
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		
		String body="Action=ListGroups&Version=2010-05-08&GroupName="+groupName+"&MaxItems=5.5";
				        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("MalformedInput",error.get("Code"));
		assertEquals("Invalid Argument.",error.get("Message"));
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}		
	}	
	//ListGroups，设置Marker
	@Test
	public void test_ListGroups_setMarker() throws Exception {

		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String groupName="TestListGroups";
		for(int i=0;i<20;i++){
			createGroup(groupName+i);
		}
		String body="Action=ListGroups&Version=2010-05-08&Marker=0000000gc0uy9|testlistgroups5";
        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(200, code); 
		String xml = IOUtils.toString(connection.getInputStream());
		System.out.println(xml);
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}	
	}
	
	
	//addUserToGroup，向组中添加用户
	@Test
	public void test_addUserToGroup() throws Exception {
		String groupName="groupfortestadduser";
		String userName="userforaddgroup";
		createGroup(groupName);
		createUser(userName);
		
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		
		String body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+groupName+"&UserName="+userName;
				        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(200, code); 
		String xml = IOUtils.toString(connection.getInputStream());
		System.out.println(xml);
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}
		
	}	

	//将用户添加到组，组不存在
	@Test
	public void test_addUserToGroup_groupnotExist() throws Exception {
		String userName="addusertogroupNotexist";
		createUser(userName);
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String body="Action=AddUserToGroup&Version=2010-05-08&GroupName=groupNotExist&UserName="+userName;
        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(404, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("NoSuchEntity",error.get("Code"));
		assertEquals("The group with name groupNotExist cannot be found.",error.get("Message"));
	
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}	
	}
	
	//将用户添加到组，组名错误
	@Test
	public void test_addUserToGroup_invalidGroupName() throws Exception {
		String userName="addusertogroupinvalid";
		createUser(userName);
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
					        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
				                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+URLEncoder.encode("testGroup**01")+"&UserName="+userName;
	        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'groupName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",error.get("Message"));
		
		out.close();
					        
		if (connection != null) {
			connection.disconnect();
		}	
	}
	
	//将用户添加到组：组名长度校验，合法长度1-128
	@Test
	public void test_addUserToGroup_groupNameinvalidlength() throws Exception {
		StringBuilder sb=new StringBuilder();
		for(int i=0;i<129;i++)
			sb.append("a");
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
					        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
				                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+URLEncoder.encode(sb.toString())+"&UserName=user";
	        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value '"+sb.toString()+"' at 'groupName' failed to satisfy constraint: Member must have length less than or equal to 128",error.get("Message"));
		
		out.close();
					        
		if (connection != null) {
			connection.disconnect();
		}	
	}	
	
	//将用户添加到组，用户不存在
	@Test
	public void test_addUserToGroup_userNotExist() throws Exception {
		String groupName="testUserAddGroup";
		createGroup(groupName);
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+ groupName +"&UserName=userNotExist";
        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(404, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("NoSuchEntity",error.get("Code"));
		assertEquals("The user with name userNotExist cannot be found.",error.get("Message"));
	
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}	
	}
	//将用户添加到组，用户名错误
	@Test
	public void test_addUserToGroup_invalidUserName() throws Exception {
		String groupName="creategroupforaddusertogroup";
		createGroup(groupName);
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
					        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
				                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+groupName+"&UserName="+URLEncoder.encode("test***user&");
	        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'userName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",error.get("Message"));
		
		out.close();
					        
		if (connection != null) {
			connection.disconnect();
		}	
	}
	
	//将用户添加到组：组名长度校验，合法长度1-64
	@Test
	public void test_addUserToGroup_userNameinvalidlength() throws Exception {
		String groupName="creategroupfrtestadduserinvaliduser";
		createGroup(groupName);
		StringBuilder sb=new StringBuilder();
		for(int i=0;i<65;i++)
			sb.append("a");
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
					        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
				                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+URLEncoder.encode(groupName)+"&UserName="+URLEncoder.encode(sb.toString());
	        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value '"+sb.toString()+"' at 'userName' failed to satisfy constraint: Member must have length less than or equal to 64",error.get("Message"));
		
		out.close();
					        
		if (connection != null) {
			connection.disconnect();
		}	
	}
	
	//将用户添加到组，必填项校验--缺少Groupname
	@Test
	public void test_addUserToGroup_requiredGroupName() throws Exception {
		String userName="foraddusertonogroupName";
		createUser(userName);
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String body="Action=AddUserToGroup&Version=2010-05-08&UserName="+userName;
        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'groupName' failed to satisfy constraint: Member must not be null",error.get("Message"));
		
		System.out.println(xml);
		
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}	
	}
	
	//将用户添加到组，必填项校验--缺少userName
	@Test
	public void test_addUserToGroup_requiredUserName() throws Exception {
		String groupName="testUserAddGroup";
		createGroup(groupName);
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+ groupName;
        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null",error.get("Message"));
		
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}	
	}
	
	//将用户添加到组，同一个用户可以重复加入同一个组
	@Test
	public void test_addUserToGroup_repeated() throws Exception {
		String groupName="repeatedaddUsertosameGroup";
		String userName="userforrepeatedaddGroup";
		createUser(userName);
		createGroup(groupName);
		
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+ groupName +"&UserName="+userName;
        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(200, code); 
		String xml = IOUtils.toString(connection.getInputStream());
		System.out.println(xml);
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}	
	}	
	
	//将用户添加到组，用户加入组限制，一个用户最多可以加入到10个组
	@Test
	public void test_addUserToGroup_limited() throws Exception {
		String groupName="testforlimitedgroupNum";
		String userName="userforlimitedgroupNum";
		createUser(userName);
		for(int i=0;i<10;i++){
			createGroup(groupName+i);
			addUserToGroup(groupName+i,userName);
		}
		createGroup(groupName);
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+ groupName +"&UserName="+userName;
        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(409, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("LimitExceeded",error.get("Code"));
		assertEquals("Cannot exceed quota for GroupsPerUser: 10.",error.get("Message"));
		
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}	
	}	

	
	//removeUserfromGroup,从组中删除用户
	@Test
	public void test_removeUserFromGroup() throws Exception {
		String groupName="groupfortestadduser";
		String userName="userforaddgroup";
		createGroup(groupName);
		createUser(userName);
		addUserToGroup(groupName,userName);
		
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		
		String body="Action=RemoveUserFromGroup&Version=2010-05-08&GroupName="+groupName+"&UserName="+userName;
				        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(200, code); 
		String xml = IOUtils.toString(connection.getInputStream());
		System.out.println(xml);
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}
		
	}
	
	//将用户从组中移除，组名错误
	@Test
	public void test_removeUserFromGroup_invalidGroupName() throws Exception {
		String userName="rmusertogroupinvalid";
		createUser(userName);
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
					        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
				                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String body="Action=RemoveUserFromGroup&Version=2010-05-08&GroupName="+URLEncoder.encode("testGroup**01")+"&UserName="+userName;
	        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'groupName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",error.get("Message"));
		
		out.close();
					        
		if (connection != null) {
			connection.disconnect();
		}	
	}
	
	//将用户从组中移除：组名长度校验，合法长度1-128
	@Test
	public void test_removeUserFromGroup_groupNameinvalidlength() throws Exception {
		StringBuilder sb=new StringBuilder();
		for(int i=0;i<129;i++)
			sb.append("a");
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
					        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
				                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String body="Action=RemoveUserFromGroup&Version=2010-05-08&GroupName="+URLEncoder.encode(sb.toString())+"&UserName=user";
	        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value '"+sb.toString()+"' at 'groupName' failed to satisfy constraint: Member must have length less than or equal to 128",error.get("Message"));
		
		out.close();
					        
		if (connection != null) {
			connection.disconnect();
		}	
	}	
	
	//将用户添加到组，用户名错误
	@Test
	public void test_removeUserFromGroup_invalidUserName() throws Exception {
		String groupName="creategroupforrmusertogroup";
		createGroup(groupName);
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
					        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
				                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String body="Action=RemoveUserFromGroup&Version=2010-05-08&GroupName="+groupName+"&UserName="+URLEncoder.encode("test***user&");
	        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'userName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",error.get("Message"));
		
		out.close();
					        
		if (connection != null) {
			connection.disconnect();
		}	
	}
	
	//将用户添加到组：组名长度校验，合法长度1-64
	@Test
	public void test_removeUserFromGroup_userNameinvalidlength() throws Exception {
		String groupName="creategroupfrtestrmuserinvaliduser";
		createGroup(groupName);
		StringBuilder sb=new StringBuilder();
		for(int i=0;i<65;i++)
			sb.append("a");
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
					        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
				                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String body="Action=RemoveUserFromGroup&Version=2010-05-08&GroupName="+URLEncoder.encode(groupName)+"&UserName="+URLEncoder.encode(sb.toString());
	        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value '"+sb.toString()+"' at 'userName' failed to satisfy constraint: Member must have length less than or equal to 64",error.get("Message"));
		
		out.close();
					        
		if (connection != null) {
			connection.disconnect();
		}	
	}	
	
	//从组中删除用户，必填项校验--缺少Groupname
	@Test
	public void test_removeUserFromGroup_requiredgroupName() throws Exception {
		String userName="deleteuserfromgroupnogroupName";
		createUser(userName);

		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String body="Action=RemoveUserFromGroup&Version=2010-05-08&UserName="+userName;
        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'groupName' failed to satisfy constraint: Member must not be null",error.get("Message"));
		
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}	
	}
	
	//从组中删除用户，必填项校验--缺少userName
	@Test
	public void test_removeUserFromGroup_requireduserName() throws Exception {
		String groupName="testfordeleteuserfromgroup";
		createGroup(groupName);
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String body="Action=RemoveUserFromGroup&Version=2010-05-08&GroupName="+ groupName;
        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(400, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("ValidationError",error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null",error.get("Message"));
		
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}	
	}
	
	//将用户从组中删除，用户不在group内
	@Test
	public void test_removeUserFromGroup_notIngroup() throws Exception {
		String groupName="testfordeleteuserfromgroup";
		createGroup(groupName);
		String userName="testfordeleteuserfromgroup";
		createUser(userName);
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String body="Action=RemoveUserFromGroup&Version=2010-05-08&GroupName="+ groupName +"&UserName=" + userName;
        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(200, code); 
		String xml = IOUtils.toString(connection.getInputStream());
		System.out.println(xml);
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}	
	}	

	//将用户添加到组，组不存在
	@Test
	public void test_removeUserFromGroup_groupnotExist() throws Exception {
		String userName="removeUserFromGroupNotexist";
		createUser(userName);
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String body="Action=RemoveUserFromGroup&Version=2010-05-08&GroupName=groupNotExist&UserName="+userName;
        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(404, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("NoSuchEntity",error.get("Code"));
		assertEquals("The group with name groupNotExist cannot be found.",error.get("Message"));
	
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}	
	}	
	
	//将用户添加到组，用户不存在
	@Test
	public void test_removeUserFromGroup_userNotExist() throws Exception {
		String groupName="removeUserFromGroup";
		createGroup(groupName);
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		String body="Action=RemoveUserFromGroup&Version=2010-05-08&GroupName="+ groupName +"&UserName=userNotExist";
        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(404, code); 
		String xml = IOUtils.toString(connection.getErrorStream());
		System.out.println(xml);
		JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
		assertEquals("NoSuchEntity",error.get("Code"));
		assertEquals("The user with name userNotExist cannot be found.",error.get("Message"));
	
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}	
	}	
	
	
	//创建group
	public void createGroup(String groupName) throws Exception {

		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		
		String body="Action=CreateGroup&Version=2010-05-08&GroupName="+groupName;
				        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(200, code); 
		String xml = IOUtils.toString(connection.getInputStream());
		System.out.println(xml);
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}
	}
	
	//创建用户
	public void createUser(String userName) throws Exception {
		URL url = new URL(OOS_IAM_DOMAIN);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        
        String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                url, "POST", "sts", regionName);
        headers.put("Authorization", authorization);
        
        String body="Action=CreateUser&Version=2010-05-08&UserName="+userName+"&Tags.member.1.Key=test_key&Tags.member.1.Value=test_value";
        
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
	//创建策略
		public static String createPolicy(Effect effect,String policyName,String actionEffect,List<String> actions,String resourceEffect,List<String> resources,List<Condition> conditions)throws Exception{
			String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(effect,null, null, actionEffect, actions, resourceEffect, resources, conditions);
			String body="Action=CreatePolicy&Version=2010-05-08&PolicyName="+URLEncoder.encode(policyName)+"&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=test_des";
			Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
			assertEquals(200,result.first().intValue());
//			System.out.println(result.second());
			return result.second();
		}
	
	//组内添加用户
	public void addUserToGroup(String groupName, String userName) throws Exception{
		URL url = new URL(OOS_IAM_DOMAIN);
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
				        
		String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
			                url, "POST", "sts", regionName);
		headers.put("Authorization", authorization);
		
		String body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+groupName+"&UserName="+userName;
				        
		HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
		assertEquals(200, code); 
		String xml = IOUtils.toString(connection.getInputStream());
		System.out.println(xml);
		out.close();
				        
		if (connection != null) {
			connection.disconnect();
		}
	}
	
	private static void cleanTable(String tableName) throws IOException{ 
        HBaseAdmin hbaseAdmin = null;
        try {
            hbaseAdmin = new HBaseAdmin(GlobalHHZConfig.getConfig());
            hbaseAdmin.disableTable(tableName);
            hbaseAdmin.truncateTable(TableName.valueOf(tableName), true);

        } finally {
            if (hbaseAdmin != null) {
                hbaseAdmin.close();
            }
        }
    }
	
public static JSONObject ParseXmlToJson1(String xml, String actions) {
		
		try {
		
			StringReader sr = new StringReader(xml);
	        InputSource is = new InputSource(sr);
	        Document doc = (new SAXBuilder()).build(is);
	        Element root = null ;
	        JSONObject jObject= new JSONObject();
	        if(actions.equals("CreateGroup"))
	        	root = doc.getRootElement().getChild("CreateGroupResult").getChild("Group");
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
public static JSONObject ParseXmlToJson2(String xml, String actions) {
	
	try {
	
		StringReader sr = new StringReader(xml);
        InputSource is = new InputSource(sr);
        Document doc = (new SAXBuilder()).build(is);
        Element root = null ;
        JSONObject jObject= new JSONObject();
        
        if(actions.equals("ListGroups")){
        	root = doc.getRootElement().getChild("ListGroupsResult");
        	String values = root.getChild("IsTruncated").getValue();
        	jObject.put("IsTruncated", values);
        	if(values.equals("true")){
        		String value2 = root.getChild("Marker").getValue();
	        	jObject.put("Marker", value2);
        	}
        	
        }
        	
        if(actions.equals("GetGroup")){
        	root = doc.getRootElement().getChild("GetGroupResult");
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
        	if(root2.getName().equals("Users")){
        		List<Element> users=root2.getChildren("member");
        		if(users != null){
        			Iterator<Element> usersiterator=users.iterator();
            		JSONObject jObject2= new JSONObject();
            		int i=1;
            		while(usersiterator.hasNext()){
            			
        	        	Element root3 = usersiterator.next();
        	        	System.out.println("root3："+root3.getName());
        	        	JSONObject jObject3= new JSONObject();
        	        	Element userName=root3.getChild("UserName");
        	        	Element Arn=root3.getChild("Arn");
        	        	Element UserId=root3.getChild("UserId");
        	        	Element PasswordLastUsed=root3.getChild("PasswordLastUsed");
        	        	System.out.println("PasswordLastUsed:"+PasswordLastUsed);
        	        	Element CreateDate=root3.getChild("CreateDate");
        	        	Element JoinDate=root3.getChild("JoinDate");
        	        	jObject3.put(userName.getName(), userName.getValue());
        	        	jObject3.put(Arn.getName(), Arn.getValue());
        	        	jObject3.put(UserId.getName(), UserId.getValue());
        	        	if(PasswordLastUsed !=null)
        	        		jObject3.put(PasswordLastUsed.getName(), PasswordLastUsed.getValue());
        	        	
        	        	jObject3.put(CreateDate.getName(), CreateDate.getValue());
        	        	jObject3.put(JoinDate.getName(), JoinDate.getValue());
        	        	
        	        	jObject2.put("member"+i, jObject3);
        	        	
        	        	i++;
        	        	
            		}
            		jObject.put("Users", jObject2);	
        		}
        		
        	}
        	if(root2.getName().equals("Group")){
        		List<Element> group=root2.getChildren();
        		System.out.println("Group----"+group);
        		Iterator<Element> iterator2=group.iterator();
        		JSONObject jObject2= new JSONObject();
	        	while(iterator2.hasNext()){
	        		Element root3 = iterator2.next();
	        		System.out.println(root3.getName());
	        		String key=root3.getName();
		        	String value=root3.getValue();
		        	jObject2.put(key, value);
	        	}
	        	jObject.put("Group", jObject2);
        	}
        	if(root2.getName().equals("Groups")){
        		List<Element> groups=root2.getChildren("member");
        		if(groups != null){
        			Iterator<Element> groupsterator=groups.iterator();
            		JSONObject jObject2= new JSONObject();
            		int i=1;
            		while(groupsterator.hasNext()){
            			Element root3 = groupsterator.next();
            			JSONObject jObject3= new JSONObject();
        	        	Element GroupName=root3.getChild("GroupName");
        	        	Element Arn=root3.getChild("Arn");
        	        	Element GroupId=root3.getChild("GroupId");
        	        	Element Policies=root3.getChild("Policies");
        	        	Element CreateDate=root3.getChild("CreateDate");
        	        	Element Users=root3.getChild("Users");
        	        	jObject3.put(GroupName.getName(), GroupName.getValue());
        	        	jObject3.put(Arn.getName(), Arn.getValue());
        	        	jObject3.put(GroupId.getName(), GroupId.getValue());
        	        	jObject3.put(Policies.getName(), Policies.getValue());
        	        	jObject3.put(CreateDate.getName(), CreateDate.getValue());
        	        	jObject3.put(Users.getName(), Users.getValue());
        	        	
        	        	jObject2.put("member"+i, jObject3);
        	        	i++;
    	        	}
            		jObject.put("Groups", jObject2);
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
