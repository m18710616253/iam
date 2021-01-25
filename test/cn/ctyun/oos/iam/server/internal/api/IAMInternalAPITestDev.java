package cn.ctyun.oos.iam.server.internal.api;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;
import org.xml.sax.InputSource;

import cn.ctyun.common.Consts;
import cn.ctyun.common.conf.GlobalIamConfig;
import cn.ctyun.common.conf.OOSConfig;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.service.IAMPolicyClient;
import cn.ctyun.oos.iam.server.entity.AccountSummary;
import cn.ctyun.oos.iam.server.util.JSONUtils;
import cn.ctyun.oos.iam.signer.Utils;
import cn.ctyun.oos.metadata.OwnerMeta;
import common.tuple.Pair;


public class IAMInternalAPITestDev {
    
    private String ownerName1 = "test_user8_6463084869102845087@a.cn";
    private OwnerMeta owner1 = new OwnerMeta(ownerName1);
    
	public static final String OOS_IAM_DOMAIN="http://localhost:9097/";


	@Test
	public void testGetAccountSummary() throws Exception {
		URL url = new URL(OOS_IAM_DOMAIN + "internal/getAccountSummary");
        AccountSummary accountSummary = new AccountSummary();
        accountSummary.accountId = owner1.getAccountId();
        String body = JSONUtils.MAPPER.writeValueAsString(accountSummary);
        
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setUseCaches(false);
        connection.setDoInput(true);
        connection.setDoOutput(true);
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

	@Test
	public void testPutAccountQuota() throws Exception {
        URL url = new URL(OOS_IAM_DOMAIN + "internal/putAccountQuota");
        AccountSummary accountQuota = new AccountSummary();
        //测试数据
        accountQuota.accountId = owner1.getAccountId();
        accountQuota.usersQuota = 222L;
        accountQuota.groupsQuota = 30L;
        accountQuota.policiesQuota = 150L;
        accountQuota.groupsPerUserQuota = 2L;
        accountQuota.attachedPoliciesPerUserQuota = 2L;
        accountQuota.attachedPoliciesPerGroupQuota = 2L;
        accountQuota.accessKeysPerUserQuota = 5L;
        accountQuota.accessKeysPerAccountQuota = 4L;
        String body = JSONUtils.MAPPER.writeValueAsString(accountQuota);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setUseCaches(false);
        connection.setDoInput(true);
        connection.setDoOutput(true);
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

	@Test
	public void testGetSystemQuota() throws Exception {
        URL url = new URL(OOS_IAM_DOMAIN + "internal/getSystemQuota");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setUseCaches(false);
        connection.setDoInput(true);
        connection.setDoOutput(true);
        int code = connection.getResponseCode();
        String xml = IOUtils.toString(connection.getInputStream());
        assertEquals(200, code);
        System.out.println(xml);
        if (connection != null) {
            connection.disconnect();
        }
	}

	@Test
	public void testPutSystemQuota() throws Exception {
        URL url = new URL(OOS_IAM_DOMAIN + "internal/putSystemQuota");
        AccountSummary systemQuota = new AccountSummary();
        //测试数据
        systemQuota.usersQuota = 666L;
        systemQuota.groupsQuota = 30L;
        systemQuota.policiesQuota = 150L;
        systemQuota.groupsPerUserQuota = 10L;
        systemQuota.attachedPoliciesPerUserQuota = 10L;
        systemQuota.attachedPoliciesPerGroupQuota = 10L;
        systemQuota.accessKeysPerUserQuota = 2L;
        systemQuota.accessKeysPerAccountQuota = 2L;
        String body = JSONUtils.MAPPER.writeValueAsString(systemQuota);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setUseCaches(false);
        connection.setDoInput(true);
        connection.setDoOutput(true);
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
	
	
	
	//用获取单用户策略来调试Authorize中的错误
	@Test
	public void test_Authorize() throws Exception {
		//准备
		//IAMTestUtils.TrancateTable("iam-policy");
		//IAMTestUtils.TrancateTable("iam-user");
		String accountId = "3rmoqzn03g6ga";
	    String user1Name="test_1";
	    String accessKey="userak";
		String secretKey="usersk";
		String ownerName = "root_user@test.com";
		String user1accessKey1="abcdefghijklmnop";
		String user1secretKey1="cccccccccccccccc";
		String user1accessKey2="1234567890123456";
		String user1secretKey2="user1secretKey2lllll";
		OwnerMeta owner = new OwnerMeta(ownerName);
		MetaClient metaClient = MetaClient.getGlobalClient();
	    // 创建根用户
//	    owner.email=ownerName;
//	 	owner.setPwd("123456");
//	 	owner.maxAKNum=10;
//	 	owner.displayName="测试根用户";
//	 	owner.bucketCeilingNum=10;
//	 	metaClient.ownerInsertForTest(owner);
//	 	
//	 	AkSkMeta aksk=new AkSkMeta(owner.getId());
//	 	aksk.accessKey=accessKey;
//	 	aksk.setSecretKey(secretKey);
//	 	aksk.isPrimary=1;
//	 	metaClient.akskInsert(aksk);
//	    
//	 	String UserName1=user1Name;
//	 	Pair<String, String> tag=new Pair<String, String>();
//	 	tag.first("email");
//	 	tag.second("test1@oos.com");
//	 	
//	 	List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
//	 	tags.add(tag);
//	 	
//	 	String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName1+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
//	 	Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
//	 	
//	 	assertEquals(200, resultPair.first().intValue());
//	 	String userId1=AssertCreateUserResult(resultPair.second(), UserName1, tags);
//	 	// 插入数据库aksk
//	 	AkSkMeta aksk1 = new AkSkMeta(owner.getId());
//	    aksk1.isRoot = 0;
//	    aksk1.userId = userId1;
//	    aksk1.userName = UserName1;
//	    aksk1.accessKey=user1accessKey1;
//	    aksk1.setSecretKey(user1secretKey1);
//	    metaClient.akskInsert(aksk1);
//	    User user1 = new User();
//	    user1.accountId = accountId;
//	    user1.userName = UserName1;
//	    user1.accessKeys = new ArrayList<>();
//	    user1.accessKeys.add(aksk1.accessKey);
//	    
//	    aksk1.accessKey=user1accessKey2;
//	    aksk1.setSecretKey(user1secretKey2);
//	    metaClient.akskInsert(aksk1);
//	    user1.accessKeys.add(aksk1.accessKey);
//	    HBaseUtils.put(user1);

		//测试
	    Log log = LogFactory.getLog(IAMPolicyClient.class);
		JSONObject jsonObject = new JSONObject();
        try {
            jsonObject.put("accountId", "3rmoqzn03g6ga");
            jsonObject.put("userName", user1Name);
        } catch (JSONException e) {
            // 该错误不会发生，不做处理
            log.error(e.getMessage(), e);
        }
        InputStream is = null;
        try {
            is = getPoliciesStreamViaHttp(GlobalIamConfig.getResource()+"/policy", jsonObject.toString());
        } finally {
            try{
                if(null != is)
                    is.close();
            } catch (Exception e){
                log.error(e.getMessage(), e); 
            }
        }
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
	
	private static InputStream getPoliciesStreamViaHttp(String resource, String body) throws IOException {
//        URL url = new URL(GlobalIamConfig.getProtocol(), GlobalIamConfig.getIamHost(), 
//                GlobalIamConfig.getPort(), resource);
		URL url = new URL(GlobalIamConfig.getProtocol(), GlobalIamConfig.getIamHost(), 
              9097, resource);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        // 服务间的AK签名认证
        String auth = Utils.authorize("GET", GlobalIamConfig.getAk(), GlobalIamConfig.getSk(),
                new HashMap<String, String>());
        conn.setRequestProperty(Consts.AUTHORIZATION, auth);
        conn.setConnectTimeout(OOSConfig.getInternalConnTimeout());
        conn.setReadTimeout(OOSConfig.getInternalReadTimeout());
        conn.setRequestMethod("GET");
        conn.setDoInput(true);
        conn.setDoOutput(true);
        OutputStream out = conn.getOutputStream();
        out.write(body.getBytes());
        out.flush();
        int code = conn.getResponseCode();
        if (code == HttpURLConnection.HTTP_OK) {
            return conn.getInputStream();
        } else {
            String msg = getErrorMsg(conn);
            throw new IOException(msg);
        }
    }
	
	private static String getErrorMsg(HttpURLConnection conn) {
		Log log = LogFactory.getLog(IAMPolicyClient.class);
		try (InputStream in = conn.getInputStream()) {
            return IOUtils.toString(in, Consts.STR_UTF8);
        } catch (IOException e) {
            try (InputStream err = conn.getErrorStream()) {
                if (err != null) {
                    return IOUtils.toString(err, Consts.STR_UTF8);
                } else {
                    return null;
                }
            } catch (IOException e2) {
                log.error(e2.getMessage(), e2);
                return null;
            }
        }
    }


	

	
	
	
	
	
}
