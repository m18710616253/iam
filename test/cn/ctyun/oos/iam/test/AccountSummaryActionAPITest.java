package cn.ctyun.oos.iam.test;

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.URL;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.io.IOUtils;
import org.eclipse.jetty.util.UrlEncoded;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.XML;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xml.sax.InputSource;

import cn.ctyun.common.BaseException;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.server.entity.AccountSummary;
import cn.ctyun.oos.iam.server.entity.MFADevice;
import cn.ctyun.oos.iam.server.entity.ParseArnException;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.server.util.JSONUtils;
import cn.ctyun.oos.iam.test.iamaccesscontrol.IAMInterfaceTestUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;
import common.tuple.Pair;

public class AccountSummaryActionAPITest {
	public static final String OOS_IAM_DOMAIN="https://oos-xl-iam.ctyunapi.cn:9460/";
	public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
	public static final String regionName="xl";
	
	public static final String accessKey="65dd530d67f7f88e222f";
	public static final String secretKey="bee6a1d024e999bdf72e04d6a37d85bba789c5d3";
	
	public static final String accessKeyother="122aa530d67f7f88e222f";
	public static final String secretKeyother="aac6a1d024e999bdf72e04d6a37d85bba789c225";

	public static final String accountId = "0000000gc0uy9";

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
//		IAMTestUtils.TrancateTable("iam-accountSummary-huxl");
	}

	@Before
	public void setUp() throws Exception {
	}

	//未修改默认值，未添加策略，用户，group，MFA，获取账户信息
	@Test
	public void test_getAccountSummary() throws JSONException {
		String body="Action=GetAccountSummary&Version=2010-05-08";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		JSONObject assertresult=ParseXmlToJson(result.second());
		assertEquals("0",assertresult.get("Policies"));
		assertEquals("10",assertresult.get("GroupsPerUserQuota"));
		assertEquals("10",assertresult.get("AttachedPoliciesPerUserQuota"));
		assertEquals("0",assertresult.get("Users"));
		assertEquals("150",assertresult.get("PoliciesQuota"));
		assertEquals("0",assertresult.get("MFADevicesInUse"));
		assertEquals("2",assertresult.get("AccessKeysPerUserQuota"));
		assertEquals("10",assertresult.get("AttachedPoliciesPerGroupQuota"));
		assertEquals("0",assertresult.get("Groups"));
		assertEquals("500",assertresult.get("UsersQuota"));
		assertEquals("1",assertresult.get("AccountAccessKeysPresent"));
		assertEquals("0",assertresult.get("MFADevices"));
		assertEquals("30",assertresult.get("GroupsQuota"));
		
		
	}
	
	
	//添加用户，组，策略，将策略附加到组和用户，获取账户信息
	@Test
	public void test_getAccountSummary_setParam() throws Exception {
		String groupName="createfortestgetSummary";
		String userName="createfortestgetSummary";
		String policyName="createfortestgetSummary";
		String policyArn="arn:ctyun:iam::0000000gc0uy9:policy/"+policyName;
		//创建4个组
		for(int i=0;i<4;i++)
			createGroup(groupName+i);
		//创建4个用户
		for(int i=0;i<4;i++)
			createUser(userName+i);
		//创建4个策略
		for(int i=0;i<4;i++)
			createPolicy(policyName+i);
				
		String body="Action=GetAccountSummary&Version=2010-05-08";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		JSONObject assertresult=ParseXmlToJson(result.second());
		assertEquals("4",assertresult.get("Policies"));
		assertEquals("10",assertresult.get("GroupsPerUserQuota"));
		assertEquals("10",assertresult.get("AttachedPoliciesPerUserQuota"));
		assertEquals("4",assertresult.get("Users"));
		assertEquals("150",assertresult.get("PoliciesQuota"));
		assertEquals("0",assertresult.get("MFADevicesInUse"));
		assertEquals("2",assertresult.get("AccessKeysPerUserQuota"));
		assertEquals("10",assertresult.get("AttachedPoliciesPerGroupQuota"));
		assertEquals("4",assertresult.get("Groups"));
		assertEquals("500",assertresult.get("UsersQuota"));
		assertEquals("1",assertresult.get("AccountAccessKeysPresent"));
		assertEquals("0",assertresult.get("MFADevices"));
		assertEquals("30",assertresult.get("GroupsQuota"));
		
		for(int i = 0; i<4;i++){
			IAMInterfaceTestUtils.DeleteGroup(accessKey, secretKey, groupName+i, 200);
			IAMInterfaceTestUtils.DeleteUser(accessKey, secretKey, userName+i, 200);
			IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName+i, 200);
		}
			
		
	}
	
	//创建MFADevice，设置Enabled，添加MFA,获取账户信息
	@Test
	public void test_getAccountSummary_setParam2() throws Exception {
		String userName="createUserfortestgetSummary";
		createUser(userName);
		String virtualFMAName="createmfafortestgetSummary";
		//创建2个MFA
		for(int i=0;i<2;i++)
			createVirtualMFADevice(virtualFMAName+i);
		//1个设备添加到用户
		virtualMFADeviceEnabled(accessKey, secretKey, userName, virtualFMAName + "1", 200);
		
		String body="Action=GetAccountSummary&Version=2010-05-08";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		JSONObject assertresult=ParseXmlToJson(result.second());
		assertEquals("0",assertresult.get("Policies"));
		assertEquals("10",assertresult.get("GroupsPerUserQuota"));
		assertEquals("10",assertresult.get("AttachedPoliciesPerUserQuota"));
		assertEquals("5",assertresult.get("Users"));
		assertEquals("150",assertresult.get("PoliciesQuota"));
		assertEquals("1",assertresult.get("MFADevicesInUse"));
		assertEquals("2",assertresult.get("AccessKeysPerUserQuota"));
		assertEquals("10",assertresult.get("AttachedPoliciesPerGroupQuota"));
		assertEquals("0",assertresult.get("Groups"));
		assertEquals("500",assertresult.get("UsersQuota"));
		assertEquals("1",assertresult.get("AccountAccessKeysPresent"));
		assertEquals("2",assertresult.get("MFADevices"));
		assertEquals("30",assertresult.get("GroupsQuota"));
		
		
	}

	//创建policy
	public void createPolicy(String policyName) {
		String policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"Arn:aws:s3:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:Get*\",\"s3:List*\"],\"Resource\":[\"Arn:aws:s3:::EXAMPLE-BUCKET\",\"Arn:aws:s3:::EXAMPLE-BUCKET/*\"]}]}";
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
	
	
	//创建MFA
	public void createVirtualMFADevice(String virtualMFADeviceName){
		String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName="+virtualMFADeviceName;
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
	}
	
	//
	public void virtualMFADeviceEnabled(String userName,String SerialNumber,String base32StringSeed) {
//        String base32StringSeed="X7QSF6FIDOKUCXMHKSGLV334YOUCDSKFXYEDA7IQHJSRSDRQFM3RTAM2T7LLZDLK";
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        String body="Action=EnableMFADevice&Version=2010-05-08&UserName="+userName+"&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
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
	public static JSONObject ParseXmlToJson(String xml) {
		try {
			StringReader sr = new StringReader(xml);
	        InputSource is = new InputSource(sr);
	        Document doc = (new SAXBuilder()).build(is);
	        Element root = doc.getRootElement().getChild("GetAccountSummaryResult").getChild("SummaryMap");
	        List<Element> children=root.getChildren();
	        Iterator<Element> iterator=children.iterator();
	        JSONObject jObject= new JSONObject();
	        while(iterator.hasNext()){
	        	Element root2 = iterator.next();
	        	String key=root2.getChild("key").getValue();
	        	String value=root2.getChild("value").getValue();
	        	
	        	jObject.put(key, value);
	        	
	        }
	        
	        return jObject;
	        
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
        return null;
        
	}	
	
	   private static MFADevice getMFADeviceFromArn(String arn, String accountId) throws BaseException, IOException {
	        MFADevice mFADevice = new MFADevice();
	        try {
	            mFADevice.parseArn(arn);
	        } catch (ParseArnException e) {
//	            log.error("", e);
	            throw new BaseException(404, "NoSuchEntity", "VirtualMFADevice with serial number " + arn + " does not exist.");
	        }
	        MFADevice existMFA = HBaseUtils.get(mFADevice);
	        if (existMFA == null || !mFADevice.accountId.equals(accountId)) {
	            throw new BaseException(404, "NoSuchEntity", "VirtualMFADevice with serial number " + arn + " does not exist.");

	        }
	        return existMFA;
	    }
	   



}
