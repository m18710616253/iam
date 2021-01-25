package cn.ctyun.oos.iam.server.internal.api;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.io.IOUtils;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xml.sax.InputSource;

import cn.ctyun.common.BaseException;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.server.util.JSONUtils;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.iam.test.V4TestUtils;
import cn.ctyun.oos.metadata.OwnerMeta;
import common.tuple.Pair;

public class IAMInternalLoginTestDev {
	public static final String OOS_IAM_DOMAIN = "http://localhost:9097/";
	
	public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
	public static final String regionName="cd";
	
	private static String ownerName = "root_user@test.com";
	public static final String accessKey="userak";
	public static final String secretKey="usersk";
	
	public static final String user1Name="ak_test_1";
	public static final String user1accessKey1="abcdefghijklmnop";
	public static final String user1secretKey1="cccccccccccccccc";
	public static final String user1accessKey2="1234567890123456";
	public static final String user1secretKey2="user1secretKey2lllll";

	public static final String policyName="AccessKeyPolicy";
	
	public static String accountId="3rmoqzn03g6ga";
	
	public static OwnerMeta owner = new OwnerMeta(ownerName);
    public static MetaClient metaClient = MetaClient.getGlobalClient();
    
    
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
//		IAMTestUtils.TrancateTable("oos-aksk");
//		IAMTestUtils.TrancateTable("iam-user");
//		IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
//		IAMTestUtils.TrancateTable(IAMTestUtils.iamGroupTable);
//		IAMTestUtils.TrancateTable(IAMTestUtils.iammfaDeviceTable);
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
//        //创建用户ak_test_1
//		String UserName1=user1Name;
//		Pair<String, String> tag=new Pair<String, String>();
//		tag.first("email");
//		tag.second("test1@oos.com");
//		
//		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
//		tags.add(tag);
//		
//		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName1+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
//		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
//		
//		assertEquals(200, resultPair.first().intValue());
//		String userId1=AssertCreateUserResult(resultPair.second(), UserName1, tags);
//
//		// 插入数据库aksk
//		AkSkMeta aksk1 = new AkSkMeta(owner.getId());
//        aksk1.isRoot = 0;
//        aksk1.userId = userId1;
//        aksk1.userName = UserName1;
//        aksk1.accessKey=user1accessKey1;
//        aksk1.setSecretKey(user1secretKey1);
//        metaClient.akskInsert(aksk1);
//        User user1 = new User();
//        user1.accountId = accountId;
//        user1.userName = UserName1;
//        user1.accessKeys = new ArrayList<>();
//        user1.accessKeys.add(aksk1.accessKey); 
//        aksk1.accessKey=user1accessKey2;
//        aksk1.setSecretKey(user1secretKey2);
//        metaClient.akskInsert(aksk1);
//        user1.accessKeys.add(aksk1.accessKey);
//        HBaseUtils.put(user1);
	}

	@Test
	public void checkMFACode() throws Exception {
//		//创建mfa设备
//		String mfaName="testmfa";
//		String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName="+mfaName;
//		Pair<Integer,String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
//        assertEquals(200,root.first().intValue());
//		
//		//将mfa设备与用户关联
//        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(root.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + mfaName);
//        Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
//        String authenticationCode1 = authenticationCode.first();
//        String authenticationCode2 = authenticationCode.second();
//		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user1Name, accountId, mfaName, authenticationCode1, authenticationCode2, 200);
//		
//		//为用户创建登录权限
//		IAMInterfaceTestUtils.CreateLoginProfile(accessKey, secretKey, user1Name, "a12345678", 200);
//		System.out.println("base32String : "+devicePair.second());
//		String mfaCode=getMFACode(devicePair.second());
		
		String base32String="V7KZG3GMO74K3SXXWERTSWUTVE5TWNGR36V27FHXJGTQ3JYTCBGTHBIXQJ6KG5VZ";
		String mfaCode=getMFACode(base32String);
		
		LoginParam loginParam=new LoginParam();
		loginParam.accountId=accountId;
		loginParam.userName=user1Name;
		loginParam.passwordMd5="a12345678";
		loginParam.mFACode=Long.parseLong(mfaCode);
		String body=JSONUtils.MAPPER.writeValueAsString(loginParam);
		
		Pair<Integer,String> result=invokeHttpsRequest(body);//成功
		assertEquals(200, result.first().intValue());
		System.out.println("成功,mfaCode: "+mfaCode);
        
		result=invokeHttpsRequest(body);//重复，失败第一次
		assertEquals(403, result.first().intValue());
		System.out.println("重复，失败第一次");
		
		Thread.sleep(30*1000);
		
		mfaCode=getMFACode(base32String);
		loginParam.mFACode=Long.parseLong(mfaCode);
		body=JSONUtils.MAPPER.writeValueAsString(loginParam);
		
		result=invokeHttpsRequest(body);//新的mfaCode，成功
		assertEquals(200, result.first().intValue());
		System.out.println("成功,mfaCode: "+mfaCode);
		
		result=invokeHttpsRequest(body);//重复，失败第二次
		assertEquals(403, result.first().intValue());
		System.out.println("重复，失败第二次");
		
		loginParam.mFACode=Long.parseLong("123456");
		body=JSONUtils.MAPPER.writeValueAsString(loginParam);
		
		result=invokeHttpsRequest(body);//失败第三次，验证码错误
		assertEquals(403, result.first().intValue());
		System.out.println("失败第三次，验证码错误");
		
		result=invokeHttpsRequest(body);//失败第四次，验证码错误
		assertEquals(403, result.first().intValue());
		System.out.println("失败第四次，验证码错误");
		
		result=invokeHttpsRequest(body);//失败第五次，验证码错误，禁用2分钟
		assertEquals(403, result.first().intValue());
		System.out.println("失败第五次，验证码错误，禁用2分钟");
		
		Thread.sleep(30*1000);
		
		mfaCode=getMFACode(base32String);
		loginParam.mFACode=Long.parseLong(mfaCode);
		body=JSONUtils.MAPPER.writeValueAsString(loginParam);
		
		result=invokeHttpsRequest(body);//禁用，失败
		assertEquals(403, result.first().intValue());
		System.out.println("禁用，失败,mfaCode:"+mfaCode);
		
		Thread.sleep(2*60*1000);
		
		mfaCode=getMFACode(base32String);
		loginParam.mFACode=Long.parseLong(mfaCode);
		body=JSONUtils.MAPPER.writeValueAsString(loginParam);
		
		result=invokeHttpsRequest(body);//解除禁用，成功
		assertEquals(200, result.first().intValue());
		System.out.println("解除禁用，成功,mfaCode:"+mfaCode);
	}
	
	public String getMFACode(String secret) {
		return addZeroForNum(String.valueOf(generateCode(secret)),6);
	}
	
	private int generateCode(String secret)  {
	     
	     Base32 codec = new Base32();
	     byte[] key = codec.decode(secret);
	     long t = System.currentTimeMillis() / 1000L / 30L;
	     
	     
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
	
	public Pair<String, String> AssertcreateVirtualMFADevice(String xml,String serialNumber) {
		try {
			StringReader sr = new StringReader(xml);
	        InputSource is = new InputSource(sr);
	        Document doc = (new SAXBuilder()).build(is);
	        Element root = doc.getRootElement();
	        
	        Element resultElement=root.getChild("CreateVirtualMFADeviceResult");
	        Element virtualMFADevice=resultElement.getChild("VirtualMFADevice");
	        String SerialNumber=virtualMFADevice.getChild("SerialNumber").getValue();
	        String Base32StringSeed=virtualMFADevice.getChild("Base32StringSeed").getValue();
	        String QRCodePNG=virtualMFADevice.getChild("QRCodePNG").getValue();
	        System.out.println("QRCodePNG="+QRCodePNG);
	        assertEquals(serialNumber, SerialNumber);
	        Pair<String, String> pair = new Pair<String, String>();
	        pair.first(SerialNumber);
	        pair.second(Base32StringSeed);
	        return pair;
		} catch (Exception e) {
			// TODO: handle exception
		}
		
		return null;
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
        //补全IdentifyingCode前面缺少的零
        String firstCode = addZeroForNum(codePair.first(), 6);
        String secondCode = addZeroForNum(codePair.second(), 6);
        codePair.first(firstCode);
        codePair.second(secondCode);
        return codePair;
    }

	private int generateCode(byte[] key, long t)  {
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
	
	public String addZeroForNum(String str, int strLength) {
	    int strLen = str.length();
	    StringBuffer sb = null;
	     while (strLen < strLength) {
	           sb = new StringBuffer();
	           sb.append("0").append(str); //不足6位左补0
	           str = sb.toString();
	           strLen = str.length();
	     }
	    return str;
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

	public Pair<Integer, String> invokeHttpsRequest(String body) throws Exception {
		Pair<Integer, String> result=new Pair<Integer, String>();
		
		URL url = new URL(OOS_IAM_DOMAIN + "internal/login");
		
		HttpURLConnection connection = (HttpURLConnection) url.openConnection();
		connection.setRequestMethod("POST");
		connection.setUseCaches(false);
		connection.setDoInput(true);
		connection.setDoOutput(true);
		OutputStream out = connection.getOutputStream();
		out.write(body.getBytes());
		out.flush();
		int code = connection.getResponseCode();
        String xml ="";
        if (code==200) {
        	xml = IOUtils.toString(connection.getInputStream());
		}else {
			xml = IOUtils.toString(connection.getErrorStream());
		}
        result.first(code);
        result.second(xml);;
        System.out.println(xml);
		out.close();
		if (connection != null) {
			connection.disconnect();
		}
		
		return result;
		
	}


}
