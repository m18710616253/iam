package cn.ctyun.oos.utils.api;

import static org.junit.Assert.assertEquals;

import java.io.OutputStream;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.io.IOUtils;
import org.eclipse.jetty.util.UrlEncoded;

import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.utils.HttpConnectionSSLRequestUtils;
import cn.ctyun.oos.utils.V4SignClient;
import common.tuple.Pair;

public class IAMAPITestUtils {
    public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
    
    
    public static String CreateGroup(String endpointUrlStr,String regionName,String ak,String sk,String groupName,Map<String, String> headers,int expectedCode) {
        String body="Action=CreateGroup&Version=2010-05-08&GroupName="+UrlEncoded.encodeString(groupName);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();  
    }
    
    public static String DeleteGroup(String endpointUrlStr,String regionName,String ak,String sk,String groupName,Map<String, String> headers,int expectedCode) {
        String body="Action=DeleteGroup&Version=2010-05-08&GroupName="+UrlEncoded.encodeString(groupName); 
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers); 
        assertEquals(expectedCode, result.first().intValue());
        return result.second(); 
    }
    
    public static String GetGroup(String endpointUrlStr,String regionName,String ak,String sk,String groupName,Map<String, String> headers,int expectedCode) {
        String body="Action=GetGroup&Version=2010-05-08&GroupName="+UrlEncoded.encodeString(groupName); 
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);  
        assertEquals(expectedCode, result.first().intValue());
        return result.second(); 
    }
    
    public static String ListGroups(String endpointUrlStr,String regionName,String ak,String sk,Map<String, String> headers,int expectedCode) {
        String body="Action=ListGroups&Version=2010-05-08"; 
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();
    }
    
    public static String AddUserToGroup(String endpointUrlStr,String regionName,String ak,String sk,String groupName,String userName,Map<String, String> headers,int expectedCode) {
        String body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+UrlEncoded.encodeString(groupName)+"&UserName="+UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();
    }
    
    public static String RemoveUserFromGroup(String endpointUrlStr,String regionName,String ak,String sk,String groupName,String userName,Map<String, String> headers,int expectedCode) {
        String body="Action=RemoveUserFromGroup&Version=2010-05-08&GroupName="+UrlEncoded.encodeString(groupName)+"&UserName="+UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();
  
    }
    
    public static String CreateUser(String endpointUrlStr,String regionName,String ak,String sk,String userName,Map<String, String> headers,int expectedCode) {
        String body="Action=CreateUser&Version=2010-05-08&UserName="+UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String DeleteUser(String endpointUrlStr,String regionName,String ak,String sk,String userName,Map<String, String> headers,int expectedCode) {
        String body="Action=DeleteUser&UserName="+UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String GetUser(String endpointUrlStr,String regionName,String ak,String sk,String userName,Map<String, String> headers,int expectedCode) {
        String body="Action=GetUser&UserName="+UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String ListUsers(String endpointUrlStr,String regionName,String ak,String sk,Map<String, String> headers,int expectedCode) {
        String body="Action=ListUsers&Version=2010-05-08";
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String ListUserTags(String endpointUrlStr,String regionName,String ak,String sk,String userName,Map<String, String> headers,int expectedCode) {
        String body="Action=ListUserTags&Version=2010-05-08&UserName="+UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String TagUser(String endpointUrlStr,String regionName,String ak,String sk,String userName, List<Pair<String, String>> tags,Map<String, String> headers,int expectedCode) {
        String tagString="";
        for (int i = 1; i < tags.size()+1; i++) {
            tagString+="&Tags.member."+i+".Key="+tags.get(i-1).first()+"&Tags.member."+i+".Value="+tags.get(i-1).second();
        }
        
//        System.out.println(tagString);
        String body="Action=TagUser&Version=2010-05-08&UserName="+UrlEncoded.encodeString(userName)+tagString;
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String UntagUser(String endpointUrlStr,String regionName,String ak,String sk,String userName, List<String> tagKeys,Map<String, String> headers,int expectedCode) {
        String untagString="";
        for (int i = 1; i < tagKeys.size(); i++) {
            untagString+="&TagKeys.member."+i+"="+tagKeys.get(i-1);
        }
        
        System.out.println(untagString);
        String body="Action=UntagUser&Version=2010-05-08&UserName="+UrlEncoded.encodeString(userName)+untagString;
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String ListGroupsForUser(String endpointUrlStr,String regionName,String ak,String sk,String userName,Map<String, String> headers,int expectedCode) {
        String body="Action=ListGroupsForUser&Version=2010-05-08&UserName="+UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String CreateAccessKey(String endpointUrlStr,String regionName,String ak,String sk,String userName,Map<String, String> headers,int expectedCode) {
        String body="Action=CreateAccessKey&UserName="+UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String DeleteAccessKey(String endpointUrlStr,String regionName,String ak,String sk,String akId,String userName,Map<String, String> headers,int expectedCode) {
        String body="Action=DeleteAccessKey&AccessKeyId="+akId+"&UserName="+UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String ListAccessKeys(String endpointUrlStr,String regionName,String ak,String sk,String userName,Map<String, String> headers,int expectedCode) {
        String body="Action=ListAccessKeys&UserName="+UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String UpdateAccessKey(String endpointUrlStr,String regionName,String ak,String sk,String akId,String userName,String status,Map<String, String> headers,int expectedCode) {
        String body="Status="+status+"&Action=UpdateAccessKey&AccessKeyId="+akId+"&UserName="+UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String GetAccessKeyLastUsed(String endpointUrlStr,String regionName,String ak,String sk,String akId,Map<String, String> headers,int expectedCode) {
        String body="Action=GetAccessKeyLastUsed&AccessKeyId="+akId;
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String ChangePassword(String endpointUrlStr,String regionName,String ak,String sk,String userName,String oldPassword,String newPassword,Map<String, String> headers,int expectedCode) {
        String body="Action=ChangePassword&UserName="+UrlEncoded.encodeString(userName)+"&OldPassword="+oldPassword+"&NewPassword="+newPassword;
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String CreateLoginProfile(String endpointUrlStr,String regionName,String ak,String sk,String userName,String newPassword,Map<String, String> headers,int expectedCode) {
        String body="Action=CreateLoginProfile&UserName="+UrlEncoded.encodeString(userName)+"&Password="+newPassword;
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String UpdateLoginProfile(String endpointUrlStr,String regionName,String ak,String sk,String userName,String newPassword,Map<String, String> headers,int expectedCode) {
        String body="Action=UpdateLoginProfile&UserName="+UrlEncoded.encodeString(userName)+"&Password="+newPassword;
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String DeleteLoginProfile(String endpointUrlStr,String regionName,String ak,String sk,String userName,Map<String, String> headers,int expectedCode) {
        String body="Action=DeleteLoginProfile&UserName="+UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String CreateVirtualMFADevice(String endpointUrlStr,String regionName,String ak,String sk,String virtualMFADeviceName,Map<String, String> headers,int expectedCode) {
        String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName="+UrlEncoded.encodeString(virtualMFADeviceName);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String EnableMFADevice(String endpointUrlStr,String regionName,String ak,String sk,String userName,String accountId,String deviceName,String authenticationCode1,String authenticationCode2,Map<String, String> headers,int expectedCode) {
        System.out.println("authenticationCode1="+authenticationCode1);
        System.out.println("authenticationCode2="+authenticationCode2);
        if (authenticationCode1.length()<6) {
            int bu0=6-authenticationCode1.length();
            String prefix="";
            for (int i = 0; i < bu0; i++) {
                prefix+="0";
            }
            
            authenticationCode1=prefix+authenticationCode1;
            
        }
        
        if (authenticationCode2.length()<6) {
            int bu0=6-authenticationCode2.length();
            String prefix="";
            for (int i = 0; i < bu0; i++) {
                prefix+="0";
            }
            
            authenticationCode2=prefix+authenticationCode2;
            
        }
        
        String serialNumber="arn:ctyun:iam::"+accountId+":mfa/"+deviceName;
        String body="Action=EnableMFADevice&Version=2010-05-08&UserName="+UrlEncoded.encodeString(userName)+"&SerialNumber="+UrlEncoded.encodeString(serialNumber)+"&AuthenticationCode1="+authenticationCode1+"&AuthenticationCode2="+authenticationCode2;
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String DeactivateMFADevice(String endpointUrlStr,String regionName,String ak,String sk,String userName,String accountId,String deviceName,Map<String, String> headers,int expectedCode) {
        String serialNumber="arn:ctyun:iam::"+accountId+":mfa/"+deviceName;
        String body="Action=DeactivateMFADevice&Version=2010-05-08&UserName="+UrlEncoded.encodeString(userName)+"&SerialNumber="+UrlEncoded.encodeString(serialNumber);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String DeleteAccountPasswordPolicy(String endpointUrlStr,String regionName,String ak,String sk,Map<String, String> headers,int expectedCode) {
        String body="Action=DeleteAccountPasswordPolicy&Version=2010-05-08";
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String DeleteVirtualMFADevice(String endpointUrlStr,String regionName,String ak,String sk,String accountId,String deviceName,Map<String, String> headers,int expectedCode) {
        String serialNumber="arn:ctyun:iam::"+accountId+":mfa/"+deviceName;
        String body="Action=DeleteVirtualMFADevice&SerialNumber="+UrlEncoded.encodeString(serialNumber);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String UpdateAccountPasswordPolicy(String endpointUrlStr,String regionName,String ak,String sk,Map<String, String> headers,int expectedCode) {
        String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08";
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        return result.second();    
    }
    
    public static String GetAccountPasswordPolicy(String endpointUrlStr,String regionName,String ak,String sk,Map<String, String> headers,int expectedCode) {
        String body="Action=GetAccountPasswordPolicy&Version=2010-05-08";
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String GetLoginProfile(String endpointUrlStr,String regionName,String ak,String sk,String userName,Map<String, String> headers,int expectedCode) {
        String body="Action=GetLoginProfile&UserName="+UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String ListVirtualMFADevices(String endpointUrlStr,String regionName,String ak,String sk,Map<String, String> headers,int expectedCode) {
        String body="Action=ListVirtualMFADevices&Version=2010-05-08";
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    public static String ListMFADevices(String endpointUrlStr,String regionName,String ak,String sk, String userName, Map<String, String> headers,int expectedCode) {
        String body="Action=ListMFADevices&Version=2010-05-08&UserName=" + UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String CreatePolicy(String endpointUrlStr,String regionName,String ak,String sk,String policyName,String policyString,Map<String, String> headers,int expectedCode) {
        String body="Action=CreatePolicy&Version=2010-05-08&PolicyName="+UrlEncoded.encodeString(policyName)+"&PolicyDocument="+UrlEncoded.encodeString(policyString);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();   
    }
    
    public static String DeletePolicy(String endpointUrlStr,String regionName,String ak,String sk,String accountId,String policyName,Map<String, String> headers,int expectedCode) {
        String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
        String body="Action=DeletePolicy&Version=2010-05-08&PolicyArn="+UrlEncoded.encodeString(policyArn);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();
    }
    
    public static String AttachUserPolicy(String endpointUrlStr,String regionName,String ak,String sk,String accountId,String userName,String policyName,Map<String, String> headers,int expectedCode) {
        String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
        String body="Action=AttachUserPolicy&Version=2010-05-08&UserName="+ UrlEncoded.encodeString(userName) +"&PolicyArn="+UrlEncoded.encodeString(policyArn);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();
    }
    
    public static String AttachGroupPolicy(String endpointUrlStr,String regionName,String ak,String sk,String accountId,String groupName,String policyName,Map<String, String> headers,int expectedCode) {
        String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
        String body="Action=AttachGroupPolicy&Version=2010-05-08&GroupName="+ UrlEncoded.encodeString(groupName) +"&PolicyArn="+UrlEncoded.encodeString(policyArn);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();   
    }

    public static String DetachGroupPolicy(String endpointUrlStr,String regionName,String ak,String sk,String accountId,String groupName,String policyName,Map<String, String> headers,int expectedCode) {
        String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
        String body="Action=DetachGroupPolicy&Version=2010-05-08&GroupName="+ UrlEncoded.encodeString(groupName) +"&PolicyArn="+UrlEncoded.encodeString(policyArn);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String DetachUserPolicy(String endpointUrlStr,String regionName,String ak,String sk,String accountId,String userName,String policyName,Map<String, String> headers,int expectedCode) {
        String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
        String body="Action=DetachUserPolicy&Version=2010-05-08&UserName="+ UrlEncoded.encodeString(userName)+"&PolicyArn="+UrlEncoded.encodeString(policyArn);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String GetPolicy(String endpointUrlStr,String regionName,String ak,String sk,String accountId,String policyName,Map<String, String> headers,int expectedCode) {
        String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
        String body="Action=GetPolicy&Version=2010-05-08&PolicyArn="+UrlEncoded.encodeString(policyArn);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String ListAttachedGroupPolicies(String endpointUrlStr,String regionName,String ak,String sk,String groupName,Map<String, String> headers,int expectedCode) {
        String body = "Action=ListAttachedGroupPolicies&Version=2010-05-08&GroupName=" + UrlEncoded.encodeString(groupName);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second(); 
    }
    
    public static String CreateMFADevice(String endpointUrlStr,String regionName,String ak,String sk,String VirtualMFADeviceName,Map<String, String> headers,int expectedCode) {
        String body = "Action=CreateVirtualMFADevice&VirtualMFADeviceName=" + VirtualMFADeviceName;
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second(); 
    }

    public static String ListAttachedUserPolicies(String endpointUrlStr,String regionName,String ak,String sk,String userName,Map<String, String> headers,int expectedCode) {
        String body = "Action=ListAttachedUserPolicies&Version=2010-05-08&UserName=" + UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second(); 
    }
    
    public static String ListEntitiesForPolicy(String endpointUrlStr,String regionName,String ak,String sk,String accountId,String policyName,Map<String, String> headers,int expectedCode) {
        String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
        String body="Action=ListEntitiesForPolicy&Version=2010-05-08&PolicyArn="+UrlEncoded.encodeString(policyArn);
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String ListPolicies(String endpointUrlStr,String regionName,String ak,String sk,Map<String, String> headers,int expectedCode) {
        String body= "Action=ListPolicies&Version=2010-05-08";
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second(); 
    }
    
    public static String GetAccountSummary(String endpointUrlStr,String regionName,String ak,String sk,Map<String, String> headers,int expectedCode) {
        String body="Action=GetAccountSummary&Version=2010-05-08";
        Pair<Integer,String> result=IAMRequest(endpointUrlStr,regionName,ak,sk,body,headers);
        assertEquals(expectedCode, result.first().intValue());
        return result.second(); 
    }
    
    public static Pair<Integer, String> IAMRequest(String endpointUrlStr,String regionName,String accessKey,String secretKey,String body,Map<String, String> headers) {
        Pair<Integer, String> result=new Pair<Integer, String>();
        try {
            URL url = new URL(endpointUrlStr);
            if (headers==null) {
                headers = new HashMap<String, String>();
            }
            headers.put("Content-Type", "application/x-www-form-urlencoded");
//            headers.put("Content-Type", "application/octet-stream;charset=utf-8");
            
            String authorization = V4SignClient.computeV4SignatureDefalut(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                    url, "POST", "sts", regionName);
            if (accessKey!=null) {
                headers.put("Authorization", authorization);
            }
            
            
            HttpsURLConnection connection = HttpConnectionSSLRequestUtils.createhttpsConn(url, "POST", headers);
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
            
        } catch (Exception e) {
            // TODO: handle exception
            e.printStackTrace();
        }
        
        return result;
    }
}
