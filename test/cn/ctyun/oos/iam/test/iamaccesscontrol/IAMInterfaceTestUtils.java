package cn.ctyun.oos.iam.test.iamaccesscontrol;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.StringReader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;
import org.apache.hadoop.ha.SshFenceByTcpPort;
import org.eclipse.jetty.util.UrlEncoded;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.xml.sax.InputSource;

import cn.ctyun.oos.hbase.HBaseUtil;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.server.entity.Group;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import common.tuple.Pair;

public class IAMInterfaceTestUtils {
    
    public static String CreateGroup(String ak,String sk,String groupName,int expectedCode) {
        String body="Action=CreateGroup&Version=2010-05-08&GroupName="+UrlEncoded.encodeString(groupName);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String DeleteGroup(String ak,String sk,String groupName,int expectedCode) {
        String body="Action=DeleteGroup&Version=2010-05-08&GroupName="+UrlEncoded.encodeString(groupName); 
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second(); 
    }
    
    public static String GetGroup(String ak,String sk,String groupName,int expectedCode) {
        String body="Action=GetGroup&Version=2010-05-08&GroupName="+UrlEncoded.encodeString(groupName); 
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);  
        assertEquals(expectedCode, result.first().intValue());
        return result.second(); 
    }
    
    public static String ListGroups(String ak,String sk,String groupName,int expectedCode) {
        String body="Action=ListGroups&Version=2010-05-08"; 
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();
    }
    
    public static String AddUserToGroup(String ak,String sk,String groupName,String userName,int expectedCode) {
        String body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+UrlEncoded.encodeString(groupName)+"&UserName="+UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();
    }
    
    public static String RemoveUserFromGroup(String ak,String sk,String groupName,String userName,int expectedCode) {
        String body="Action=RemoveUserFromGroup&Version=2010-05-08&GroupName="+UrlEncoded.encodeString(groupName)+"&UserName="+UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();
  
    }
    
    public static String CreateUser(String ak,String sk,String userName,int expectedCode) {
        String body="Action=CreateUser&Version=2010-05-08&UserName="+UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String DeleteUser(String ak,String sk,String userName,int expectedCode) {
        String body="Action=DeleteUser&UserName="+UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String GetUser(String ak,String sk,String userName,int expectedCode) {
        String body="Action=GetUser&UserName="+UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String ListUsers(String ak,String sk,int expectedCode) {
        String body="Action=ListUsers&Version=2010-05-08";
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String ListUserTags(String ak,String sk,String userName,int expectedCode) {
        String body="Action=ListUserTags&Version=2010-05-08&UserName="+UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String TagUser(String ak,String sk,String userName, List<Pair<String, String>> tags,int expectedCode) {
        String tagString="";
        for (int i = 1; i < tags.size()+1; i++) {
            tagString+="&Tags.member."+i+".Key="+tags.get(i-1).first()+"&Tags.member."+i+".Value="+tags.get(i-1).second();
        }
        
//        System.out.println(tagString);
        String body="Action=TagUser&Version=2010-05-08&UserName="+UrlEncoded.encodeString(userName)+tagString;
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String UntagUser(String ak,String sk,String userName, List<String> tagKeys,int expectedCode) {
        String untagString="";
        for (int i = 1; i < tagKeys.size(); i++) {
            untagString+="&TagKeys.member."+i+"="+tagKeys.get(i-1);
        }
        
        System.out.println(untagString);
        String body="Action=UntagUser&Version=2010-05-08&UserName="+UrlEncoded.encodeString(userName)+untagString;
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String ListGroupsForUser(String ak,String sk,String userName,int expectedCode) {
        String body="Action=ListGroupsForUser&Version=2010-05-08&UserName="+UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String CreateAccessKey(String ak,String sk,String userName,int expectedCode) {
        String body="Action=CreateAccessKey&UserName="+UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String DeleteAccessKey(String ak,String sk,String akId,String userName,int expectedCode) {
        String body="Action=DeleteAccessKey&AccessKeyId="+akId+"&UserName="+UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String ListAccessKeys(String ak,String sk,String userName,int expectedCode) {
        String body="Action=ListAccessKeys&UserName="+UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String UpdateAccessKey(String ak,String sk,String akId,String userName,String status,int expectedCode) {
        String body="Status="+status+"&Action=UpdateAccessKey&AccessKeyId="+akId+"&UserName="+UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String GetAccessKeyLastUsed(String ak,String sk,String akId,int expectedCode) {
        String body="Action=GetAccessKeyLastUsed&AccessKeyId="+akId;
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String ChangePassword(String ak,String sk,String userName,String oldPassword,String newPassword,int expectedCode) {
        String body="Action=ChangePassword&UserName="+UrlEncoded.encodeString(userName)+"&OldPassword="+oldPassword+"&NewPassword="+newPassword;
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String CreateLoginProfile(String ak,String sk,String userName,String newPassword,int expectedCode) {
        String body="Action=CreateLoginProfile&UserName="+UrlEncoded.encodeString(userName)+"&Password="+newPassword;
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String UpdateLoginProfile(String ak,String sk,String userName,String newPassword,int expectedCode) {
        String body="Action=UpdateLoginProfile&UserName="+UrlEncoded.encodeString(userName)+"&Password="+newPassword;
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String DeleteLoginProfile(String ak,String sk,String userName,int expectedCode) {
        String body="Action=DeleteLoginProfile&UserName="+UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String CreateVirtualMFADevice(String ak,String sk,String virtualMFADeviceName,int expectedCode) {
        String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName="+UrlEncoded.encodeString(virtualMFADeviceName);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String EnableMFADevice(String ak,String sk,String userName,String accountId,String deviceName,String authenticationCode1,String authenticationCode2,int expectedCode) {
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
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String DeactivateMFADevice(String ak,String sk,String userName,String accountId,String deviceName,int expectedCode) {
        String serialNumber="arn:ctyun:iam::"+accountId+":mfa/"+deviceName;
        String body="Action=DeactivateMFADevice&Version=2010-05-08&UserName="+UrlEncoded.encodeString(userName)+"&SerialNumber="+UrlEncoded.encodeString(serialNumber);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String DeleteAccountPasswordPolicy(String ak,String sk,int expectedCode) {
        String body="Action=DeleteAccountPasswordPolicy&Version=2010-05-08";
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String DeleteVirtualMFADevice(String ak,String sk,String accountId,String deviceName,int expectedCode) {
        String serialNumber="arn:ctyun:iam::"+accountId+":mfa/"+deviceName;
        String body="Action=DeleteVirtualMFADevice&SerialNumber="+UrlEncoded.encodeString(serialNumber);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String UpdateAccountPasswordPolicy(String ak,String sk,int expectedCode) {
        String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08";
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String GetAccountPasswordPolicy(String ak,String sk,int expectedCode) {
        String body="Action=GetAccountPasswordPolicy&Version=2010-05-08";
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String GetLoginProfile(String ak,String sk,String userName,int expectedCode) {
        String body="Action=GetLoginProfile&UserName="+UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String ListVirtualMFADevices(String ak,String sk,int expectedCode) {
        String body="Action=ListVirtualMFADevices&Version=2010-05-08";
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    public static String ListMFADevices(String ak,String sk, String userName, int expectedCode) {
        String body="Action=ListMFADevices&Version=2010-05-08&UserName=" + UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String CreatePolicy(String ak,String sk,String policyName,String policyString,int expectedCode) {
        String body="Action=CreatePolicy&Version=2010-05-08&PolicyName="+UrlEncoded.encodeString(policyName)+"&PolicyDocument="+UrlEncoded.encodeString(policyString);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();   
    }
    
    public static String DeletePolicy(String ak,String sk,String accountId,String policyName,int expectedCode) {
        String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
        String body="Action=DeletePolicy&Version=2010-05-08&PolicyArn="+UrlEncoded.encodeString(policyArn);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();
    }
    
    public static String AttachUserPolicy(String ak,String sk,String accountId,String userName,String policyName,int expectedCode) {
        String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
        String body="Action=AttachUserPolicy&Version=2010-05-08&UserName="+ UrlEncoded.encodeString(userName) +"&PolicyArn="+UrlEncoded.encodeString(policyArn);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();
    }
    
    public static String AttachGroupPolicy(String ak,String sk,String accountId,String groupName,String policyName,int expectedCode) {
        String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
        String body="Action=AttachGroupPolicy&Version=2010-05-08&GroupName="+ UrlEncoded.encodeString(groupName) +"&PolicyArn="+UrlEncoded.encodeString(policyArn);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();   
    }

    public static String DetachGroupPolicy(String ak,String sk,String accountId,String groupName,String policyName,int expectedCode) {
        String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
        String body="Action=DetachGroupPolicy&Version=2010-05-08&GroupName="+ UrlEncoded.encodeString(groupName) +"&PolicyArn="+UrlEncoded.encodeString(policyArn);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String DetachUserPolicy(String ak,String sk,String accountId,String userName,String policyName,int expectedCode) {
        String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
        String body="Action=DetachUserPolicy&Version=2010-05-08&UserName="+ UrlEncoded.encodeString(userName)+"&PolicyArn="+UrlEncoded.encodeString(policyArn);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String GetPolicy(String ak,String sk,String accountId,String policyName,int expectedCode) {
        String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
        String body="Action=GetPolicy&Version=2010-05-08&PolicyArn="+UrlEncoded.encodeString(policyArn);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String ListAttachedGroupPolicies(String ak,String sk,String groupName,int expectedCode) {
        String body = "Action=ListAttachedGroupPolicies&Version=2010-05-08&GroupName=" + UrlEncoded.encodeString(groupName);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second(); 
    }
    
    public static String CreateMFADevice(String ak,String sk,String VirtualMFADeviceName,int expectedCode) {
        String body = "Action=CreateVirtualMFADevice&VirtualMFADeviceName=" + VirtualMFADeviceName;
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second(); 
    }

    public static String ListAttachedUserPolicies(String ak,String sk,String userName,int expectedCode) {
        String body = "Action=ListAttachedUserPolicies&Version=2010-05-08&UserName=" + UrlEncoded.encodeString(userName);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second(); 
    }
    
    public static String ListEntitiesForPolicy(String ak,String sk,String accountId,String policyName,int expectedCode) {
        String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
        String body="Action=ListEntitiesForPolicy&Version=2010-05-08&PolicyArn="+UrlEncoded.encodeString(policyArn);
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String ListPolicies(String ak,String sk,int expectedCode) {
        String body= "Action=ListPolicies&Version=2010-05-08";
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second(); 
    }
    
    public static String GetAccountSummary(String ak,String sk,int expectedCode) {
        String body="Action=GetAccountSummary&Version=2010-05-08";
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second(); 
    }
    
    /*
     * 对应资源为MFA/<mfa>
     * 如果排除验证CreateVirtualMFADevice需要提供rootAK，其他默认rootAK为null
     */
    public static void AllowActionResourceMFA(String rootAK,String rootSK,List<String> excludes,String ak,String sk,String accountId,String deviceName) {
        List<String> successList= new ArrayList<String>();
        List<String> accessDenyList= new ArrayList<String>();
        if (excludes!=null&&excludes.contains("CreateVirtualMFADevice")) {
            CreateVirtualMFADevice(ak, sk, deviceName, 403);
            CreateVirtualMFADevice(rootAK, rootSK, deviceName, 200);
            accessDenyList.add("CreateVirtualMFADevice");  
        }else {
            CreateVirtualMFADevice(ak, sk, deviceName, 200);
            successList.add("CreateVirtualMFADevice");
        }
        if (excludes!=null&&excludes.contains("DeleteVirtualMFADevice")) {
            DeleteVirtualMFADevice(ak, sk, accountId, deviceName, 403);
            accessDenyList.add("DeleteVirtualMFADevice");
        }else {
            DeleteVirtualMFADevice(ak, sk, accountId, deviceName, 200);
            successList.add("DeleteVirtualMFADevice");
        }
        
        if (excludes!=null&&successList!=null&&successList.size()>0) {
            System.out.println("Allow Method:");
            System.out.println(successList.toString());
        }
        
        if (excludes!=null&&accessDenyList!=null&&accessDenyList.size()>0) {
            System.out.println("AccessDeny Method:");
            System.out.println(accessDenyList.toString());
        }

    }
    
    
    public static void AllowActionResourceMFA_userResource(String rootAK,String rootSK,List<String> excludes,String ak,String sk,String accountId,String deviceName) {
        List<String> successList= new ArrayList<String>();
        List<String> accessDenyList= new ArrayList<String>();
        if (excludes!=null&&excludes.contains("CreateVirtualMFADevice")) {
            CreateVirtualMFADevice(ak, sk, deviceName, 403);
            CreateVirtualMFADevice(rootAK, rootSK, deviceName, 200);
            accessDenyList.add("CreateVirtualMFADevice");  
        }else {
            CreateVirtualMFADevice(ak, sk, deviceName, 403);
            CreateVirtualMFADevice(rootAK, rootSK, deviceName, 200);
            accessDenyList.add("CreateVirtualMFADevice");
        }
        if (excludes!=null&&excludes.contains("DeleteVirtualMFADevice")) {
            DeleteVirtualMFADevice(ak, sk, accountId, deviceName, 403);
            DeleteVirtualMFADevice(rootAK, rootSK, accountId, deviceName, 200);
            accessDenyList.add("DeleteVirtualMFADevice");
        }else {
        	DeleteVirtualMFADevice(ak, sk, accountId, deviceName, 403);
        	DeleteVirtualMFADevice(rootAK, rootSK, accountId, deviceName, 200);
            accessDenyList.add("DeleteVirtualMFADevice");
        }
        
        if (excludes!=null&&successList!=null&&successList.size()>0) {
            System.out.println("Allow Method:");
            System.out.println(successList.toString());
        }
        
        if (excludes!=null&&accessDenyList!=null&&accessDenyList.size()>0) {
            System.out.println("AccessDeny Method:");
            System.out.println(accessDenyList.toString());
        }

    }
    
    
    
    /*
     * 对应资源为MFA/*
     * 如果排除验证CreateVirtualMFADevice需要提供rootAK，其他默认rootAK为null
     */
    public static void AllowActionResourceMFAALL(String rootAK,String rootSK,List<String> excludes,String ak,String sk,String accountId,String deviceName) {
        List<String> successList= new ArrayList<String>();
        List<String> accessDenyList= new ArrayList<String>();
        if (excludes!=null&&excludes.contains("CreateVirtualMFADevice")) {
            CreateVirtualMFADevice(ak, sk, deviceName, 403);
            CreateVirtualMFADevice(rootAK, rootSK, deviceName, 200);
            accessDenyList.add("CreateVirtualMFADevice");  
        }else {
            CreateVirtualMFADevice(ak, sk, deviceName, 200);
            successList.add("CreateVirtualMFADevice");
        }
        if (excludes!=null&&excludes.contains("ListVirtualMFADevices")) {
            ListVirtualMFADevices(ak, sk, 403);
            accessDenyList.add("ListVirtualMFADevices");
        }else {
            ListVirtualMFADevices(ak, sk, 200);
            successList.add("ListVirtualMFADevices");
        }
        if (excludes!=null&&excludes.contains("DeleteVirtualMFADevice")) {
            DeleteVirtualMFADevice(ak, sk, accountId, deviceName, 403);
            accessDenyList.add("DeleteVirtualMFADevice");
        }else {
            DeleteVirtualMFADevice(ak, sk, accountId, deviceName, 200);
            successList.add("DeleteVirtualMFADevice");
        }
        
        if (excludes!=null&&successList!=null&&successList.size()>0) {
            System.out.println("Allow Method:");
            System.out.println(successList.toString());
        }
        
        if (excludes!=null&&accessDenyList!=null&&accessDenyList.size()>0) {
            System.out.println("AccessDeny Method:");
            System.out.println(accessDenyList.toString());
        }

    }
    
    public static void AllowActionResourceMFAALL_userResource(String rootAK,String rootSK,List<String> excludes,String ak,String sk,String accountId,String deviceName) {
        List<String> successList= new ArrayList<String>();
        List<String> accessDenyList= new ArrayList<String>();
        if (excludes!=null&&excludes.contains("CreateVirtualMFADevice")) {
            CreateVirtualMFADevice(ak, sk, deviceName, 403);
            CreateVirtualMFADevice(rootAK, rootSK, deviceName, 200);
            accessDenyList.add("CreateVirtualMFADevice");  
        }else {
        	CreateVirtualMFADevice(ak, sk, deviceName, 403);
            CreateVirtualMFADevice(rootAK, rootSK, deviceName, 200);
            accessDenyList.add("CreateVirtualMFADevice"); 
        }
        if (excludes!=null&&excludes.contains("ListVirtualMFADevices")) {
            ListVirtualMFADevices(ak, sk, 403);
            accessDenyList.add("ListVirtualMFADevices");
        }else {
        	ListVirtualMFADevices(ak, sk, 403);
            accessDenyList.add("ListVirtualMFADevices");
        }
        if (excludes!=null&&excludes.contains("DeleteVirtualMFADevice")) {
            DeleteVirtualMFADevice(ak, sk, accountId, deviceName, 403);
            DeleteVirtualMFADevice(rootAK, rootSK, accountId, deviceName, 200);
            accessDenyList.add("DeleteVirtualMFADevice");
        }else {
        	DeleteVirtualMFADevice(ak, sk, accountId, deviceName, 403);
            DeleteVirtualMFADevice(rootAK, rootSK, accountId, deviceName, 200);
            accessDenyList.add("DeleteVirtualMFADevice");
        }
        
        if (excludes!=null&&successList!=null&&successList.size()>0) {
            System.out.println("Allow Method:");
            System.out.println(successList.toString());
        }
        
        if (excludes!=null&&accessDenyList!=null&&accessDenyList.size()>0) {
            System.out.println("AccessDeny Method:");
            System.out.println(accessDenyList.toString());
        }

    }
    
    
    
    /*
     * 对应资源为MFA/<mfa>
     * 如果排除验证CreateVirtualMFADevice需要提供rootAK，其他默认rootAK为null
     */
    public static void DenyActionResourceMFA(String rootAK,String rootSK,String ak,String sk,String accountId,String deviceName) {

        CreateVirtualMFADevice(ak, sk, deviceName, 403);
        CreateVirtualMFADevice(rootAK, rootSK, deviceName, 200);
        DeleteVirtualMFADevice(ak, sk, accountId, deviceName, 403); 
        DeleteVirtualMFADevice(rootAK, rootSK, accountId, deviceName, 200);  

    }
    
    
    /*
     * 对应资源为MFA/*
     * 如果排除验证CreateVirtualMFADevice需要提供rootAK，其他默认rootAK为null
     */
    public static void DenyActionResourceMFAALL(String rootAK,String rootSK,String ak,String sk,String accountId,String deviceName) {

        CreateVirtualMFADevice(ak, sk, deviceName, 403);
        CreateVirtualMFADevice(rootAK, rootSK, deviceName, 200);
        ListVirtualMFADevices(ak, sk, 403);
        DeleteVirtualMFADevice(ak, sk, accountId, deviceName, 403);    

    }
    
    /*
     * 对应资源policy/<policy>
     */
    public static void AllowActionResourcePolicy(String rootAK,String rootSK,List<String> excludes,String ak,String sk,String policyName,String policyString,String accountId) {
        List<String> successList= new ArrayList<String>();
        List<String> accessDenyList= new ArrayList<String>();
        if (excludes!=null&&excludes.contains("CreatePolicy")) {
            CreatePolicy(ak, sk, policyName, policyString, 403);
            CreatePolicy(rootAK, rootSK, policyName, policyString, 200);
            accessDenyList.add("CreatePolicy");
        }else {
            CreatePolicy(ak, sk, policyName, policyString, 200);
            successList.add("CreatePolicy");
        }
        if (excludes!=null&&excludes.contains("GetPolicy")) {
            GetPolicy(ak, sk, accountId, policyName, 403);
            accessDenyList.add("GetPolicy");
        }else {
            GetPolicy(ak, sk, accountId, policyName, 200);
            successList.add("GetPolicy");
        }
        if (excludes!=null&&excludes.contains("ListEntitiesForPolicy")) {
            ListEntitiesForPolicy(ak, sk, accountId, policyName, 403);
            accessDenyList.add("ListEntitiesForPolicy");
        }else {
            ListEntitiesForPolicy(ak, sk, accountId, policyName, 200);
            successList.add("ListEntitiesForPolicy");
        }
        if (excludes!=null&&excludes.contains("DeletePolicy")) {
            DeletePolicy(ak, sk, accountId, policyName, 403);
            accessDenyList.add("DeletePolicy");
        }else {
            DeletePolicy(ak, sk, accountId, policyName, 200);
            successList.add("DeletePolicy");
        }
        if (successList!=null&&successList.size()>0) {
            System.out.println("Allow Method:");
            System.out.println(successList.toString());
        }
        
        if (accessDenyList!=null&&accessDenyList.size()>0) {
            System.out.println("AccessDeny Method:");
            System.out.println(accessDenyList.toString());
        }
    }
    
    /*
     * 对应资源policy/<policy>
     */
    public static void DenyActionResourcePolicy(String rootAK,String rootSK,String ak,String sk,String policyName,String policyString,String accountId) {
        CreatePolicy(ak, sk, policyName, policyString, 403);
        CreatePolicy(rootAK, rootSK, policyName, policyString, 200);
        GetPolicy(ak, sk, accountId, policyName, 403);
        ListEntitiesForPolicy(ak, sk, accountId, policyName, 403);
        DeletePolicy(ak, sk, accountId, policyName, 403);
    }
    
    /*
     * 对应资源policy/*
     */
    public static void AllowActionResourcePolicyALL(String rootAK,String rootSK,List<String> excludes,String ak,String sk,String policyName,String policyString,String accountId){  
        List<String> successList= new ArrayList<String>();
        List<String> accessDenyList= new ArrayList<String>();
        if (excludes!=null&&excludes.contains("CreatePolicy")) {
            CreatePolicy(ak, sk, policyName, policyString, 403);
            CreatePolicy(rootAK, rootSK, policyName, policyString, 200);
            accessDenyList.add("CreatePolicy");
            
        }else {
            CreatePolicy(ak, sk, policyName, policyString, 200);
            successList.add("CreatePolicy");
        }
        
        if (excludes!=null&&excludes.contains("GetPolicy")) {
            GetPolicy(ak, sk, accountId, policyName, 403);
            accessDenyList.add("GetPolicy");
        }else {
            GetPolicy(ak, sk, accountId, policyName, 200);
            successList.add("GetPolicy");
        }
        if (excludes!=null&&excludes.contains("ListEntitiesForPolicy")) {
            ListEntitiesForPolicy(ak, sk, accountId, policyName, 403);
            accessDenyList.add("ListEntitiesForPolicy");
        }else {
            ListEntitiesForPolicy(ak, sk, accountId, policyName, 200);
            successList.add("ListEntitiesForPolicy");
        }
        if (excludes!=null&&excludes.contains("ListPolicies")) {
            ListPolicies(ak, sk, 403);
            accessDenyList.add("ListPolicies");
        }else {
            ListPolicies(ak, sk, 200); 
            successList.add("ListPolicies");
        }
        if (excludes!=null&&excludes.contains("DeletePolicy")) {
            DeletePolicy(ak, sk, accountId, policyName, 403);
            accessDenyList.add("DeletePolicy");
        }else {
            DeletePolicy(ak, sk, accountId, policyName, 200);
            successList.add("DeletePolicy");
        }  
        
        if (successList!=null&&successList.size()>0) {
            System.out.println("Allow Method:");
            System.out.println(successList.toString());
        }
        
        if (accessDenyList!=null&&accessDenyList.size()>0) {
            System.out.println("AccessDeny Method:");
            System.out.println(accessDenyList.toString());
        }
    }
    
    /*
     * 对应资源policy/<policy>
     */
    public static void DenyActionResourcePolicyALL(String rootAK,String rootSK,String ak,String sk,String policyName,String policyString,String accountId) {
        CreatePolicy(ak, sk, policyName, policyString, 403);
        CreatePolicy(rootAK, rootSK, policyName, policyString, 200);
        GetPolicy(ak, sk, accountId, policyName, 403);
        ListPolicies(ak, sk, 403);
        ListEntitiesForPolicy(ak, sk, accountId, policyName, 403);
        DeletePolicy(ak, sk, accountId, policyName, 403);
    }
    
    /*
     * 对应资源group/<groupname>
     */
    public static void AllowActionResourceGroup(String rootAK,String rootSK,List<String> excludes,String ak,String sk,String groupName,String userName,String accountId,String policyName,String policyString) {
        List<String> successList= new ArrayList<String>();
        List<String> accessDenyList= new ArrayList<String>();
        Group group=new Group();
        group.accountId=accountId;
        group.groupName=groupName;
        boolean exist=false;
        try {
			exist=HBaseUtils.exist(group);
		} catch (IOException e) {
			e.printStackTrace();
		}
        if (excludes!=null&&excludes.contains("CreateGroup")) {
            if(!exist) {
            	CreateGroup(ak, sk, groupName, 403);
            	CreateGroup(rootAK, rootSK, groupName, 200);
            	accessDenyList.add("CreateGroup");
            }
        }else {
        	if(!exist) {
        		CreateGroup(ak, sk, groupName, 200);
        		successList.add("CreateGroup");
        	}
        }
        if (excludes!=null&&excludes.contains("GetGroup")) {
            GetGroup(ak, sk, groupName, 403);
            accessDenyList.add("GetGroup");
        }else {
            GetGroup(ak, sk, groupName, 200);
            successList.add("GetGroup");
        }
        
        if (excludes!=null&&excludes.contains("AddUserToGroup")) {
            AddUserToGroup(ak, sk, groupName, userName, 403);
            accessDenyList.add("AddUserToGroup");
        }else {
            AddUserToGroup(ak, sk, groupName, userName, 200);
            successList.add("AddUserToGroup");
        }
        
        if (excludes!=null&&excludes.contains("RemoveUserFromGroup")) {
            RemoveUserFromGroup(ak, sk, groupName, userName, 403);
            accessDenyList.add("RemoveUserFromGroup");
        }else {
            RemoveUserFromGroup(ak, sk, groupName, userName, 200);
            successList.add("RemoveUserFromGroup");
        }
        
        // root 创建policy
        CreatePolicy(rootAK, rootSK, policyName, policyString, 200);
        
        if (excludes!=null&&excludes.contains("AttachGroupPolicy")) {
            AttachGroupPolicy(ak, sk, accountId, groupName, policyName, 403);
            AttachGroupPolicy(rootAK, rootSK, accountId, groupName, policyName, 200);
            accessDenyList.add("AttachGroupPolicy");
        }else {
            AttachGroupPolicy(ak, sk, accountId, groupName, policyName, 200);
            successList.add("AttachGroupPolicy");
        }
        if (excludes!=null&&excludes.contains("ListAttachedGroupPolicies")) {
            ListAttachedGroupPolicies(ak, sk, groupName, 403);
            accessDenyList.add("ListAttachedGroupPolicies");
        }else {
            ListAttachedGroupPolicies(ak, sk, groupName, 200);
            successList.add("ListAttachedGroupPolicies");
        }
        if (excludes!=null&&excludes.contains("DetachGroupPolicy")) {
            DetachGroupPolicy(ak, sk, accountId, groupName, policyName, 403);
            DetachGroupPolicy(rootAK, rootSK, accountId, groupName, policyName, 200);
            accessDenyList.add("DetachGroupPolicy");
        }else {
            DetachGroupPolicy(ak, sk, accountId, groupName, policyName, 200);
            successList.add("DetachGroupPolicy");
        }
        
        if (excludes!=null&&excludes.contains("DeleteGroup")) {
            DeleteGroup(ak, sk, groupName, 403);
            accessDenyList.add("DeleteGroup");
        }else {
            DeleteGroup(ak, sk, groupName, 200);
            successList.add("DeleteGroup");
        }
        
        if (successList!=null&&successList.size()>0) {
            System.out.println("Allow Method:");
            System.out.println(successList.toString());
        }
        
        if (accessDenyList!=null&&accessDenyList.size()>0) {
            System.out.println("AccessDeny Method:");
            System.out.println(accessDenyList.toString());
        }
    }
    
    /*
     * 对应资源group/*
     */
    public static void AllowActionResourceGroupALL(String rootAK,String rootSK,List<String> excludes,String ak,String sk,String groupName,String userName,String accountId,String policyName,String policyString) {
        List<String> successList= new ArrayList<String>();
        List<String> accessDenyList= new ArrayList<String>();
        if (excludes!=null&&excludes.contains("CreateGroup")) {
            CreateGroup(ak, sk, groupName, 403);
            CreateGroup(rootAK, rootSK, groupName, 200);
            accessDenyList.add("CreateGroup");
        }else {
            CreateGroup(ak, sk, groupName, 200);
            successList.add("CreateGroup");
        }
        if (excludes!=null&&excludes.contains("GetGroup")) {
            GetGroup(ak, sk, groupName, 403);
            accessDenyList.add("GetGroup");
        }else {
            GetGroup(ak, sk, groupName, 200);
            successList.add("GetGroup");
        }
        if (excludes!=null&&excludes.contains("ListGroups")) {
            ListGroups(ak, sk, groupName, 403);
            accessDenyList.add("ListGroups");
        }else {
            ListGroups(ak, sk, groupName, 200);
            successList.add("ListGroups");
        }
        User user = new User();
        user.accountId = accountId;
        user.userName = userName;
        try {
            User userExist=HBaseUtils.get(user);
            if (userExist==null) {
                CreateUser(rootAK, rootSK, userName, 200);
            }
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        if (excludes!=null&&excludes.contains("AddUserToGroup")) {
            AddUserToGroup(ak, sk, groupName, userName, 403);
            accessDenyList.add("AddUserToGroup");
        }else {
            AddUserToGroup(ak, sk, groupName, userName, 200);
            successList.add("AddUserToGroup");
        }
        
        if (excludes!=null&&excludes.contains("RemoveUserFromGroup")) {
            RemoveUserFromGroup(ak, sk, groupName, userName, 403);
            accessDenyList.add("RemoveUserFromGroup");
        }else {
            RemoveUserFromGroup(ak, sk, groupName, userName, 200);
            successList.add("RemoveUserFromGroup");
        }
        
        // root 创建policy
        CreatePolicy(rootAK, rootSK, policyName, policyString, 200);
        
        if (excludes!=null&&excludes.contains("AttachGroupPolicy")) {
            AttachGroupPolicy(ak, sk, accountId, groupName, policyName, 403);
            AttachGroupPolicy(rootAK, rootSK, accountId, groupName, policyName, 200);
            accessDenyList.add("AttachGroupPolicy");
        }else {
            AttachGroupPolicy(ak, sk, accountId, groupName, policyName, 200);
            successList.add("AttachGroupPolicy");
        }
        if (excludes!=null&&excludes.contains("ListAttachedGroupPolicies")) {
            ListAttachedGroupPolicies(ak, sk, groupName, 403);
            accessDenyList.add("ListAttachedGroupPolicies");
        }else {
            ListAttachedGroupPolicies(ak, sk, groupName, 200);
            successList.add("ListAttachedGroupPolicies");
        }
        if (excludes!=null&&excludes.contains("DetachGroupPolicy")) {
            DetachGroupPolicy(ak, sk, accountId, groupName, policyName, 403);
            accessDenyList.add("DetachGroupPolicy");
        }else {
            DetachGroupPolicy(ak, sk, accountId, groupName, policyName, 200);
            successList.add("DetachGroupPolicy");
        }
        
        if (excludes!=null&&excludes.contains("DeleteGroup")) {
            DeleteGroup(ak, sk, groupName, 403);
            accessDenyList.add("DeleteGroup");
        }else {
            DeleteGroup(ak, sk, groupName, 200);
            successList.add("DeleteGroup");
        }
        
        if (successList!=null&&successList.size()>0) {
            System.out.println("Allow Method:");
            System.out.println(successList.toString());
        }
        
        if (accessDenyList!=null&&accessDenyList.size()>0) {
            System.out.println("AccessDeny Method:");
            System.out.println(accessDenyList.toString());
        }  
    }
    
    /*
     * 对应资源group/<group>
     */
    public static void DenyActionResourceGroup(String rootAK,String rootSK,String ak,String sk,String groupName,String userName,String accountId,String policyName,String policyString) {

    	Group group=new Group();
        group.accountId=accountId;
        group.groupName=groupName;
        boolean exist=false;
        try {
			exist=HBaseUtils.exist(group);
		} catch (IOException e) {
			e.printStackTrace();
		}
       if(!exist) {
    	   CreateGroup(ak, sk, groupName, 403);
    	   CreateGroup(rootAK, rootSK, groupName, 200);
       }
        GetGroup(ak, sk, groupName, 403);
        AddUserToGroup(ak, sk, groupName, userName, 403);
        RemoveUserFromGroup(ak, sk, groupName, userName, 403);
        // root 创建policy
        CreatePolicy(rootAK, rootSK, policyName, policyString, 200);
        AttachGroupPolicy(ak, sk, accountId, groupName, policyName, 403);
        AttachGroupPolicy(rootAK, rootSK, accountId, groupName, policyName, 200);
        ListAttachedGroupPolicies(ak, sk, groupName, 403);
        DetachGroupPolicy(ak, sk, accountId, groupName, policyName, 403);
        DeleteGroup(ak, sk, groupName, 403);

    }
    
    /*
     * 对应资源group/*
     */
    public static void DenyActionResourceGroupALL(String rootAK,String rootSK,String ak,String sk,String groupName,String userName,String accountId,String policyName,String policyString) {
    	
    	 Group group=new Group();
         group.accountId=accountId;
         group.groupName=groupName;
         boolean exist=false;
         try {
 			exist=HBaseUtils.exist(group);
 		} catch (IOException e) {
 			e.printStackTrace();
 		}
        if(!exist) {
        	CreateGroup(ak, sk, groupName, 403);
        	CreateGroup(rootAK, rootSK, groupName, 200);
        }
        GetGroup(ak, sk, groupName, 403);
        ListGroups(ak, sk, groupName, 403);
        AddUserToGroup(ak, sk, groupName, userName, 403);
        RemoveUserFromGroup(ak, sk, groupName, userName, 403);
        // root 创建policy
        CreatePolicy(rootAK, rootSK, policyName, policyString, 200);
        AttachGroupPolicy(ak, sk, accountId, groupName, policyName, 403);
        AttachGroupPolicy(rootAK, rootSK, accountId, groupName, policyName, 200);
        ListAttachedGroupPolicies(ak, sk, groupName, 403);
        DetachGroupPolicy(ak, sk, accountId, groupName, policyName, 403);
        DeleteGroup(ak, sk, groupName, 403);
    }
    
    /*
     * 对应资源user/<username>
     */
    public static void AllowActionResourceUser(String rootAK,String rootSK,List<String> excludes,String ak,String sk,String userName,List<Pair<String, String>> tags,String policyName, String policyString,String accountId) {
        List<String> successList= new ArrayList<String>();
        List<String> accessDenyList= new ArrayList<String>();
        User user=new User();
        user.accountId=accountId;
        user.userName=userName;
        boolean exist1=false;
        try {
            exist1=HBaseUtils.exist(user);
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (excludes!=null&&excludes.contains("CreateUser")) {
            if(!exist1) {
	        	CreateUser(ak, sk, userName, 403);
	            CreateUser(rootAK, rootSK, userName, 200);
	            accessDenyList.add("CreateUser");
            }
        }else {
            if(!exist1) {
	        	CreateUser(ak, sk, userName, 200);
	            successList.add("CreateUser");
            }
        }
        if (excludes!=null&&excludes.contains("GetUser")) {
            GetUser(ak, sk, userName, 403);
            accessDenyList.add("GetUser");
        }else {
            GetUser(ak, sk, userName, 200);
            successList.add("GetUser");
        }
        if (excludes!=null&&excludes.contains("TagUser")) {
            TagUser(ak, sk, userName, tags, 403);
            TagUser(rootAK, rootSK, userName, tags, 200);
            accessDenyList.add("TagUser");
        }else {
            TagUser(ak, sk, userName, tags, 200);
            successList.add("TagUser");
        }
        if (excludes!=null&&excludes.contains("ListUserTags")) {
            ListUserTags(ak, sk, userName, 403);
            accessDenyList.add("ListUserTags");
        }else {
            ListUserTags(ak, sk, userName, 200);
            successList.add("ListUserTags");
        }
        List<String> tagKeys = new ArrayList<String>();
        for (int i = 0; i < tags.size(); i++) {
            tagKeys.add(tags.get(0).first());
        }
        if (excludes!=null&&excludes.contains("UntagUser")) {
            UntagUser(ak, sk, userName, tagKeys, 403);
            accessDenyList.add("UntagUser");
        }else {
            UntagUser(ak, sk, userName, tagKeys, 200);
            successList.add("UntagUser");
        }
        String akId="";
        AkSkMeta aksk = new AkSkMeta();
        aksk.accessKey = ak;
        MetaClient client=MetaClient.getGlobalClient();
        try {
            boolean exist = client.akskSelectWithoutCache(aksk);
            assertTrue(exist);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        if (excludes!=null&&excludes.contains("CreateAccessKey")) {
            CreateAccessKey(ak, sk, userName, 403);  
            String xmlString =CreateAccessKey(rootAK, rootSK, userName, 200);
            akId=AssertCreateAccessKey(xmlString, userName, "Active");
            accessDenyList.add("CreateAccessKey");
        }else {
            String xmlString =CreateAccessKey(ak, sk, userName, 200);
            akId=AssertCreateAccessKey(xmlString, userName, "Active");
            successList.add("CreateAccessKey");
        }
        if (excludes!=null&&excludes.contains("ListAccessKeys")) {
            ListAccessKeys(ak, sk, userName, 403);
            accessDenyList.add("ListAccessKeys");
        }else {
            ListAccessKeys(ak, sk, userName, 200);
            successList.add("ListAccessKeys");
        }
        if (excludes!=null&&excludes.contains("UpdateAccessKey")) {
            UpdateAccessKey(ak, sk, akId, userName,"Inactive", 403);
            accessDenyList.add("UpdateAccessKey");
        }else {
            UpdateAccessKey(ak, sk, akId, userName,"Inactive", 200);
            successList.add("UpdateAccessKey");
        }
        if (excludes!=null&&excludes.contains("DeleteAccessKey")) {
            DeleteAccessKey(ak, sk, akId,userName, 403);
            DeleteAccessKey(rootAK, rootSK, akId,userName, 200);
            accessDenyList.add("DeleteAccessKey");
        }else {
            DeleteAccessKey(ak, sk, akId, userName,200);
            successList.add("DeleteAccessKey");
        }
        
        if (excludes!=null&&excludes.contains("CreateLoginProfile")) {
            CreateLoginProfile(ak, sk, userName, "a12345678", 403);
            CreateLoginProfile(rootAK, rootSK, userName, "a12345678", 200);
            accessDenyList.add("CreateLoginProfile");
        }else {
            CreateLoginProfile(ak, sk, userName, "a12345678", 200);
            successList.add("CreateLoginProfile");
        }
        if (excludes!=null&&excludes.contains("GetLoginProfile")) {
            GetLoginProfile(ak, sk, userName, 403);
            accessDenyList.add("GetLoginProfile");
        }else {
            GetLoginProfile(ak, sk, userName, 200);
            successList.add("GetLoginProfile");
        }
//        if (excludes!=null&&excludes.contains("ChangePassword")) {
//            CreateLoginProfile(rootAK, rootSK, aksk.userName, "a12345678", 200);
//            ChangePassword(ak, sk, aksk.userName, "a12345678", "b1234567", 403);
//            DeleteLoginProfile(rootAK, rootSK, aksk.userName, 200);
//            accessDenyList.add("ChangePassword");
//        }else {
//            CreateLoginProfile(rootAK, rootSK, aksk.userName, "a12345678", 200);
//            ChangePassword(ak, sk, aksk.userName, "a12345678", "b1234567", 200);
//            DeleteLoginProfile(rootAK, rootSK, aksk.userName, 200);
//            successList.add("ChangePassword");
//        }
        if (excludes!=null&&excludes.contains("UpdateLoginProfile")) {
            UpdateLoginProfile(ak, sk, userName, "b987654321", 403);
            accessDenyList.add("UpdateLoginProfile");
        }else {
            UpdateLoginProfile(ak, sk, userName, "b987654321", 200);
            successList.add("UpdateLoginProfile");
        }
        if (excludes!=null&&excludes.contains("DeleteLoginProfile")) {
            DeleteLoginProfile(ak, sk, userName, 403);
            accessDenyList.add("DeleteLoginProfile");
        }else {
            DeleteLoginProfile(ak, sk, userName, 200);
            successList.add("DeleteLoginProfile");
        }
        
        
        String groupName="userResourceGroup";
        CreateGroup(rootAK, rootSK, groupName, 200);
        AddUserToGroup(rootAK, rootSK, groupName, userName, 200);
        
        if (excludes!=null&&excludes.contains("ListGroupsForUser")) {
            ListGroupsForUser(ak, sk, userName, 403);
            accessDenyList.add("ListGroupsForUser");
        }else {
            ListGroupsForUser(ak, sk, userName, 200);
            successList.add("ListGroupsForUser");
        }

        String deviceName=userName;
        String xml=CreateVirtualMFADevice(rootAK, rootSK, deviceName, 200);
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(xml,"arn:ctyun:iam::"+accountId+":mfa/"+deviceName);
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        if (excludes!=null&&excludes.contains("EnableMFADevice")) {
            EnableMFADevice(ak, sk, userName, accountId, deviceName, codesPair.first(), codesPair.second(), 403);
            accessDenyList.add("EnableMFADevice");
        }else {
            EnableMFADevice(ak, sk, userName, accountId, deviceName, codesPair.first(), codesPair.second(), 200);
            successList.add("EnableMFADevice");
        }
        
        CreatePolicy(rootAK, rootSK, policyName, policyString, 200);
        if (excludes!=null&&excludes.contains("AttachUserPolicy")) {
            AttachUserPolicy(ak, sk, accountId, userName, policyName, 403);
            AttachUserPolicy(rootAK, rootSK, accountId, userName, policyName, 200);
            accessDenyList.add("AttachUserPolicy");
        }else {
            AttachUserPolicy(ak, sk, accountId, userName, policyName, 200);
            successList.add("AttachUserPolicy");
        }
        if (excludes!=null&&excludes.contains("ListAttachedUserPolicies")) {
            ListAttachedUserPolicies(ak, sk, userName, 403);
            accessDenyList.add("ListAttachedUserPolicies");
        }else {
            ListAttachedUserPolicies(ak, sk, userName, 200);
            successList.add("ListAttachedUserPolicies");
        }
        if (excludes!=null&&excludes.contains("DetachUserPolicy")) {
            DetachUserPolicy(ak, sk, accountId, userName, policyName, 403);
            DetachUserPolicy(rootAK, rootSK, accountId, userName, policyName, 200);
            accessDenyList.add("DetachUserPolicy");
        }else {
            DetachUserPolicy(ak, sk, accountId, userName, policyName, 200);
            successList.add("DetachUserPolicy");
        }
        
        RemoveUserFromGroup(rootAK, rootSK, groupName, userName, 200);
        DeactivateMFADevice(rootAK, rootSK, userName, accountId, deviceName, 200);
        
        
        
        if (excludes!=null&&excludes.contains("DeleteUser")) {
            DeleteUser(ak, sk, userName, 403);
            accessDenyList.add("DeleteUser");
        }else {
            DeleteUser(ak, sk, userName, 200);
            successList.add("DeleteUser");
        }
        
        DeleteGroup(rootAK,rootSK,groupName,200);
        DeleteVirtualMFADevice(rootAK,rootSK,accountId,deviceName,200);
        
        if (successList!=null&&successList.size()>0) {
            System.out.println("Allow Method:");
            System.out.println(successList.toString());
        }
        
        if (accessDenyList!=null&&accessDenyList.size()>0) {
            System.out.println("AccessDeny Method:");
            System.out.println(accessDenyList.toString());
        }  
        
    }
    
    /*
     * 对应资源user/*
     */
    public static void AllowActionResourceUserALL(String rootAK,String rootSK,List<String> excludes,String ak,String sk,String userName,List<Pair<String, String>> tags,String policyName, String policyString,String accountId) {
        List<String> successList= new ArrayList<String>();
        List<String> accessDenyList= new ArrayList<String>();
        User user=new User();
        user.accountId=accountId;
        user.userName=userName;
        boolean exist1=false;
        try {
            exist1=HBaseUtils.exist(user);
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (excludes!=null&&excludes.contains("CreateUser")) {
            if(!exist1) {
            	CreateUser(ak, sk, userName, 403);
            	CreateUser(rootAK, rootSK, userName, 200);
            	accessDenyList.add("CreateUser");
            }
        }else {
        	if(!exist1) {
        		CreateUser(ak, sk, userName, 200);
        		successList.add("CreateUser");
        	}
        }
        if (excludes!=null&&excludes.contains("GetUser")) {
            GetUser(ak, sk, userName, 403);
            accessDenyList.add("GetUser");
        }else {
            GetUser(ak, sk, userName, 200);
            successList.add("GetUser");
        }
        if (excludes!=null&&excludes.contains("ListUsers")) {
            ListUsers(ak, sk, 403);
            accessDenyList.add("ListUsers");
        }else {
            ListUsers(ak, sk, 200);
            successList.add("ListUsers");
        }
        if (excludes!=null&&excludes.contains("TagUser")) {
            TagUser(ak, sk, userName, tags, 403);
            TagUser(rootAK, rootSK, userName, tags, 200);
            accessDenyList.add("TagUser");
        }else {
            TagUser(ak, sk, userName, tags, 200);
            successList.add("TagUser");
        }
        if (excludes!=null&&excludes.contains("ListUserTags")) {
            ListUserTags(ak, sk, userName, 403);
            accessDenyList.add("ListUserTags");
        }else {
            ListUserTags(ak, sk, userName, 200);
            successList.add("ListUserTags");
        }
        List<String> tagKeys = new ArrayList<String>();
        for (int i = 0; i < tags.size(); i++) {
            tagKeys.add(tags.get(0).first());
        }
        if (excludes!=null&&excludes.contains("UntagUser")) {
            UntagUser(ak, sk, userName, tagKeys, 403);
            accessDenyList.add("UntagUser");
        }else {
            UntagUser(ak, sk, userName, tagKeys, 200);
            successList.add("UntagUser");
        }
        String akId="";
        AkSkMeta aksk = new AkSkMeta();
        aksk.accessKey = ak;
        MetaClient client=MetaClient.getGlobalClient();
        try {
            boolean exist = client.akskSelectWithoutCache(aksk);
            assertTrue(exist);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        if (excludes!=null&&excludes.contains("CreateAccessKey")) {
            CreateAccessKey(ak, sk, userName, 403);  
            String xmlString =CreateAccessKey(rootAK, rootSK, userName, 200);
            akId=AssertCreateAccessKey(xmlString, userName, "Active");
            accessDenyList.add("CreateAccessKey");
        }else {
            String xmlString =CreateAccessKey(ak, sk, userName, 200);
            akId=AssertCreateAccessKey(xmlString, userName, "Active");
            successList.add("CreateAccessKey");
        }
        if (excludes!=null&&excludes.contains("ListAccessKeys")) {
            ListAccessKeys(ak, sk, userName, 403);
            accessDenyList.add("ListAccessKeys");
        }else {
            ListAccessKeys(ak, sk, userName, 200);
            successList.add("ListAccessKeys");
        }
        if (excludes!=null&&excludes.contains("UpdateAccessKey")) {
            UpdateAccessKey(ak, sk, akId, userName,"Inactive", 403);
            accessDenyList.add("UpdateAccessKey");
        }else {
            UpdateAccessKey(ak, sk, akId, userName,"Inactive", 200);
            successList.add("UpdateAccessKey");
        }
        if (excludes!=null&&excludes.contains("DeleteAccessKey")) {
            DeleteAccessKey(ak, sk, akId,userName, 403);
            DeleteAccessKey(rootAK, rootSK, akId,userName, 200);
            accessDenyList.add("DeleteAccessKey");
        }else {
            DeleteAccessKey(ak, sk, akId, userName,200);
            successList.add("DeleteAccessKey");
        }
        
        if (excludes!=null&&excludes.contains("CreateLoginProfile")) {
            CreateLoginProfile(ak, sk, userName, "a12345678", 403);
            CreateLoginProfile(rootAK, rootSK, userName, "a12345678", 200);
            accessDenyList.add("CreateLoginProfile");
        }else {
            CreateLoginProfile(ak, sk, userName, "a12345678", 200);
            successList.add("CreateLoginProfile");
        }
        if (excludes!=null&&excludes.contains("GetLoginProfile")) {
            GetLoginProfile(ak, sk, userName, 403);
            accessDenyList.add("GetLoginProfile");
        }else {
            GetLoginProfile(ak, sk, userName, 200);
            successList.add("GetLoginProfile");
        }
        String body="Action=CreateLoginProfile&UserName="+aksk.userName+"&Password=a12345678";
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, rootAK, rootSK);
        if (result.first().intValue()==409) {
            DeleteLoginProfile(rootAK, rootSK, aksk.userName, 200);
            CreateLoginProfile(rootAK, rootSK, aksk.userName, "a12345678", 200);
        }

        if (excludes!=null&&excludes.contains("ChangePassword")) {
            ChangePassword(ak, sk, aksk.userName, "a12345678", "b1234567", 403);
            accessDenyList.add("ChangePassword");
        }else {
            ChangePassword(ak, sk, aksk.userName, "a12345678", "b1234567", 200);
            successList.add("ChangePassword");
        }
        if (excludes!=null&&excludes.contains("UpdateLoginProfile")) {
            UpdateLoginProfile(ak, sk, userName, "b987654321", 403);
            accessDenyList.add("UpdateLoginProfile");
        }else {
            UpdateLoginProfile(ak, sk, userName, "b987654321", 200);
            successList.add("UpdateLoginProfile");
        }
        if (excludes!=null&&excludes.contains("DeleteLoginProfile")) {
            DeleteLoginProfile(ak, sk, userName, 403);
            accessDenyList.add("DeleteLoginProfile");
        }else {
            DeleteLoginProfile(ak, sk, userName, 200);
            successList.add("DeleteLoginProfile");
        }
        
        
        String groupName="userResourceGroup";
        CreateGroup(rootAK, rootSK, groupName, 200);
        AddUserToGroup(rootAK, rootSK, groupName, userName, 200);
        
        if (excludes!=null&&excludes.contains("ListGroupsForUser")) {
            ListGroupsForUser(ak, sk, userName, 403);
            accessDenyList.add("ListGroupsForUser");
        }else {
            ListGroupsForUser(ak, sk, userName, 200);
            successList.add("ListGroupsForUser");
        }

        String deviceName="userResourceDevice";
        String xml=CreateVirtualMFADevice(rootAK, rootSK, deviceName, 200);
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(xml,"arn:ctyun:iam::"+accountId+":mfa/"+deviceName);
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        if (excludes!=null&&excludes.contains("EnableMFADevice")) {
            EnableMFADevice(ak, sk, userName, accountId, deviceName, codesPair.first(), codesPair.second(), 403);
            EnableMFADevice(rootAK, rootSK, userName, accountId, deviceName, codesPair.first(), codesPair.second(), 200);
            accessDenyList.add("EnableMFADevice");
        }else {
            EnableMFADevice(ak, sk, userName, accountId, deviceName, codesPair.first(), codesPair.second(), 200);
            successList.add("EnableMFADevice");
        }
        
        CreatePolicy(rootAK, rootSK, policyName, policyString, 200);
        if (excludes!=null&&excludes.contains("AttachUserPolicy")) {
            AttachUserPolicy(ak, sk, accountId, userName, policyName, 403);
            AttachUserPolicy(rootAK, rootSK, accountId, userName, policyName, 200);
            accessDenyList.add("AttachUserPolicy");
        }else {
            AttachUserPolicy(ak, sk, accountId, userName, policyName, 200);
            successList.add("AttachUserPolicy");
        }
        if (excludes!=null&&excludes.contains("ListAttachedUserPolicies")) {
            ListAttachedUserPolicies(ak, sk, userName, 403);
            accessDenyList.add("ListAttachedUserPolicies");
        }else {
            ListAttachedUserPolicies(ak, sk, userName, 200);
            successList.add("ListAttachedUserPolicies");
        }
        if (excludes!=null&&excludes.contains("DetachUserPolicy")) {
            DetachUserPolicy(ak, sk, accountId, userName, policyName, 403);
            DetachUserPolicy(rootAK, rootSK, accountId, userName, policyName, 200);
            accessDenyList.add("DetachUserPolicy");
        }else {
            DetachUserPolicy(ak, sk, accountId, userName, policyName, 200);
            successList.add("DetachUserPolicy");
        }
        
        RemoveUserFromGroup(rootAK, rootSK, groupName, userName, 200);
        DeactivateMFADevice(rootAK, rootSK, userName, accountId, deviceName, 200);
        if (excludes!=null&&excludes.contains("DeleteUser")) {
            DeleteUser(ak, sk, userName, 403);
            accessDenyList.add("DeleteUser");
        }else {
            DeleteUser(ak, sk, userName, 200);
            successList.add("DeleteUser");
        }
        
        if (successList!=null&&successList.size()>0) {
            System.out.println("Allow Method:");
            System.out.println(successList.toString());
        }
        
        if (accessDenyList!=null&&accessDenyList.size()>0) {
            System.out.println("AccessDeny Method:");
            System.out.println(accessDenyList.toString());
        }  
    }
    
    /*
     * 对应资源user/<user>
     */
    public static void DenyActionResourceUser(String rootAK,String rootSK,String ak,String sk,String userName,List<Pair<String, String>> tags,String policyName, String policyString,String accountId) {
    
    	User user=new User();
        user.accountId=accountId;
        user.userName=userName;
        boolean exist=false;
        try {
            exist=HBaseUtils.exist(user);
        } catch (IOException e) {
            e.printStackTrace();
        }
        if(!exist) {
	        CreateUser(ak, sk, userName, 403);
	        CreateUser(rootAK, rootSK, userName, 200);
        }
        GetUser(ak, sk, userName, 403);
        TagUser(ak, sk, userName, tags, 403);
        TagUser(rootAK, rootSK, userName, tags, 200);
        ListUserTags(ak, sk, userName, 403);   
        List<String> tagKeys = new ArrayList<String>();
        for (int i = 0; i < tags.size(); i++) {
            tagKeys.add(tags.get(0).first());
        }
        UntagUser(ak, sk, userName, tagKeys, 403);
            
        String akId="";
        CreateAccessKey(ak, sk, userName, 403);
        String xmlString =CreateAccessKey(rootAK, rootSK, userName, 200);
        akId=AssertCreateAccessKey(xmlString, userName, "Active");
        ListAccessKeys(ak, sk, userName, 403);
        UpdateAccessKey(ak, sk, akId,userName, "Inactive", 403);
        DeleteAccessKey(ak, sk, akId,userName, 403);
        CreateLoginProfile(ak, sk, userName, "a12345678", 403);
        CreateLoginProfile(rootAK, rootSK, userName, "a12345678", 200);
        GetLoginProfile(ak, sk, userName, 403);
//        ChangePassword(ak, sk, userName, "a12345678", "b1234567", 200);
        UpdateLoginProfile(ak, sk, userName, "b987654321", 403);
        DeleteLoginProfile(ak, sk, userName, 403);
        DeleteLoginProfile(rootAK, rootSK, userName, 200);
  
        String groupName="userResourceGroup";
        CreateGroup(rootAK, rootSK, groupName, 200);
        AddUserToGroup(rootAK, rootSK, groupName, userName, 200);
        ListGroupsForUser(ak, sk, userName, 403);
        RemoveUserFromGroup(rootAK, rootSK, groupName, userName, 200);
        DeleteGroup(rootAK,rootSK,groupName,200);
           
        String deviceName="userResourceDevice";
        String xml=CreateVirtualMFADevice(rootAK, rootSK, deviceName, 200);
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(xml,"arn:ctyun:iam::"+accountId+":mfa/"+deviceName);
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        EnableMFADevice(ak, sk, userName, accountId, deviceName, codesPair.first(), codesPair.second(), 403);
        DeleteVirtualMFADevice(rootAK,rootSK,accountId,deviceName,200);
        CreatePolicy(rootAK, rootSK, policyName, policyString, 200);
        AttachUserPolicy(ak, sk, accountId, userName, policyName, 403);
        AttachUserPolicy(rootAK, sk, accountId, userName, policyName, 403);
        ListAttachedUserPolicies(akId, sk, userName, 403);
        DetachUserPolicy(ak, sk, accountId, userName, policyName, 403);
        DeleteUser(ak, sk, userName, 403);
    }
    
    /*
     * 对应资源user/*
     */
    public static void DenyActionResourceUserALL(String rootAK,String rootSK,String ak,String sk,String userName,List<Pair<String, String>> tags,String policyName, String policyString,String accountId) {
    
    	User user=new User();
        user.accountId=accountId;
        user.userName=userName;
        boolean exist1=false;
        try {
            exist1=HBaseUtils.exist(user);
        } catch (IOException e) {
            e.printStackTrace();
        }

        if(!exist1) {
	    	CreateUser(ak, sk, userName, 403);
	        CreateUser(rootAK, rootSK, userName, 200);
        }
        GetUser(ak, sk, userName, 403);
        ListUsers(ak, sk, 403);
        TagUser(ak, sk, userName, tags, 403);
        TagUser(rootAK, rootSK, userName, tags, 200);
        ListUserTags(ak, sk, userName, 403);   
        List<String> tagKeys = new ArrayList<String>();
        for (int i = 0; i < tags.size(); i++) {
            tagKeys.add(tags.get(0).first());
        }
        UntagUser(ak, sk, userName, tagKeys, 403);
            
        String akId="";
        CreateAccessKey(ak, sk, userName, 403);
        String xmlString =CreateAccessKey(rootAK, rootSK, userName, 200);
        akId=AssertCreateAccessKey(xmlString, userName, "Active");
        ListAccessKeys(ak, sk, userName, 403);
        UpdateAccessKey(ak, sk, akId, userName, "Inactive", 403);
        DeleteAccessKey(ak, sk, akId,userName, 403);
        CreateLoginProfile(ak, sk, userName, "a12345678", 403);
        CreateLoginProfile(rootAK, rootSK, userName, "a12345678", 200);
        GetLoginProfile(ak, sk, userName, 403);
//        ChangePassword(ak, sk, userName, "a12345678", "b1234567", 403);
        UpdateLoginProfile(ak, sk, userName, "b987654321", 403);
        DeleteLoginProfile(ak, sk, userName, 403);
  
        String groupName="userResourceGroup";
        CreateGroup(rootAK, rootSK, groupName, 200);
        AddUserToGroup(rootAK, rootSK, groupName, userName, 200);
        ListGroupsForUser(ak, sk, userName, 403);
        RemoveUserFromGroup(rootAK, rootSK, groupName, userName, 200);
        DeleteGroup(rootAK,rootSK,groupName,200);
           
        String deviceName="userResourceDevice";
        String xml=CreateVirtualMFADevice(rootAK, rootSK, deviceName, 200);
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(xml,"arn:ctyun:iam::"+accountId+":mfa/"+deviceName);
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        EnableMFADevice(ak, sk, userName, accountId, deviceName, codesPair.first(), codesPair.second(), 403);
        DeleteVirtualMFADevice(rootAK,rootSK,accountId,deviceName,200);
        CreatePolicy(rootAK, rootSK, policyName, policyString, 200);
        AttachUserPolicy(ak, sk, accountId, userName, policyName, 403);
        AttachUserPolicy(rootAK, sk, accountId, userName, policyName, 403);
        ListAttachedUserPolicies(akId, sk, userName, 403);
        DetachUserPolicy(ak, sk, accountId, userName, policyName, 403);
        DeleteUser(ak, sk, userName, 403);
    }
    
    public static void AllowActionResourceALL(String rootAK,String rootSK,List<String> excludes,String ak,String sk,String userName,List<Pair<String, String>> tags,String policyName, String policyString,String accountId,String groupName,String deviceName) {
        List<String> successList= new ArrayList<String>();
        List<String> accessDenyList= new ArrayList<String>();
        if (excludes!=null&&excludes.contains("GetAccountPasswordPolicy")) {
            GetAccountPasswordPolicy(ak, sk, 403);
            accessDenyList.add("GetAccountPasswordPolicy");
        }else {
            GetAccountPasswordPolicy(ak, sk, 200);
            successList.add("GetAccountPasswordPolicy");
        }
        if (excludes!=null&&excludes.contains("UpdateAccountPasswordPolicy")) {
            UpdateAccountPasswordPolicy(ak, sk, 403);
            accessDenyList.add("UpdateAccountPasswordPolicy");
        }else {
            UpdateAccountPasswordPolicy(ak, sk, 200);
            successList.add("UpdateAccountPasswordPolicy");
        }
        if (excludes!=null&&excludes.contains("DeleteAccountPasswordPolicy")) {
            DeleteAccountPasswordPolicy(ak, sk, 403);
            accessDenyList.add("DeleteAccountPasswordPolicy");
        }else {
            DeleteAccountPasswordPolicy(ak, sk, 200);
            successList.add("DeleteAccountPasswordPolicy");
        }
        if (excludes!=null&&excludes.contains("GetAccountSummary")) {
            GetAccountSummary(ak, sk, 403);
            accessDenyList.add("GetAccountSummary");
        }else {
            GetAccountSummary(ak, sk, 200);
            successList.add("GetAccountSummary");
        }
        
        if (successList!=null&&successList.size()>0) {
            System.out.println("Allow Method:");
            System.out.println(successList.toString());
        }
        
        if (accessDenyList!=null&&accessDenyList.size()>0) {
            System.out.println("AccessDeny Method:");
            System.out.println(accessDenyList.toString());
        }  
        
        AllowActionResourceUserALL(rootAK, rootSK, excludes, ak, sk, userName, tags, policyName, policyString, accountId);
        AllowActionResourceGroupALL(rootAK, rootSK, excludes, ak, sk, groupName, userName, accountId, policyName, policyString);
        AllowActionResourcePolicyALL(rootAK, rootSK, excludes, ak, sk, policyName, policyString, accountId);
        AllowActionResourceMFAALL(rootAK, rootSK, excludes, ak, sk, accountId, deviceName);
    }
    
    public static void DenyActionResourceALL(String rootAK,String rootSK,String ak,String sk,String userName,List<Pair<String, String>> tags,String policyName, String policyString,String accountId,String groupName,String deviceName) {
        DenyActionResourceOthers(ak,sk);
        DenyActionResourceUserALL(rootAK, rootSK,  ak, sk, userName, tags, policyName, policyString, accountId);
        DenyActionResourceGroupALL(rootAK, rootSK,  ak, sk, groupName, userName, accountId, policyName, policyString);
        DenyActionResourcePolicyALL(rootAK, rootSK,  ak, sk, policyName, policyString, accountId);
        DenyActionResourceMFAALL(rootAK, rootSK, ak, sk, accountId, deviceName);
    }
    
    public static void DenyActionResourceOthers(String ak,String sk) {
        GetAccountPasswordPolicy(ak, sk, 403);
        UpdateAccountPasswordPolicy(ak, sk, 403);
        DeleteAccountPasswordPolicy(ak, sk, 403);
        GetAccountSummary(ak, sk, 403);
    }
    
    public static void AllowActionResourceOthers(String ak,String sk,List<String> excludes) {
        List<String> successList= new ArrayList<String>();
        List<String> accessDenyList= new ArrayList<String>();
        if (excludes!=null&&excludes.contains("GetAccountPasswordPolicy")) {
            GetAccountPasswordPolicy(ak, sk, 403);
            accessDenyList.add("GetAccountPasswordPolicy");
        }else {
            GetAccountPasswordPolicy(ak, sk, 200);
            successList.add("GetAccountPasswordPolicy");
        }
        if (excludes!=null&&excludes.contains("UpdateAccountPasswordPolicy")) {
            UpdateAccountPasswordPolicy(ak, sk, 403);
            accessDenyList.add("UpdateAccountPasswordPolicy");
        }else {
            UpdateAccountPasswordPolicy(ak, sk, 200);
            successList.add("UpdateAccountPasswordPolicy");
        }
        if (excludes!=null&&excludes.contains("DeleteAccountPasswordPolicy")) {
            DeleteAccountPasswordPolicy(ak, sk, 403);
            accessDenyList.add("DeleteAccountPasswordPolicy");
        }else {
            DeleteAccountPasswordPolicy(ak, sk, 200);
            successList.add("DeleteAccountPasswordPolicy");
        }
        if (excludes!=null&&excludes.contains("GetAccountSummary")) {
            GetAccountSummary(ak, sk, 403);
            accessDenyList.add("GetAccountSummary");
        }else {
            GetAccountSummary(ak, sk, 200);
            successList.add("GetAccountSummary");
        }
        
        if (successList!=null&&successList.size()>0) {
            System.out.println("Allow Method:");
            System.out.println(successList.toString());
        }
        
        if (accessDenyList!=null&&accessDenyList.size()>0) {
            System.out.println("AccessDeny Method:");
            System.out.println(accessDenyList.toString());
        }  
        
        
    }
    
    public static String AssertCreateAccessKey(String xml,String username,String status) {
        try {
            StringReader sr = new StringReader(xml);
            InputSource is = new InputSource(sr);
            Document doc = (new SAXBuilder()).build(is);
            Element root = doc.getRootElement();
            
            Element createAKResultElement=root.getChild("CreateAccessKeyResult");
            Element AkElement=createAKResultElement.getChild("AccessKey");
            assertEquals(username, AkElement.getChild("UserName").getValue());
            assertEquals(status, AkElement.getChild("Status").getValue());
            String ak=AkElement.getChild("AccessKeyId").getValue();
            System.out.println(ak);
            System.out.println(AkElement.getChild("SecretAccessKey").getValue());
            System.out.println(AkElement.getChild("CreateDate").getValue());
            
            return ak;
        } catch (Exception e) {
            e.getStackTrace();
        }
        return null;
    }
    
    public static Pair<String, String> AssertcreateVirtualMFADevice(String xml,String serialNumber) {
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
            e.getStackTrace();
        }
        
        return null;
    }
    
    public static Pair<String, String> CreateIdentifyingCode(String secret) {
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
