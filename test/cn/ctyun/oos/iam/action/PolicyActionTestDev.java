/**
 * 
 */
package cn.ctyun.oos.iam.action;

import java.net.URLEncoder;

import org.junit.Test;

import cn.ctyun.oos.iam.util.IAMHttpTestClient;

/**
 * @author wangduo
 *
 */
public class PolicyActionTestDev {

    public static final String accessKey="test_user8_6463084869102845087@a.cn88";
    public static final String secretKey="secretKey88";

    public static IAMHttpTestClient httpTestClient = new IAMHttpTestClient(accessKey, secretKey);

    @Test
    public void testCreatePolicy() throws Exception {
        String body="Action=CreatePolicy&Version=2010-05-08&PolicyName=fullaccess&Description=" + URLEncoder.encode("测试") + "&"
                + "PolicyDocument=" + URLEncoder.encode("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"oos:ListAllMyBuckets\",\"Resource\":\"arn:ctyun:oos:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"oos:Get*\",\"oos:List*\"],\"Resource\":[\"arn:ctyun:oos:::EXAMPLE-BUCKET\",\"arn:ctyun:oos:::EXAMPLE-BUCKET/*\"]}]}");
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
    
    @Test
    public void testGetPolicy() throws Exception {
        String body="Action=GetPolicy&PolicyArn=arn:ctyun:iam::OOS:policy/OOSpolicy1";
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
    
    @Test
    public void testListPolicies() throws Exception {
        String body="Action=ListPolicies&Version=2010-05-08";
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
    
    @Test
    public void testAttachUserPolicy() throws Exception {
        String body="Action=AttachUserPolicy&PolicyArn=arn:ctyun:iam::OOS:policy/OOSpolicy1&UserName=userwd";
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
    
    @Test
    public void testListAttachedUserPolicies() throws Exception {
        String body="Action=ListAttachedUserPolicies&UserName=userwd";
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
    
    @Test
    public void testDeletePolicy() throws Exception {
        String body="Action=DeletePolicy&PolicyArn=arn:ctyun:iam::OOS:policy/fullaccess";
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
}
