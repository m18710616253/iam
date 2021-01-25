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
public class MFAActionTestDev {

    public static final String accessKey="test_user8_6463084869102845087@a.cn88";
    public static final String secretKey="secretKey88";

    public static IAMHttpTestClient httpTestClient = new IAMHttpTestClient(accessKey, secretKey);

    @Test
    public void testCreateVirtualMFADevice() throws Exception {
        String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=MFA333";
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
    
    @Test
    public void testListVirtualMFADevices() throws Exception {
        String body="Action=ListVirtualMFADevices&Version=2010-05-08&MaxItems=1&Marker=" + "17vdu0cyjo7rh|MFA1";
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
    
    @Test
    public void testEnableMFADevice() throws Exception {
        String body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_user1&SerialNumber=" + URLEncoder.encode("arn:ctyun:iam::17vdu0cyjo7rh:mfa/MFA1", "UTF-8")+ "&AuthenticationCode1=222222&AuthenticationCode2=333333";
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
}
