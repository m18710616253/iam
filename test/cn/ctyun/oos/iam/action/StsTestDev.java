/**
 * 
 */
package cn.ctyun.oos.iam.action;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.text.ParseException;
import java.util.List;

import org.junit.Test;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.Bucket;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClient;
import com.amazonaws.services.securitytoken.model.Credentials;
import com.amazonaws.services.securitytoken.model.GetSessionTokenRequest;
import com.amazonaws.services.securitytoken.model.GetSessionTokenResult;

import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.iam.util.IAMHttpTestClient;

/**
 * @author wangduo
 *
 */
public class StsTestDev {

    // userwd
    public static final String accessKey="test_user8_6463084869102845087@a.cn88";
    public static final String secretKey="secretKey88";
    private String OOS_DOMAIN = "http://oos-cd.ctyunapi.cn:8080";

    
  
    public static IAMHttpTestClient httpTestClient = new IAMHttpTestClient(accessKey, secretKey);

    @Test
    public void testGetSessionToken() throws Exception {
        String body="Action=GetSessionToken&Version=2010-05-08&DurationSeconds=" + 30 * 3600;
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
    
    @Test
    public void testUpdateAccessKey() throws Exception {
        String userName = "iamUserName";
        String body="Action=CreateUser&Version=2010-05-08&UserName=" + userName + "&Tags.member.1.Key=tagkey1&Tags.member.1.Value=tagvalue";
        IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        
        
        body="Action=CreateAccessKey&UserName=" + userName;
        IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
    }
   
    @Test
    public void testIAMUserGetSessionToken() throws Exception {
        String body="Action=GetSessionToken&Version=2010-05-08&DurationSeconds=" + 30 * 3600;
        IAMTestUtils.invokeHttpsRequest(body, "552e66fa6999b2480dd6", "d277f362ced7a671d6e0cac555a49f10fd84a5aa");
    }
    
    @Test
    //   sts过期后在使用会报403
    public void get_Token_with_expire() throws IOException, ParseException, InterruptedException{
//        GetSessionTokenRequest getSessionTokenRequest = new GetSessionTokenRequest();
//        getSessionTokenRequest.setDurationSeconds(60*2);//过期时间，单位秒
//        // 2010-05-08
//        stsClient.setEndpoint("http://oos-cd-iam.ctyunapi.cn:9097");
//        GetSessionTokenResult sessionTokenResult = stsClient.getSessionToken(getSessionTokenRequest);
//        Credentials sessionCredentials = sessionTokenResult.getCredentials();
//        //Thread.sleep(3*60*1000);
        BasicSessionCredentials basicSessionCredentials = new BasicSessionCredentials(
                "sts.de393652c546a32a8ac4",
                "747a342f2b7add3c2dcf784254a19240740567ed",
                "3a4772bad2b0797532ba82af26fb08ea5c9463159fbcdc5e9b0da5559885093986a1eaba9099105383e1676a315397b7a31aafcaa237487b52ffd52f983c112c");
        AmazonS3 s3Client = new AmazonS3Client(basicSessionCredentials);
        s3Client.setEndpoint(OOS_DOMAIN);
            List<Bucket> buckets = s3Client.listBuckets();
    }
    
}
