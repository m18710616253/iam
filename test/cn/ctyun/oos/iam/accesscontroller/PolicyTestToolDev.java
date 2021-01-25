package cn.ctyun.oos.iam.accesscontroller;

import static org.junit.Assert.assertEquals;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import cn.ctyun.oos.iam.test.IAMTestUtils;
import common.tuple.Pair;

public class PolicyTestToolDev {

    private String accessKey = "test_user8_6463084869102845087@a.cn88";
    private String secretKey = "secretKey88";
    private String accountId = "17vdu0cyjo7rh";
    
    public PolicyTestToolDev() {}
    
    public PolicyTestToolDev(String accessKey, String secretKey, String accountId) {
        this.accessKey = accessKey;
        this.secretKey = secretKey;
        this.accountId = accountId;
    }

    public void createPolicy(String policyName, String document) throws UnsupportedEncodingException {
        // 创建策略
        String body = "Action=CreatePolicy&Version=2010-05-08&Description=desc1235&PolicyName=" + policyName
                + "&PolicyDocument=" + URLEncoder.encode(document, "UTF-8");
        Pair<Integer, String> resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
    }
    
    public void attachUserPolicy(String policyName, String userName) throws UnsupportedEncodingException {
        // 创建策略
        String body="Action=AttachUserPolicy&PolicyArn=arn:ctyun:iam::" + accountId + ":policy/" + policyName + "&UserName=" + userName;
        Pair<Integer, String> resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
    }
    
    public void detachUserPolicy(String policyName, String userName) throws UnsupportedEncodingException {
        // 创建策略
        String body="Action=DetachUserPolicy&PolicyArn=arn:ctyun:iam::" + accountId + ":policy/" + policyName + "&UserName=" + userName;
        Pair<Integer, String> resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
    }
    
    public void deletePolicy(String policyName) throws UnsupportedEncodingException {
        // 创建策略
        String body = "Action=DeletePolicy&PolicyArn=arn:ctyun:iam::"  + accountId + ":policy/" + policyName;
        Pair<Integer, String> resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
    }
}
