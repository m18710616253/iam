package cn.ctyun.oos.iam.server.internal.api;

import static org.junit.Assert.assertEquals;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

import org.apache.commons.io.IOUtils;
import org.junit.BeforeClass;
import org.junit.Test;

import cn.ctyun.oos.iam.server.util.JSONUtils;
import common.tuple.Pair;

public class OOSPolicyAPITestDev {
    public static final String OOS_IAM_DOMAIN = "http://localhost:9097/";

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
    }

    @Test
    public void testCreatePolicy() throws Exception {
        String policyDocument = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"oos:ListAllMyBuckets\",\"Resource\":\"arn:ctyun:oos:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"oos:Get*\",\"oos:List*\"],\"Resource\":[\"arn:ctyun:oos:::EXAMPLE-BUCKET\",\"arn:ctyun:oos:::EXAMPLE-BUCKET/*\"]}]}";
        OOSPolicyParam param = new OOSPolicyParam();
        param.policyDocument = policyDocument;
        param.policyName = "OOSpolicy1";
        param.description = "test1234";
        String body = JSONUtils.MAPPER.writeValueAsString(param);
        Pair<Integer, String> result = invokeHttpsRequest("createPolicy", body);
        assertEquals(200, result.first().intValue());
    }

    @Test
    public void testUpdatePolicy() throws Exception {
        String policyDocument = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"oos:ListAllMyBuckets\",\"Resource\":\"arn:ctyun:oos:::*\"},{\"Effect\":\"Allow\",\"Action\":[\"oos:Get*\",\"oos:List*\"],\"Resource\":[\"arn:ctyun:oos:::EXAMPLE-BUCKET\",\"arn:ctyun:oos:::EXAMPLE-BUCKET/*\"]}]}";
        OOSPolicyParam param = new OOSPolicyParam();
        param.policyDocument = policyDocument;
        param.policyName = "OOSpolicy1";
        param.description = "test1232";
        String body = JSONUtils.MAPPER.writeValueAsString(param);
        Pair<Integer, String> result = invokeHttpsRequest("updatePolicy", body);
        assertEquals(200, result.first().intValue());
    }

    @Test
    public void testDeletePolicy() throws Exception {
        OOSPolicyParam param = new OOSPolicyParam();
        param.policyName = "OOSpolicy2";
        String body = JSONUtils.MAPPER.writeValueAsString(param);
        Pair<Integer, String> result = invokeHttpsRequest("deletePolicy", body);
        assertEquals(200, result.first().intValue());
    }

    @Test
    public void testGetPolicy() throws Exception {
        OOSPolicyParam param = new OOSPolicyParam();
        param.policyName = "OOSpolicy1";
        String body = JSONUtils.MAPPER.writeValueAsString(param);
        Pair<Integer, String> result = invokeHttpsRequest("getPolicy", body);
        assertEquals(200, result.first().intValue());
    }

    @Test
    public void testListPolicies() throws Exception {
        ListOOSPoliciesParam param = new ListOOSPoliciesParam();
        param.policyName = "OOSpolicy";
        param.marker = "OOS|oospolicy1";
        param.maxItems = 1;
        String body = JSONUtils.MAPPER.writeValueAsString(param);
        Pair<Integer, String> result = invokeHttpsRequest("listPolicies", body);
        assertEquals(200, result.first().intValue());
    }
    
    
    public Pair<Integer, String> invokeHttpsRequest(String action, String body) throws Exception {
        System.out.println(body);
        Pair<Integer, String> result = new Pair<Integer, String>();

        URL url = new URL(OOS_IAM_DOMAIN + "internal/" + action);

        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setUseCaches(false);
        connection.setDoInput(true);
        connection.setDoOutput(true);
        OutputStream out = connection.getOutputStream();
        out.write(body.getBytes());
        out.flush();
        int code = connection.getResponseCode();
        String json = "";
        if (code == 200) {
            json = IOUtils.toString(connection.getInputStream());
        } else {
            json = IOUtils.toString(connection.getErrorStream());
        }
        result.first(code);
        result.second(json);
        System.out.println(code + " " + json);
        out.close();
        if (connection != null) {
            connection.disconnect();
        }

        return result;

    }

}
