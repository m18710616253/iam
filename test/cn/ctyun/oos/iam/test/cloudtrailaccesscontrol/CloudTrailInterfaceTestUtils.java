package cn.ctyun.oos.iam.test.cloudtrailaccesscontrol;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.OutputStream;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.io.IOUtils;

import cn.ctyun.oos.iam.test.HttpsRequestUtils;
import cn.ctyun.oos.iam.test.V4TestUtils;
import common.tuple.Pair;



public class CloudTrailInterfaceTestUtils {
    
    static String OOS_CLOUDTRAIL_DOMAIN="https://oos-cn-cloudtrail.ctyunapi.cn:9461/";
    static String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
    static String DEFAULT_TARGET = "cn.ctyunapi.oos-cn-cloudtrail.v20131101.CloudTrail_20131101";
    static String regionName="cn";
    
    public static Pair<Integer, String> CreateTrail(String accessKey,String secretKey,String trailName,String bucketName,Map<String, String> headers) {
        String action = "CreateTrail";
        String body = "{\"Name\":\""+trailName+"\",\"S3BucketName\":\""+bucketName+"\"}";
        //请求CloudTrailServer
        Pair<Integer, String> result = callCloudTrailServer("POST",action,body,accessKey,secretKey, true,headers);

        return result;
    }
    
    public static Pair<Integer, String> DeleteTrail(String accessKey,String secretKey,String trailName,Map<String, String> headers) {
        String action = "DeleteTrail";
        String body = "{\"Name\":\""+trailName+"\"}";
        Pair<Integer, String> result = callCloudTrailServer("POST",action,body,accessKey,secretKey, true,headers);
        return result;
    }
    
    public static Pair<Integer, String> DescribeTrails(String accessKey,String secretKey,List<String> trailNames,Map<String, String> headers) {
        String action = "DescribeTrails";
        String trailNameList="";
        if (trailNames!=null&&trailNames.size()>0) {
            for (int i = 0; i < trailNames.size(); i++) {
                trailNameList+="\""+trailNames.get(i)+"\"";
                if (i!=trailNames.size()-1) {
                    trailNameList+=",";
                }
            }  
        }
        String body = "{\"TrailNameList\":["+trailNameList+"]}";
        Pair<Integer, String> result = callCloudTrailServer("POST",action,body,accessKey,secretKey, true,headers);
        return result;
    }
    
    public static Pair<Integer, String> GetTrailStatus(String accessKey,String secretKey,String trailName,Map<String, String> headers) {
        String action = "GetTrailStatus";
        String body = "{\"Name\":\""+trailName+"\"}";
        //请求CloudTrailServer
        Pair<Integer, String> result = callCloudTrailServer("POST",action,body,accessKey,secretKey, true,headers);

        return result;
    }
    
    public static Pair<Integer, String> PutEventSelectors(String accessKey,String secretKey,String trailName,String readWriteType,Map<String, String> headers) {
        String action = "PutEventSelectors";
        String EventSelectors="";
        
        if (readWriteType!=null) {
            EventSelectors="{\"ReadWriteType\":\""+readWriteType+"\"}";
        }
        
        String body = "{\"TrailName\":\""+trailName+"\","
                + "\"EventSelectors\":["+EventSelectors+"]}";

        //请求CloudTrailServer
        Pair<Integer, String> result = callCloudTrailServer("POST",action,body,accessKey,secretKey, true,headers);

        return result;
    }
    
    public static Pair<Integer, String> GetEventSelectors(String accessKey,String secretKey,String trailName,Map<String, String> headers) {
        String action = "GetEventSelectors";
        String body = "{\"TrailName\":\""+trailName+"\"}";

        //请求CloudTrailServer
        Pair<Integer, String> result = callCloudTrailServer("POST",action,body,accessKey,secretKey, true,headers);

        return result;
    }
    
    public static Pair<Integer, String> UpdateTrail(String accessKey,String secretKey,String trailName,String bucketName,String keyPrefix,Map<String, String> headers) {
        String action = "UpdateTrail";
        String bucketString="";
        String prefixString="";
        if (bucketName!=null) {
            bucketString=",\"S3BucketName\":\""+bucketName+"\"";
        }
        if (keyPrefix!=null) {
            prefixString=",\"S3KeyPrefix\":\""+keyPrefix+"\"";
        }
        String body = "{\"Name\":\""+trailName+"\""+bucketString+prefixString+"}";

        //请求CloudTrailServer
        Pair<Integer, String> result = callCloudTrailServer("POST",action,body,accessKey,secretKey, true,headers);

        return result;
    }
    
    public static Pair<Integer, String> StartLogging(String accessKey,String secretKey,String trailName,Map<String, String> headers) {
        String action = "StartLogging";
        String body = "{\"Name\":\""+trailName+"\"}";
        //请求CloudTrailServer
        Pair<Integer, String> result = callCloudTrailServer("POST",action,body,accessKey,secretKey, true,headers);

        return result;
    }
    
    public static Pair<Integer, String> StopLogging(String accessKey,String secretKey,String trailName,Map<String, String> headers) {
        String action = "StopLogging";
        String body = "{\"Name\":\""+trailName+"\"}";
        //请求CloudTrailServer
        Pair<Integer, String> result = callCloudTrailServer("POST",action,body,accessKey,secretKey, true,headers);

        return result;
    }
    
    public static Pair<Integer, String> LookupEvents(String accessKey,String secretKey,String attributeKey,String attributeValue,Map<String, String> headers) {
        String action = "LookupEvents";
        String body = "{\"LookupAttributes\":[{\"AttributeKey\":\""+attributeKey+"\","
                + "\"AttributeValue\":\""+attributeValue+"\"}]}";
        if (attributeKey=="ReadOnly") {
            body = "{\"LookupAttributes\":[{\"AttributeKey\":\""+attributeKey+"\","
                    + "\"AttributeValue\":"+attributeValue+"}]}";
        }
        //请求CloudTrailServer
        Pair<Integer, String> result = callCloudTrailServer( "POST",action,body,accessKey,secretKey, true,headers);

        return result;
    }

    private static Pair<Integer, String> callCloudTrailServer(String method, String action, String body, String accessKey,String secretKey, boolean isTarget,Map<String, String> headers) {
        Pair<Integer, String> result=new Pair<Integer, String>();
        try {
            URL url = new URL(OOS_CLOUDTRAIL_DOMAIN);
            if (headers==null) {
                headers = new HashMap<String, String>();
            }
            
            headers.put("x-amz-content-sha256", UNSIGNED_PAYLOAD);  
            if(isTarget)
                headers.put("x-amz-target", DEFAULT_TARGET + "." + action);  
            else
                headers.put("x-amz-target", "cn.ctyunapi.oos-cn-cloudtrail.CloudTrail_20131101." + action);
            headers.put("Content-Type", "application/json");
            String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                    url, method, "cloudtrail", regionName);
            headers.put("Authorization", authorization);
            HttpsURLConnection connection = HttpsRequestUtils.createConn(url, method, headers);
            OutputStream out = connection.getOutputStream();
            out.write(body.getBytes());
            out.flush();
            int code = connection.getResponseCode();
            assertEquals("CTYUN",connection.getHeaderField("Server"));
            assertNotNull(connection.getHeaderField("DATE"));
            assertNotNull(connection.getHeaderField("x-amz-request-id"));
            System.out.println("Date:"+connection.getHeaderField("DATE"));
            System.out.println("x-amz-request-id:"+connection.getHeaderField("x-amz-request-id"));
            String res ="";
            if (code==200) {
                res = IOUtils.toString(connection.getInputStream());
            }else {
                res = IOUtils.toString(connection.getErrorStream());
            }
            result.first(code);
            result.second(res);
            System.out.println(res);   
            out.close(); 
            if (connection != null) {
                connection.disconnect();
            }
            
        } catch (Exception e) {

        }       
        return result;
    }
}
