package cn.ctyun.oos.utils.api;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.OutputStream;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.io.IOUtils;

import cn.ctyun.oos.utils.HttpConnectionSSLRequestUtils;
import cn.ctyun.oos.utils.V4SignClient;
import common.tuple.Pair;

public class CloudTrailAPITestUtils {
    
    static String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
    static String DEFAULT_TARGET = "cn.ctyunapi.oos-cn-cloudtrail.v20131101.CloudTrail_20131101";
    
    
    public static Pair<Integer, String> CreateTrail(String endpointUrlStr,String regionName,String accessKey,String secretKey,String trailName,String bucketName,boolean isTarget,Map<String, String> headers) {
        String action = "CreateTrail";
        String body = "{\"Name\":\""+trailName+"\",\"S3BucketName\":\""+bucketName+"\"}";
        //请求CloudTrailServer
        Pair<Integer, String> result = callCloudTrailServer(endpointUrlStr,regionName,accessKey,secretKey,action,body, isTarget,headers);

        return result;
    }
    
    public static Pair<Integer, String> DeleteTrail(String endpointUrlStr,String regionName,String accessKey,String secretKey,String trailName,boolean isTarget,Map<String, String> headers) {
        String action = "DeleteTrail";
        String body = "{\"Name\":\""+trailName+"\"}";
        Pair<Integer, String> result = callCloudTrailServer(endpointUrlStr,regionName,accessKey,secretKey,action,body, isTarget,headers);
        return result;
    }
    
    public static Pair<Integer, String> DescribeTrails(String endpointUrlStr,String regionName,String accessKey,String secretKey,List<String> trailNames,boolean isTarget,Map<String, String> headers) {
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
        Pair<Integer, String> result = callCloudTrailServer(endpointUrlStr,regionName,accessKey,secretKey,action,body, isTarget,headers);
        return result;
    }
    
    public static Pair<Integer, String> GetTrailStatus(String endpointUrlStr,String regionName,String accessKey,String secretKey,String trailName,boolean isTarget,Map<String, String> headers) {
        String action = "GetTrailStatus";
        String body = "{\"Name\":\""+trailName+"\"}";
        //请求CloudTrailServer
        Pair<Integer, String> result = callCloudTrailServer(endpointUrlStr,regionName,accessKey,secretKey,action,body, isTarget,headers);

        return result;
    }
    
    public static Pair<Integer, String> PutEventSelectors(String endpointUrlStr,String regionName,String accessKey,String secretKey,String trailName,String readWriteType,boolean isTarget,Map<String, String> headers) {
        String action = "PutEventSelectors";
        String EventSelectors="";
        
        if (readWriteType!=null) {
            EventSelectors="{\"ReadWriteType\":\""+readWriteType+"\"}";
        }
        
        String body = "{\"TrailName\":\""+trailName+"\","
                + "\"EventSelectors\":["+EventSelectors+"]}";

        //请求CloudTrailServer
        Pair<Integer, String> result = callCloudTrailServer(endpointUrlStr,regionName,accessKey,secretKey,action,body, isTarget,headers);

        return result;
    }
    
    public static Pair<Integer, String> GetEventSelectors(String endpointUrlStr,String regionName,String accessKey,String secretKey,String trailName,boolean isTarget,Map<String, String> headers) {
        String action = "GetEventSelectors";
        String body = "{\"TrailName\":\""+trailName+"\"}";

        //请求CloudTrailServer
        Pair<Integer, String> result = callCloudTrailServer(endpointUrlStr,regionName,accessKey,secretKey,action,body, isTarget,headers);

        return result;
    }
    
    public static Pair<Integer, String> UpdateTrail(String endpointUrlStr,String regionName,String accessKey,String secretKey,String trailName,String bucketName,String keyPrefix,boolean isTarget,Map<String, String> headers) {
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
        Pair<Integer, String> result = callCloudTrailServer(endpointUrlStr,regionName,accessKey,secretKey,action,body, isTarget,headers);

        return result;
    }
    
    public static Pair<Integer, String> StartLogging(String endpointUrlStr,String regionName,String accessKey,String secretKey,String trailName,boolean isTarget,Map<String, String> headers) {
        String action = "StartLogging";
        String body = "{\"Name\":\""+trailName+"\"}";
        //请求CloudTrailServer
        Pair<Integer, String> result = callCloudTrailServer(endpointUrlStr,regionName,accessKey,secretKey,action,body, isTarget,headers);

        return result;
    }
    
    public static Pair<Integer, String> StopLogging(String endpointUrlStr,String regionName,String accessKey,String secretKey,String trailName,boolean isTarget,Map<String, String> headers) {
        String action = "StopLogging";
        String body = "{\"Name\":\""+trailName+"\"}";
        //请求CloudTrailServer
        Pair<Integer, String> result = callCloudTrailServer(endpointUrlStr,regionName,accessKey,secretKey,action,body, isTarget,headers);

        return result;
    }
    
    public static Pair<Integer, String> LookupEvents(String endpointUrlStr,String regionName,String accessKey,String secretKey,String attributeKey,String attributeValue,boolean isTarget,Map<String, String> headers) {
        String action = "LookupEvents";
        String body = "{\"LookupAttributes\":[{\"AttributeKey\":\""+attributeKey+"\","
                + "\"AttributeValue\":\""+attributeValue+"\"}]}";
        if (attributeKey=="ReadOnly") {
            body = "{\"LookupAttributes\":[{\"AttributeKey\":\""+attributeKey+"\","
                    + "\"AttributeValue\":"+attributeValue+"}]}";
        }
        //请求CloudTrailServer
        Pair<Integer, String> result = callCloudTrailServer(endpointUrlStr,regionName,accessKey,secretKey,action,body, isTarget,headers);

        return result;
    }

    private static Pair<Integer, String> callCloudTrailServer(String endpointUrlStr,String regionName,String accessKey,String secretKey, String action,  String body, boolean isTarget,Map<String, String> headers) {
        Pair<Integer, String> result=new Pair<Integer, String>();
        try {
            URL url = new URL(endpointUrlStr);
            if (headers==null) {
                headers = new HashMap<String, String>();
            }
            
            headers.put("x-amz-content-sha256", UNSIGNED_PAYLOAD);  
            if(isTarget)
                headers.put("x-amz-target", DEFAULT_TARGET + "." + action);  
            else
                headers.put("x-amz-target", "cn.ctyunapi.oos-cn-cloudtrail.CloudTrail_20131101." + action);
            headers.put("Content-Type", "application/json");
            String authorization = V4SignClient.computeV4SignatureDefalut(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                    url, "POST", "cloudtrail", regionName);
            if (accessKey!=null) {
                headers.put("Authorization", authorization);
            }
            HttpsURLConnection connection = HttpConnectionSSLRequestUtils.createhttpsConn(url, "POST", headers);
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

