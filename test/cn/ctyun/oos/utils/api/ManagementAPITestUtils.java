package cn.ctyun.oos.utils.api;

import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.client.HBaseAdmin;
import org.eclipse.jetty.util.UrlEncoded;

import cn.ctyun.common.conf.GlobalHHZConfig;
import cn.ctyun.oos.hbase.HBaseRole;
import cn.ctyun.oos.hbase.HBaseUserToRole;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.test.oosaccesscontrol.OOSInterfaceTestUtils;
import cn.ctyun.oos.metadata.RoleMeta;
import cn.ctyun.oos.metadata.UserToRoleMeta;
import cn.ctyun.oos.metadata.RoleMeta.RolePermission;
import cn.ctyun.oos.utils.HttpConnectionSSLRequestUtils;
import cn.ctyun.oos.utils.V2SignClient;
import cn.ctyun.oos.utils.V4SignClient;
import common.time.TimeUtils;
import common.tuple.Pair;

public class ManagementAPITestUtils {
    public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";

    public static Pair<Integer, String> GetUsage(String httpOrHttps,String host,int port,String signVersion,String regionName,String ak,String sk,String beginDate,String endDate,String bucketName,String freq,Map<String, String> headers){
        String Action="GetUsage";
        String param = JoinBeginEndDate(Action, beginDate, endDate, bucketName, freq, null,null,null,null,null,null,null);
        String urlStr = httpOrHttps+"://" + host + ":" + port+"/?"+param;
        
        Map<String, String> querys=getQuerys(param);

        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps,signVersion, regionName, ak, sk, "GET", null, null, headers, querys, null, 80);
        try {
            conn.setRequestMethod("GET");
        } catch (ProtocolException e) {
            e.printStackTrace();
        }
        conn.setRequestProperty("Host", host + ":" + port);
        return OOSInterfaceTestUtils.GetResult(conn);
    }
    
    /*
     * 需要先添加role
     */
    public static Pair<Integer, String> GetAvailBW(String httpOrHttps,String host,int port,String signVersion,String regionName,String ak,String sk,String beginDate,String endDate,String pools,Map<String, String> headers) {
        
        String Action="GetAvailBW";
        String param = JoinBeginEndDate(Action, beginDate, endDate, null, null, null,null,null,null,null,null,pools);
        String urlStr = httpOrHttps+"://" + host + ":" + port+"/?"+param;

        Map<String, String> querys=getQuerys(param);
        
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,ak, sk, "GET", null, null, headers, querys, null, 80);
        try {
            conn.setRequestMethod("GET");
        } catch (ProtocolException e) {
            e.printStackTrace();
        }
        conn.setRequestProperty("Host", host + ":" + port);
        
        return OOSInterfaceTestUtils.GetResult(conn);
    }
    
    public static Pair<Integer, String> GetBandwidth(String httpOrHttps,String host,int port,String signVersion,String regionName,String ak,String sk,String beginDate,String endDate,String bucketName,Map<String, String> headers) {
        String Action="GetBandwidth";
        String param = JoinBeginEndDate(Action, beginDate, endDate, null, null, null, null, null, null, null, null, null);
        String urlStr = httpOrHttps+"://" + host + ":" + port+"/?"+param;

        Map<String, String> querys=getQuerys(param);
        
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,ak, sk, "GET", null, null, headers, querys, null, 80);
        try {
            conn.setRequestMethod("GET");
        } catch (ProtocolException e) {
            e.printStackTrace();
        }
        conn.setRequestProperty("Host", host + ":" + port);
        
        return OOSInterfaceTestUtils.GetResult(conn);
    }
    
    public static Pair<Integer, String> GetConnection(String httpOrHttps,String host,int port,String signVersion,String regionName,String ak,String sk,String beginDate,String endDate,String bucketName,Map<String, String> headers) {
        String Action="GetConnection";
        String param = JoinBeginEndDate(Action, beginDate, endDate, null, null, null, null, null, null, null, null, null);
        String urlStr = httpOrHttps+"://" + host + ":" + port+"/?"+param;

        Map<String, String> querys=getQuerys(param);
        
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,ak, sk, "GET", null, null, headers, querys, null, 80);
        try {
            conn.setRequestMethod("GET");
        } catch (ProtocolException e) {
            e.printStackTrace();
        }
        conn.setRequestProperty("Host", host + ":" + port);
        
        return OOSInterfaceTestUtils.GetResult(conn);
    }
    
    public static Pair<Integer, String> GetCapacity(String httpOrHttps,String host,int port,String signVersion,String regionName,String ak,String sk,String beginDate,String endDate,String bucketName,String freq,String region,Map<String, String> headers) {
        String Action="GetCapacity";

        String param = JoinBeginEndDate(Action, beginDate, endDate, bucketName, freq, region,null,null,null,null,null,null);
        String urlStr = httpOrHttps+"://" + host + ":" + port+"/?"+param;

        Map<String, String> querys=getQuerys(param);
        
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,ak, sk, "GET", null, null, headers, querys, null, 80);
        try {
            conn.setRequestMethod("GET");
        } catch (ProtocolException e) {
            e.printStackTrace();
        }
        conn.setRequestProperty("Host", host + ":" + port);
        return OOSInterfaceTestUtils.GetResult(conn);
    }
    
    public static Pair<Integer, String> GetDeleteCapacity(String httpOrHttps,String host,int port,String signVersion,String regionName,String ak,String sk,String beginDate,String endDate,String bucketName,String freq,String region,Map<String, String> headers) {
        String Action="GetDeleteCapacity";
        String param = JoinBeginEndDate(Action, beginDate, endDate, bucketName, freq, region,null,null,null,null,null,null);
        String urlStr = httpOrHttps+"://" + host + ":" + port+"/?"+param;

        Map<String, String> querys=getQuerys(param);
        
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion,regionName, ak, sk, "GET", null, null, headers, querys, null, 80);
        try {
            conn.setRequestMethod("GET");
        } catch (ProtocolException e) {
            e.printStackTrace();
        }
        conn.setRequestProperty("Host", host + ":" + port);
        return OOSInterfaceTestUtils.GetResult(conn);
    }
    
    public static Pair<Integer, String> GetTraffics(String httpOrHttps,String host,int port,String signVersion,String regionName,String ak,String sk,String beginDate,String endDate,String bucketName,String freq,String region,String inOutType,String internetType,String trafficsType,Map<String, String> headers) {
        String Action="GetTraffics";
        String param = JoinBeginEndDate(Action, beginDate, endDate, bucketName, freq, region,inOutType,internetType,trafficsType,null,null,null);
        String urlStr = httpOrHttps+"://" + host + ":" + port+"/?"+param;

        Map<String, String> querys=getQuerys(param);
        
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,ak, sk, "GET", null, null, headers, querys, null, 80);
        try {
            conn.setRequestMethod("GET");
        } catch (ProtocolException e) {
            e.printStackTrace();
        }
        conn.setRequestProperty("Host", host + ":" + port);
        return OOSInterfaceTestUtils.GetResult(conn);
    }
    
    public static Pair<Integer, String> GetAvailableBandwidth(String httpOrHttps,String host,int port,String signVersion,String regionName,String ak,String sk,String beginDate,String endDate,String freq,String region,String inOutType,String internetType,Map<String, String> headers) {
        String Action="GetAvailableBandwidth";
        String param = JoinBeginEndDate(Action, beginDate, endDate, null, freq, region,inOutType,internetType,null,null,null,null);
        String urlStr = httpOrHttps+"://" + host + ":" + port+"/?"+param;

        Map<String, String> querys=getQuerys(param);
        
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,ak, sk, "GET", null, null, headers, querys, null, 80);
        try {
            conn.setRequestMethod("GET");
        } catch (ProtocolException e) {
            e.printStackTrace();
        }
        conn.setRequestProperty("Host", host + ":" + port);
        return OOSInterfaceTestUtils.GetResult(conn);
    }
    
    public static Pair<Integer, String> GetRequests(String httpOrHttps,String host,int port,String signVersion,String regionName,String ak,String sk,String beginDate,String endDate,String bucketName,String freq,String region,String internetType,String requestsType,Map<String, String> headers) {
        String Action="GetRequests";
        String param = JoinBeginEndDate(Action, beginDate, endDate, bucketName, freq, region,null,internetType,null,requestsType,null,null);
        String urlStr = httpOrHttps+"://" + host + ":" + port+"/?"+param;
        
        Map<String, String> querys=getQuerys(param);
        
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,ak, sk, "GET", null, null, headers, querys, null, 80);
        try {
            conn.setRequestMethod("GET");
        } catch (ProtocolException e) {
            e.printStackTrace();
        }
        conn.setRequestProperty("Host", host + ":" + port);
        return OOSInterfaceTestUtils.GetResult(conn);
    }
    
    public static Pair<Integer, String> GetReturnCode(String httpOrHttps,String host,int port,String signVersion,String regionName,String ak,String sk,String beginDate,String endDate,String bucketName,String freq,String region,String internetType,String requestsType,String responseType,Map<String, String> headers) {
        String Action="GetReturnCode";
        String param = JoinBeginEndDate(Action, beginDate, endDate, bucketName, freq, region,null,internetType,null,requestsType,responseType,null);
        String urlStr = httpOrHttps+"://" + host + ":" + port+"/?"+param;

        Map<String, String> querys=getQuerys(param);
        
        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,ak, sk, "GET", null, null, headers, querys, null, 80);
        try {
            conn.setRequestMethod("GET");
        } catch (ProtocolException e) {
            e.printStackTrace();
        }
        conn.setRequestProperty("Host", host + ":" + port);
        return OOSInterfaceTestUtils.GetResult(conn);
    }
      
    public static Pair<Integer, String> GetConcurrentConnection(String httpOrHttps,String host,int port,String signVersion,String regionName,String ak,String sk,String beginDate,String endDate,String bucketName,String freq,String region,String internetType,Map<String, String> headers) {
        String Action="GetConcurrentConnection";
        String param = JoinBeginEndDate(Action, beginDate, endDate, bucketName, freq, region,null,internetType,null,null,null,null);
        String urlStr = httpOrHttps+"://" + host + ":" + port+"/?"+param;
        
        Map<String, String> querys=getQuerys(param);

        HttpURLConnection conn=CreateConn(urlStr, httpOrHttps, signVersion, regionName,ak, sk, "GET", null, null, headers, querys, null, 80);
        try {
            conn.setRequestMethod("GET");
        } catch (ProtocolException e) {
            e.printStackTrace();
        }
        conn.setRequestProperty("Host", host + ":" + port);
        return OOSInterfaceTestUtils.GetResult(conn);
    }
    
    
    public static String JoinBeginEndDate(String Action, String beginDate, String endDate,
            String bucketName, String freq, String region,String inOutType,String internetType,String trafficsType,String requestsType,String responseType,String pools) {
        StringBuilder sb = new StringBuilder();
        sb.append("Action=").append(Action);
        sb.append("&BeginDate=").append(beginDate).append("&EndDate=").append(endDate);
        if (bucketName!= null) {
            sb.append("&BucketName=").append(bucketName);
        }
        if (freq!=null) {
            sb.append("&Freq=").append(freq);
        }
        if (region!=null) {
            sb.append("&Region=").append(region);
        }
        if (inOutType!=null) {
            sb.append("&InOutType=").append(inOutType);
        }
        if (internetType!=null) {
            sb.append("&InternetType=").append(internetType);
        }
        if (trafficsType!=null) {
            sb.append("&TrafficsType=").append(trafficsType);
        }
        if (requestsType!=null) {
            sb.append("&RequestsType=").append(requestsType);
        }
        if (responseType!=null) {
            sb.append("&ResponseType=").append(responseType);
        }
        if (pools!=null) {
            sb.append("&Pools=").append(pools);
        }
        
        System.out.println(sb);
        return sb.toString();
    }
    
    
    
    private static Map<String, String> getQuerys(String param) {
        Map<String, String> querys = new HashMap<String, String>();
        if (param.contains("&")) {
            String [] keyvalues=param.split("&");
            for (int i = 0; i < keyvalues.length; i++) {
                String [] kv=keyvalues[i].split("=");
                if (kv.length<2) {
                    querys.put(kv[0], "");
                }else {
                    querys.put(kv[0], kv[1]);
                }
                
            }
        }else {
            String [] kv=param.split("=");
            querys.put(kv[0], kv[1]);
        }
        return querys;
    }
    
    public static HttpURLConnection CreatehttpConn(URL url, String method, Map<String, String> headers) throws Exception{
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod(method);
        if (headers != null) {
//            System.out.println("--------- Request headers ---------");
            for (String headerKey : headers.keySet()) {
//                System.out.println(headerKey + ": " + headers.get(headerKey));
                connection.setRequestProperty(headerKey, headers.get(headerKey));
            }
        }
        connection.setUseCaches(false);
        connection.setDoInput(true);
        connection.setDoOutput(true);
        return connection;
    }
    
    public static HttpURLConnection CreateConn(String urlStr,String httpOrHttps,String signVersion,String regionName,String accessKey,String secretKey,String method,String bucketName,String objectName,Map<String, String> headers,Map<String, String> querys,String bodyHash,int jettyPort) {
        HttpURLConnection conn=null;
        try {
            URL url = new URL(urlStr);
            
            if (headers==null) {
                headers = new HashMap<String, String>();
            }
            
            if (querys==null) {
                querys = new HashMap<String, String>();
            }
            
            if (signVersion.equals("V4")) {
                System.out.println("V4");
                if (bodyHash==null) {
                    bodyHash=UNSIGNED_PAYLOAD;
                }
                String authorization = V4SignClient.computeV4SignatureDefalut(headers, querys, bodyHash, accessKey, secretKey, 
                        url, method, "s3", regionName);
                if (accessKey!=null) {
                    headers.put("Authorization", authorization);
                }
                
                if (httpOrHttps.equals("https")) {
                    conn=HttpConnectionSSLRequestUtils.createhttpsConn(url, method, headers);
                    System.out.println(" url="+url.toString());
                }else {
                    conn=CreatehttpConn(url, method, headers);
                    System.out.println("url="+url.toString());
                }
                
            }else {
                System.out.println("V2");
                String date = TimeUtils.toGMTFormat(new Date());
                headers.put("Date", date);
                if (httpOrHttps.equals("https")) {
                    conn=HttpConnectionSSLRequestUtils.createhttpsConn(url, method, headers);
                    System.out.println("url="+url.toString());
                    
                }else {
                    conn=CreatehttpConn(url, method, headers);
                    System.out.println("url="+url.toString());
                }
                
                if (headers != null) {
                    for (String headerKey : headers.keySet()) {
                        conn.setRequestProperty(headerKey, headers.get(headerKey));
                    }
                }
                String authorization = V2SignClient.computeV2SignatureDefalut(headers,querys,accessKey,secretKey,method,bucketName,objectName,false,null);
                conn.setRequestProperty("Authorization", authorization);  
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return conn;
    }
}
