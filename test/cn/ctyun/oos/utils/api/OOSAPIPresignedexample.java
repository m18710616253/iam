package cn.ctyun.oos.utils.api;

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import cn.ctyun.oos.utils.HttpConnectionSSLRequestUtils;
import common.tuple.Pair;

public class OOSAPIPresignedexample {


    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
    }

    @Before
    public void setUp() throws Exception {
    }

    @Test
    public void test() {
        String httpOrHttps="https";
        String jettyhost="oos-cd.ctyunapi.cn";
        int jettyPort=8444;
        String regionName="cd";
        String accessKey="userak1";
        String secretKey="usersk1";
        
        String bucketName="yx-bucket-1";
        String objectName="object1.txt";
        String objectName2="mulit1.txt";
        String objectName3="mulit2.txt";
        String objectName4="mulit3.txt";
        String objectContent="first";
        
        List<String> headers =null;
        List<String> querys =null;
        
        String putobjectv4url=OOSAPIPresignedUrlUtils.Object_Put_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName, objectContent, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn=creatConn(putobjectv4url, "PUT", CreateHeaders(headers));
        try {
            OutputStream wr = conn.getOutputStream();
            wr.write(objectContent.getBytes());
            wr.flush();
            wr.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        Pair<Integer, String> putobjectv4result=OOSAPITestUtils.GetResult(conn);
        assertEquals(200, putobjectv4result.first().intValue());
        
        // get head v4
        String getobjectv4url=OOSAPIPresignedUrlUtils.Object_Get_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName,CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn1=creatConn(getobjectv4url, "GET", CreateHeaders(headers));
        Pair<Integer, String> getobjectv4result=OOSAPITestUtils.GetResult(conn1);
        assertEquals(200, getobjectv4result.first().intValue());
        
        String headobjectv4url=OOSAPIPresignedUrlUtils.Object_Head_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName,CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn2=creatConn(headobjectv4url, "HEAD", CreateHeaders(headers));
        try {
            conn2.connect();
            int code = conn2.getResponseCode();
            assertEquals(200, code);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // get v2
        String getobjectv2url=OOSAPIPresignedUrlUtils.Object_get_V2_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName,CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn3=creatConn(getobjectv2url, "GET", CreateHeaders(headers));
        Pair<Integer, String> getobjectv2result=OOSAPITestUtils.GetResult(conn3);
        assertEquals(200, getobjectv2result.first().intValue());
        
        // delete v4
        String delobjectv4url=OOSAPIPresignedUrlUtils.Object_Delete_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName,CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn4=creatConn(delobjectv4url, "DELETE", CreateHeaders(headers));
        Pair<Integer, String> delobjectv4result=OOSAPITestUtils.GetResult(conn4);
        assertEquals(204, delobjectv4result.first().intValue());
        
//         initial v4
        String initialobjectv4url=OOSAPIPresignedUrlUtils.Object_InitialMultipartUpload_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName2,CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn5=creatConn(initialobjectv4url, "POST", CreateHeaders(headers));
        Pair<Integer, String> initialobjectv4result=OOSAPITestUtils.GetResult(conn5);
        assertEquals(200, initialobjectv4result.first().intValue());
        String uploadId1=OOSAPITestUtils.getMultipartUploadId(initialobjectv4result.second());
        
        // upload v4
        String partContent1="123";
        String partContent2="456";
        String etag1="";
        String etag2="";
        String uploadobjectv4url1=OOSAPIPresignedUrlUtils.Object_UploadPart_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName2,uploadId1, 1, partContent1, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn6=creatConn(uploadobjectv4url1, "PUT", CreateHeaders(headers));
        try {
            
            OutputStream wr = conn6.getOutputStream();
            wr.write(partContent1.getBytes());
            wr.flush();
            wr.close();
            
            conn6.connect();
            
            int code = conn6.getResponseCode();
            assertEquals(200, code);
            String etag = conn6.getHeaderField("ETag");
            etag1=etag;
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        String uploadobjectv4url2=OOSAPIPresignedUrlUtils.Object_UploadPart_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName2,uploadId1, 2, partContent2, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn7=creatConn(uploadobjectv4url2, "PUT", CreateHeaders(headers));
        try {
            
            OutputStream wr = conn7.getOutputStream();
            wr.write(partContent2.getBytes());
            wr.flush();
            wr.close();
            
            conn7.connect();
            
            int code = conn7.getResponseCode();
            assertEquals(200, code);
            String etag = conn7.getHeaderField("ETag");
            etag2=etag;
            
        } catch (Exception e) {
            e.printStackTrace();
        }

        // list part v4 v2
        String listpartv4url=OOSAPIPresignedUrlUtils.Object_ListPart_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName2,uploadId1, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn8=creatConn(listpartv4url, "GET", CreateHeaders(headers));
        Pair<Integer, String> listpartv4result=OOSAPITestUtils.GetResult(conn8);
        assertEquals(200, listpartv4result.first().intValue());
        
        String listpartv2url=OOSAPIPresignedUrlUtils.Object_ListPart_V2_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName2,uploadId1, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn9=creatConn(listpartv2url, "GET", CreateHeaders(headers));
        Pair<Integer, String> listpartv2result=OOSAPITestUtils.GetResult(conn9);
        assertEquals(200, listpartv2result.first().intValue());
        
        // complete v4
       
        Map<String, String> partEtagMap = new HashMap<String, String>();
        partEtagMap.put("1", etag1);
        partEtagMap.put("2", etag2);
        String completeString=OOSAPIPresignedUrlUtils.createCompleteMultipartUploadBody(partEtagMap);
        System.out.println("completeString="+completeString);
        String completev4url=OOSAPIPresignedUrlUtils.Object_CompleteMultipartUpload_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName2,uploadId1, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn10=creatConn(completev4url, "POST", CreateHeaders(headers));
        try {
            OutputStream wr = conn10.getOutputStream();
            wr.write(completeString.getBytes());
            wr.flush();
            wr.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        Pair<Integer, String> completev4result=OOSAPITestUtils.GetResult(conn10);
        assertEquals(200, completev4result.first().intValue());

        // initial v2
        String initialobjectv2url=OOSAPIPresignedUrlUtils.Object_InitialMultipartUpload_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName3,CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn11=creatConn(initialobjectv2url, "POST", CreateHeaders(headers));
        Pair<Integer, String> initialobjectv2result=OOSAPITestUtils.GetResult(conn11);
        assertEquals(200, initialobjectv2result.first().intValue());
        String uploadId2=OOSAPITestUtils.getMultipartUploadId(initialobjectv2result.second());
        
        // upload v4
        String etag3="";
        String etag4="";
        String uploadobjectv4url3=OOSAPIPresignedUrlUtils.Object_UploadPart_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName3,uploadId2, 1, partContent1, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn12=creatConn(uploadobjectv4url3, "PUT", CreateHeaders(headers));
        try {
            
            OutputStream wr = conn12.getOutputStream();
            wr.write(partContent1.getBytes());
            wr.flush();
            wr.close();
            
            conn12.connect();
            int code = conn12.getResponseCode();
            assertEquals(200, code);
            String etag = conn12.getHeaderField("ETag");
            etag3=etag;
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        String uploadobjectv4url4=OOSAPIPresignedUrlUtils.Object_UploadPart_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName3,uploadId2, 2, partContent2, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn13=creatConn(uploadobjectv4url4, "PUT", CreateHeaders(headers));
        try {
            
            OutputStream wr = conn13.getOutputStream();
            wr.write(partContent2.getBytes());
            wr.flush();
            wr.close();
            
            conn13.connect();
            
            int code = conn13.getResponseCode();
            assertEquals(200, code);
            String etag = conn13.getHeaderField("ETag");
            etag4=etag;
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        // complete v2
        Map<String, String> partEtagMap2 = new HashMap<String, String>();
        partEtagMap2.put("1", etag3);
        partEtagMap2.put("2", etag4);
        String completeString2=OOSAPIPresignedUrlUtils.createCompleteMultipartUploadBody(partEtagMap2);
        String completev2url=OOSAPIPresignedUrlUtils.Object_CompleteMultipartUpload_V2_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName3,uploadId2, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn14=creatConn(completev2url, "POST", CreateHeaders(headers));
        try {
            OutputStream wr = conn14.getOutputStream();
            wr.write(completeString2.getBytes());
            wr.flush();
            wr.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        Pair<Integer, String> completev2result=OOSAPITestUtils.GetResult(conn14);
        assertEquals(200, completev2result.first().intValue());
        
        // initial upload v4
        String initialobjectv4url3=OOSAPIPresignedUrlUtils.Object_InitialMultipartUpload_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName4,CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn15=creatConn(initialobjectv4url3, "POST", CreateHeaders(headers));
        Pair<Integer, String> initialobjectv4result3=OOSAPITestUtils.GetResult(conn15);
        assertEquals(200, initialobjectv4result3.first().intValue());
        String uploadId3=OOSAPITestUtils.getMultipartUploadId(initialobjectv4result3.second());
        
        // upload v4
        String uploadobjectv4url5=OOSAPIPresignedUrlUtils.Object_UploadPart_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName4,uploadId3, 1, partContent1, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn16=creatConn(uploadobjectv4url5, "PUT", CreateHeaders(headers));
        try {
            
            OutputStream wr = conn16.getOutputStream();
            wr.write(partContent1.getBytes());
            wr.flush();
            wr.close();
            
            conn16.connect();
            
            int code = conn16.getResponseCode();
            assertEquals(200, code);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        String uploadobjectv4url6=OOSAPIPresignedUrlUtils.Object_UploadPart_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName4,uploadId3, 2, partContent2, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn17=creatConn(uploadobjectv4url6, "PUT", CreateHeaders(headers));
        try {
            
            OutputStream wr = conn17.getOutputStream();
            wr.write(partContent2.getBytes());
            wr.flush();
            wr.close();
            
            conn17.connect();
            
            int code = conn17.getResponseCode();
            assertEquals(200, code);
            
        } catch (Exception e) {
            e.printStackTrace();
        }

        // abort v4
        String abortv4url=OOSAPIPresignedUrlUtils.Object_AboutMultipartUpload_V4_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName, objectName4,uploadId3, CreateHeaders(headers), CreateHeaders(querys));
        HttpURLConnection conn18=creatConn(abortv4url, "DELETE", CreateHeaders(headers));
        Pair<Integer, String> abortv4result=OOSAPITestUtils.GetResult(conn18);
        assertEquals(204, abortv4result.first().intValue());
        
        // deletemuli v2
        String delbodyString=OOSAPIPresignedUrlUtils.createDeleteMulitBody(Arrays.asList(objectName2,objectName3,objectName4), false);
        
        HashMap<String, String> mulidelheaders=CreateHeaders(headers);
        mulidelheaders.put("content-type", "application/x-www-form-urlencoded");
        mulidelheaders.put("Content-MD5", OOSAPIPresignedUrlUtils.getMD5(delbodyString));
        mulidelheaders.put("Content-Length",String.valueOf(delbodyString.length()));
        String deletemuliv2url=OOSAPIPresignedUrlUtils.Object_DeleteMulit_V2_PresignedUrl(httpOrHttps, jettyhost, jettyPort, regionName, accessKey, secretKey, bucketName,delbodyString, mulidelheaders, CreateHeaders(querys));
         
        HttpURLConnection conn19=creatConn(deletemuliv2url, "POST", mulidelheaders);
        try {
            OutputStream wr = conn19.getOutputStream();
            wr.write(delbodyString.getBytes());
            wr.flush();
            wr.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        Pair<Integer, String> deletemuliv2result=OOSAPITestUtils.GetResult(conn19);
        assertEquals(200, deletemuliv2result.first().intValue());
    }
    
    public static HttpURLConnection creatConn(String presignedUrl,String method,Map<String, String> headers) {
        HttpURLConnection conn=null;
        try {
            if (presignedUrl.startsWith("https")) {
                conn=HttpConnectionSSLRequestUtils.createhttpsConn(new URL(presignedUrl), method, headers);
            }else {
                conn=CreatehttpConn(new URL(presignedUrl), method, headers);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        
        return conn;
    }
    
    public static HttpURLConnection CreatehttpConn(URL url, String method, Map<String, String> headers) {
       
        try {
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod(method);
            if (headers != null) {
//                System.out.println("--------- Request headers ---------");
                for (String headerKey : headers.keySet()) {
//                    System.out.println(headerKey + ": " + headers.get(headerKey));
                    connection.setRequestProperty(headerKey, headers.get(headerKey));
                }
            }
            
            connection.setUseCaches(false);
            connection.setDoInput(true);
            connection.setDoOutput(true);
            return connection;
        } catch (Exception e) {
            e.printStackTrace();
        }
        
       return null;
    }
    
    public static Pair<Integer, String> GetResult(HttpURLConnection conn) {
        Pair<Integer, String> result= new Pair<Integer, String>();
        try {
            conn.connect();
            
            int code = conn.getResponseCode();
            System.out.println("code="+code);
            result.first(code);
            String xml="";
            if (code==200||code==204) {
                xml=IOUtils.toString(conn.getInputStream());
                
            }else {
                xml= IOUtils.toString(conn.getErrorStream());
            }
            
            System.out.println(xml);
            result.second(xml);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return result;
    }
    
    private static HashMap<String, String> CreateHeaders(List<String> propertys) {
        HashMap<String, String> headers = new HashMap<String, String>();
        if (propertys!=null&&propertys.size()%2==0) {
            int i=0;
            while (i<propertys.size()) {
                headers.put(propertys.get(i), propertys.get(i+1));
                i+=2;
                
            }
        }
        return headers;
    }

}
