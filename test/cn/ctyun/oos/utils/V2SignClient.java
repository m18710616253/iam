package cn.ctyun.oos.utils;

import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

import com.amazonaws.AmazonClientException;
import com.amazonaws.auth.SigningAlgorithm;
import com.amazonaws.services.s3.Headers;
import com.amazonaws.services.s3.internal.ServiceUtils;
import com.amazonaws.services.s3.model.ResponseHeaderOverrides;

import cn.ctyun.common.Consts;

public class V2SignClient {
    
    public static String computeV2SignatureDefalut( Map<String, String> headers, Map<String, String> querys,String accessKey,String secretKey,String method,String bucketName,String objectName,boolean endWithSlash,String timestamp) {
        String canonicalString = getCanonicalString(method, toResourcePath(bucketName, objectName, endWithSlash), headers,querys, timestamp);
        System.out.println("canonicalString=\r\n"+canonicalString);
        String signature = sign(canonicalString, secretKey, SigningAlgorithm.HmacSHA1);
        String authorization = "AWS " + accessKey + ":" + signature;
        return authorization;
    }
    
    public void computeV2SignatureSelfHeader() {
        
    }
    
    public static String computeV2PresignedUrlDefalut(URL endpointUrl,Map<String, String> headers, Map<String, String> querys,String accessKey,String secretKey,String method,String bucketName,String objectName,boolean endWithSlash,String expires) {
        String canonicalString = getCanonicalString(method, toResourcePath(bucketName, objectName, endWithSlash), headers,querys, expires);
        System.out.println("canonicalString=\r\n"+canonicalString);
        String signature = sign(canonicalString, secretKey, SigningAlgorithm.HmacSHA1);
        
        StringBuilder authString = new StringBuilder();
        authString.append("AWSAccessKeyId=" + accessKey);
        authString.append("&Expires=" + expires);
        authString.append("&Signature=" + V4SignClient.urlEncode(signature, false));
        if(null != querys.get("X-Amz-Security-Token") && querys.get("X-Amz-Security-Token").length() > 0) {
            authString.append("&x-amz-security-token=" + querys.get("X-Amz-Security-Token"));

        }
        
        String authorizationQueryParameters=authString.toString();

        String presignedUrl="";
        if (endpointUrl.toString().contains("?")) {
            presignedUrl = endpointUrl.toString() + "&" + authorizationQueryParameters;
        }else {
            presignedUrl = endpointUrl.toString() + "?" + authorizationQueryParameters;
        }
        
        System.out.println("presignedUrl:"+presignedUrl);
        return presignedUrl;
    }
    
    public void computeV2PresignedUrlSelfHeader() {
        
    }
    
    public static String sign(String data, String key, SigningAlgorithm algorithm) {
        // refer to com.amazonaws.services.s3.internal.S3Signer
        try {
            Mac mac = Mac.getInstance(algorithm.toString());
            mac.init(new SecretKeySpec(key.getBytes(Consts.STR_UTF8), algorithm.toString()));
            byte[] bs = mac.doFinal(data.getBytes(Consts.STR_UTF8));
            return new String(Base64.encodeBase64(bs), Consts.STR_UTF8);
        } catch (UnsupportedEncodingException e) {
            throw new AmazonClientException("Unable to calculate a request signature: "
                    + e.getMessage(), e);
        } catch (Exception e) {
            throw new AmazonClientException("Unable to calculate a request signature: "
                    + e.getMessage(), e);
        }
    }
    
    /**
     * The set of request parameters which must be included in the canonical
     * string to sign.
     */
    private static final List<String> SIGNED_PARAMETERS = Arrays.asList(new String[] {
            "acl", "torrent", "logging", "location", "policy", "requestPayment", "versioning",
            "versions", "versionId", "notification", "uploadId", "uploads", "partNumber", "website",
            "delete", "lifecycle", "tagging", "cors", "restore",
            ResponseHeaderOverrides.RESPONSE_HEADER_CACHE_CONTROL,
            ResponseHeaderOverrides.RESPONSE_HEADER_CONTENT_DISPOSITION,
            ResponseHeaderOverrides.RESPONSE_HEADER_CONTENT_ENCODING,
            ResponseHeaderOverrides.RESPONSE_HEADER_CONTENT_LANGUAGE,
            ResponseHeaderOverrides.RESPONSE_HEADER_CONTENT_TYPE,
            ResponseHeaderOverrides.RESPONSE_HEADER_EXPIRES,
    });

    /**
     * Calculate the canonical string for a REST/HTTP request to S3.
     *
     * When expires is non-null, it will be used instead of the Date header.
     */
    public static String getCanonicalString(String method, String resource, Map<String, String> headers, Map<String, String> querys,String expires)
    {
        StringBuilder buf = new StringBuilder();
        buf.append(method + "\n");

        // Add all interesting headers to a list, then sort them.  "Interesting"
        // is defined as Content-MD5, Content-Type, Date, and x-amz-
        Map<String, String> headersMap = headers;
        SortedMap<String, String> interestingHeaders = new TreeMap<String, String>();
        if (headersMap != null && headersMap.size() > 0) {
            Iterator<Map.Entry<String, String>> headerIter = headersMap.entrySet().iterator();
            while (headerIter.hasNext()) {
                Map.Entry<String, String> entry = (Map.Entry<String, String>) headerIter.next();
                String key = entry.getKey();
                String value = entry.getValue();

                if (key == null) continue;
                String lk = key.toString().toLowerCase(Locale.getDefault());

                // Ignore any headers that are not particularly interesting.
                if (lk.equals("content-type") || lk.equals("content-md5") || lk.equals("date") ||
                    lk.startsWith(Headers.AMAZON_PREFIX))
                {
                    interestingHeaders.put(lk, value);
                }
            }
        }

        // Remove default date timestamp if "x-amz-date" is set.
        if (interestingHeaders.containsKey(Headers.S3_ALTERNATE_DATE)) {
            interestingHeaders.put("date", "");
        }

        // Use the expires value as the timestamp if it is available. This trumps both the default
        // "date" timestamp, and the "x-amz-date" header.
        if (expires != null) {
            interestingHeaders.put("date", expires);
        }

        // These headers require that we still put a new line in after them,
        // even if they don't exist.
        if (! interestingHeaders.containsKey("content-type")) {
            interestingHeaders.put("content-type", "");
        }
        if (! interestingHeaders.containsKey("content-md5")) {
            interestingHeaders.put("content-md5", "");
        }

        // Any parameters that are prefixed with "x-amz-" need to be included
        // in the headers section of the canonical string to sign
        if (querys!=null) {
            for (Map.Entry<String, String> parameter: querys.entrySet()) {
                if (parameter.getKey().startsWith("x-amz-")) {
                    interestingHeaders.put(parameter.getKey(), parameter.getValue());
                }
            }
        }
        
        // Add all the interesting headers (i.e.: all that startwith x-amz- ;-))
        for (Iterator<Map.Entry<String, String>> i = interestingHeaders.entrySet().iterator(); i.hasNext(); ) {
            Map.Entry<String, String> entry = (Map.Entry<String, String>) i.next();
            String key = (String) entry.getKey();
            Object value = entry.getValue();

            if (key.startsWith(Headers.AMAZON_PREFIX)) {
                buf.append(key).append(':').append(value);
            } else {
                buf.append(value);
            }
            buf.append("\n");
        }

        // Add all the interesting parameters
        buf.append(resource);
        if (querys!=null) {
            String[] parameterNames = querys.keySet().toArray(
                    new String[querys.size()]);
            Arrays.sort(parameterNames);
            char separator = '?';
            for (String parameterName : parameterNames) {
                // Skip any parameters that aren't part of the canonical signed string
                if (SIGNED_PARAMETERS.contains(parameterName) == false) continue;

                buf.append(separator);
                buf.append(parameterName);
                String parameterValue = querys.get(parameterName);
                if (parameterValue != null&&parameterValue!="") {
                    buf.append("=").append(parameterValue);
                }

                separator = '&';
            }

        }
        
        return buf.toString();
    }
    
    public static String toResourcePath(String bucket, String key, boolean endWithSlash) {
        // refer to com.amazonaws.services.s3.AmazonS3Client.createSigner
        // 增加对斜杠的判断
        String resourcePath;
        if (endWithSlash)
            resourcePath = "/" + ((bucket != null && !bucket.equals("")) ? bucket + "/" : "")
                    + ((key != null) ? key : "");
        else
            resourcePath = "/" + ((bucket != null && !bucket.equals("")) ? bucket : "")
                    + ((key != null) ? "/" + key : "");
        return resourcePath;
    }
    
    
}
