package cn.ctyun.oos.utils;

import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.SortedMap;
import java.util.TimeZone;
import java.util.TreeMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.amazonaws.util.BinaryUtils;

public class V4SignClient {
    private static SimpleDateFormat timeFormatter = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
    private static SimpleDateFormat dateFormatter = new SimpleDateFormat("yyyyMMdd");
    /** SHA256 hash of an empty request body **/
    public static final String EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
    public static final String SCHEME = "AWS4";
    public static final String ALGORITHM = "HMAC-SHA256";
    public static final String TERMINATOR = "aws4_request";
    public static final String HMAC_SHA256 = "HmacSHA256";
    static{
        TimeZone utc = TimeZone.getTimeZone("UTC");
        timeFormatter.setTimeZone(utc);
        dateFormatter.setTimeZone(utc);
    }
    
    /*
     *  常用默认签名,用于测试内容跟签名无关
     */
    public static String computeV4SignatureDefalut(Map<String, String> headers,
            Map<String, String> queryParameters,
            String bodyHash,
            String accessKey,
            String secretKey,
            URL endpointUrl,
            String httpMethod,
            String serviceName,
            String regionName) {
     // first get the date and time for the subsequent request, and convert
        // to ISO 8601 format for use in signature generation
        Date now = new Date();
        String dateTimeStamp = timeFormatter.format(now);

        // update the headers with required 'x-amz-date' and 'host' values
        if(headers==null) {
            headers = new HashMap<String, String>();
        }
        headers.put("x-amz-date", dateTimeStamp);
        headers.put("x-amz-content-sha256", bodyHash);
        
        String hostHeader = endpointUrl.getHost();
        int port = endpointUrl.getPort();
        if ( port > -1 && port != 80) {
            hostHeader = hostHeader.concat(":" + Integer.toString(port));
        }
        headers.put("Host", hostHeader);
        
        // canonicalize the headers; we need the set of header names as well as the
        // names and values to go into the signature process
        String canonicalizedHeaderNames = getCanonicalizeHeaderNames(headers);
        String canonicalizedHeaders = getCanonicalizedHeaderString(headers);
        
        // if any query string parameters have been supplied, canonicalize them
        String canonicalizedQueryParameters = getCanonicalizedQueryString(queryParameters);
        
        // canonicalize the various components of the request
        String canonicalRequest = getCanonicalRequest(endpointUrl, httpMethod,
                canonicalizedQueryParameters, canonicalizedHeaderNames,
                canonicalizedHeaders, bodyHash);
        System.out.println("--------- Canonical request --------");
        System.out.println(canonicalRequest);
        System.out.println("------------------------------------");
        
        // construct the string to be signed
        String dateStamp = dateFormatter.format(now);
        String scope =  dateStamp + "/" + regionName + "/" + serviceName + "/" + TERMINATOR;
        String stringToSign = getStringToSign(SCHEME, ALGORITHM, dateTimeStamp, scope, canonicalRequest);
        System.out.println("--------- String to sign -----------");
        System.out.println(stringToSign);
        System.out.println("------------------------------------");
        
        // compute the signing key
        byte[] kSigning =createSignatureKey(secretKey, dateStamp, regionName, serviceName);
        byte[] signature = sign(stringToSign, kSigning, "HmacSHA256");
        
        
        String credentialsAuthorizationHeader = "Credential=" + accessKey + "/" + scope;
        String signedHeadersAuthorizationHeader = "SignedHeaders=" + canonicalizedHeaderNames;
        String signatureAuthorizationHeader = "Signature=" + toHex(signature);

        String authorizationHeader = SCHEME + "-" + ALGORITHM + " "
                + credentialsAuthorizationHeader + ", "
                + signedHeadersAuthorizationHeader + ", "
                + signatureAuthorizationHeader;

        return authorizationHeader;
    }
    
    /*
     * 自定义请求头签名，用于测试与签名相关请求头
     */
    public static String computeV4SignatureSelfHeader(Map<String, String> headers,
            Map<String, String> queryParameters,
            String bodyHash,
            String accessKey,
            String secretKey,
            URL endpointUrl,
            String httpMethod,
            String serviceName,
            String regionName, Date now) {
        String dateTimeStamp = timeFormatter.format(now);
        String canonicalizedHeaderNames = getCanonicalizeHeaderNames(headers);
        String canonicalizedHeaders = getCanonicalizedHeaderString(headers);
        String canonicalizedQueryParameters = getCanonicalizedQueryString(queryParameters);
        String canonicalRequest = getCanonicalRequest(endpointUrl, httpMethod,
                canonicalizedQueryParameters, canonicalizedHeaderNames,
                canonicalizedHeaders, bodyHash);
        System.out.println("--------- Canonical request --------");
        System.out.println(canonicalRequest);
        System.out.println("------------------------------------");
        String dateStamp = dateFormatter.format(now);
        String scope =  dateStamp + "/" + regionName + "/" + serviceName + "/" + TERMINATOR;
        String stringToSign = getStringToSign(SCHEME, ALGORITHM, dateTimeStamp, scope, canonicalRequest);
        System.out.println("--------- String to sign -----------");
        System.out.println(stringToSign);
        System.out.println("------------------------------------");
        
        
        byte[] kSigning = createSignatureKey(secretKey, dateStamp, regionName, serviceName);
        byte[] signature = sign(stringToSign, kSigning, "HmacSHA256");
        
        String credentialsAuthorizationHeader = "Credential=" + accessKey + "/" + scope;
        String signedHeadersAuthorizationHeader = "SignedHeaders=" + canonicalizedHeaderNames;
        String signatureAuthorizationHeader = "Signature=" + toHex(signature);

        String authorizationHeader = SCHEME + "-" + ALGORITHM + " "
                + credentialsAuthorizationHeader + ", "
                + signedHeadersAuthorizationHeader + ", "
                + signatureAuthorizationHeader;

        return authorizationHeader;
        
    }
    
    /*
     *  常用默认预签名,用于测试内容跟预签名无关
     */
    public static String computeV4PresignedUrlDefalut(Map<String, String> headers,
            Map<String, String> queryParameters,
            String accessKey,
            String secretKey,
            URL endpointUrl,
            String httpMethod,
            String serviceName,
            String regionName) {
        
        // construct the query parameter string to accompany the url
        if (queryParameters==null) {
            queryParameters = new HashMap<String, String>();
        }
        
        if (headers==null) {
            headers = new HashMap<String, String>();
        }
         
        // for SignatureV4, the max expiry for a presigned url is 7 days, expressed in seconds
        int expiresIn = 7 * 24 * 60 * 60;
        queryParameters.put("X-Amz-Expires", "" + expiresIn);
              
        String authorizationQueryParameters = computeSignatureForQueryparameters(headers, 
                                                       queryParameters,
                                                       UNSIGNED_PAYLOAD, // for a presigned url, use a constant string UNSIGNED-PAYLOAD
                                                       accessKey, 
                                                       secretKey,
                                                       endpointUrl, 
                                                       httpMethod, 
                                                       serviceName, 
                                                       regionName);
                
        // build the presigned url to incorporate the authorization elements as query parameters
        String presignedUrl="";
        if (endpointUrl.toString().contains("?")) {
            presignedUrl = endpointUrl.toString() + "&" + authorizationQueryParameters;
        }else {
            presignedUrl = endpointUrl.toString() + "?" + authorizationQueryParameters;
        }
        
//        System.out.println("presignedUrl:"+presignedUrl);
        return presignedUrl;
    }
    
    /*
     * 自定义请求头预签名，用于测试与预签名相关请求头
     */
    public static String computeV4PresignedUrlSelfHeader(Map<String, String> headers,
            Map<String, String> queryParameters,
            String bodyHash,
            String accessKey,
            String secretKey,
            URL endpointUrl,
            String httpMethod,
            String serviceName,
            String regionName,Date now) {
        if (queryParameters==null) {
            queryParameters = new HashMap<String, String>();
        }
        
        if (headers==null) {
            headers = new HashMap<String, String>();
        }
        
        String authorizationQueryParameters = computeSignatureForQueryparametersHeaders(headers,
                queryParameters,
                bodyHash,
                accessKey,
                secretKey,
                endpointUrl,
                httpMethod,
                serviceName,
                regionName,now);
        
        String presignedUrl="";
        if (endpointUrl.toString().contains("?")) {
            presignedUrl = endpointUrl.toString() + "&" + authorizationQueryParameters;
        }else {
            presignedUrl = endpointUrl.toString() + "?" + authorizationQueryParameters;
        }
        
//        System.out.println("presignedUrl:"+presignedUrl);
        return presignedUrl;
    }
    
    public static String computeSignatureForQueryparameters(Map<String, String> headers,
            Map<String, String> queryParameters,
            String bodyHash,
            String accessKey,
            String secretKey,
            URL endpointUrl,
            String httpMethod,
            String serviceName,
            String regionName) {
        // first get the date and time for the subsequent request, and convert
        // to ISO 8601 format
        // for use in signature generation
        Date now = new Date();
        String dateTimeStamp = timeFormatter.format(now);

        // make sure "Host" header is added
        String hostHeader = endpointUrl.getHost();
        int port = endpointUrl.getPort();
        if ( port > -1 ) {
            hostHeader = hostHeader.concat(":" + Integer.toString(port));
        }
        headers.put("Host", hostHeader);

        // canonicalized headers need to be expressed in the query
        // parameters processed in the signature
        String canonicalizedHeaderNames = getCanonicalizeHeaderNames(headers);
        String canonicalizedHeaders = getCanonicalizedHeaderString(headers);

        // we need scope as part of the query parameters
        String dateStamp = dateFormatter.format(now);
        String scope =  dateStamp + "/" + regionName + "/" + serviceName + "/" + TERMINATOR;

        // add the fixed authorization params required by Signature V4
        queryParameters.put("X-Amz-Algorithm", SCHEME + "-" + ALGORITHM);
        queryParameters.put("X-Amz-Credential", accessKey + "/" + scope);

        // x-amz-date is now added as a query parameter, but still need to be in ISO8601 basic form
        queryParameters.put("X-Amz-Date", dateTimeStamp);

        queryParameters.put("X-Amz-SignedHeaders", canonicalizedHeaderNames);

        // build the expanded canonical query parameter string that will go into the
        // signature computation
        String canonicalizedQueryParameters = getCanonicalizedQueryString(queryParameters);

        // express all the header and query parameter data as a canonical request string
        String canonicalRequest = getCanonicalRequest(endpointUrl, httpMethod,
                canonicalizedQueryParameters, canonicalizedHeaderNames,
                canonicalizedHeaders, bodyHash);
        System.out.println("--------- Canonical request --------");
        System.out.println(canonicalRequest);
        System.out.println("------------------------------------");

        // construct the string to be signed
        String stringToSign = getStringToSign(SCHEME, ALGORITHM, dateTimeStamp, scope, canonicalRequest);
        System.out.println("--------- String to sign -----------");
        System.out.println(stringToSign);
        System.out.println("------------------------------------");

        // compute the signing key
        
        byte[] kSigning = createSignatureKey(secretKey, dateStamp, regionName, serviceName);
        byte[] signature = sign(stringToSign, kSigning, "HmacSHA256");

        // form up the authorization parameters for the caller to place in the query string
        StringBuilder authString = new StringBuilder();

        authString.append("X-Amz-Algorithm=" + queryParameters.get("X-Amz-Algorithm"));
        authString.append("&X-Amz-Credential=" + queryParameters.get("X-Amz-Credential"));
        authString.append("&X-Amz-Date=" + queryParameters.get("X-Amz-Date"));
        authString.append("&X-Amz-Expires=" + queryParameters.get("X-Amz-Expires"));
        authString.append("&X-Amz-SignedHeaders=" + queryParameters.get("X-Amz-SignedHeaders"));
        authString.append("&X-Amz-Signature=" + toHex(signature));
        if(null != queryParameters.get("X-Amz-Security-Token") && queryParameters.get("X-Amz-Security-Token").length() > 0) {
        	authString.append("&X-Amz-Security-Token=" + queryParameters.get("X-Amz-Security-Token"));
        }

        return authString.toString();
    }
    
    
    public static String computeSignatureForQueryparametersHeaders(Map<String, String> headers,
            Map<String, String> queryParameters,
            String bodyHash,
            String accessKey,
            String secretKey,
            URL endpointUrl,
            String httpMethod,
            String serviceName,
            String regionName, Date now){
        String dateTimeStamp = timeFormatter.format(now);
        String canonicalizedHeaderNames = getCanonicalizeHeaderNames(headers);
        String canonicalizedHeaders = getCanonicalizedHeaderString(headers);
        String dateStamp = dateFormatter.format(now);
        String scope =  dateStamp + "/" + regionName + "/" + serviceName + "/" + TERMINATOR;
        queryParameters.put("X-Amz-Algorithm", SCHEME + "-" + ALGORITHM);
        queryParameters.put("X-Amz-Credential", accessKey + "/" + scope);
        queryParameters.put("X-Amz-Date", dateTimeStamp);
        queryParameters.put("X-Amz-SignedHeaders", canonicalizedHeaderNames);
        String canonicalizedQueryParameters = getCanonicalizedQueryString(queryParameters);
        String canonicalRequest = getCanonicalRequest(endpointUrl, httpMethod,
                canonicalizedQueryParameters, canonicalizedHeaderNames,
                canonicalizedHeaders, bodyHash);
        System.out.println("--------- Canonical request --------");
        System.out.println(canonicalRequest);
        System.out.println("------------------------------------");
        
        // construct the string to be signed
        String stringToSign = getStringToSign(SCHEME, ALGORITHM, dateTimeStamp, scope, canonicalRequest);
        System.out.println("--------- String to sign -----------");
        System.out.println(stringToSign);
        System.out.println("------------------------------------");
        
        // compute the signing key
        
        byte[] kSigning = createSignatureKey(secretKey, dateStamp, regionName, serviceName);
        byte[] signature = sign(stringToSign, kSigning, "HmacSHA256");
        
        // form up the authorization parameters for the caller to place in the query string
        StringBuilder authString = new StringBuilder();
        
        authString.append("X-Amz-Algorithm=" + queryParameters.get("X-Amz-Algorithm"));
        authString.append("&X-Amz-Credential=" + queryParameters.get("X-Amz-Credential"));
        authString.append("&X-Amz-Date=" + queryParameters.get("X-Amz-Date"));
        authString.append("&X-Amz-Expires=" + queryParameters.get("X-Amz-Expires"));
        authString.append("&X-Amz-SignedHeaders=" + queryParameters.get("X-Amz-SignedHeaders"));
        authString.append("&X-Amz-Signature=" + toHex(signature));

        return authString.toString();
    }
    
    public static String getCanonicalizedQueryString(Map<String, String> parameters) {
        if ( parameters == null || parameters.isEmpty() ) {
            return "";
        }
        
        SortedMap<String, String> sorted = new TreeMap<String, String>();

        Iterator<Map.Entry<String, String>> pairs = parameters.entrySet().iterator();
        while (pairs.hasNext()) {
            Map.Entry<String, String> pair = pairs.next();
            String key = pair.getKey();
            String value = pair.getValue();
            sorted.put(urlEncode(key, false), urlEncode(value, false));
        }

        StringBuilder builder = new StringBuilder();
        pairs = sorted.entrySet().iterator();
        while (pairs.hasNext()) {
            Map.Entry<String, String> pair = pairs.next();
            builder.append(pair.getKey());
            builder.append("=");
            builder.append(pair.getValue());
            if (pairs.hasNext()) {
                builder.append("&");
            }
        }

        return builder.toString();
    }
    
    public static String getCanonicalizedHeaderString(Map<String, String> headers) {
        if ( headers == null || headers.isEmpty() ) {
            return "";
        }
        
        // step1: sort the headers by case-insensitive order
        List<String> sortedHeaders = new ArrayList<String>();
        sortedHeaders.addAll(headers.keySet());
        Collections.sort(sortedHeaders, String.CASE_INSENSITIVE_ORDER);

        // step2: form the canonical header:value entries in sorted order. 
        // Multiple white spaces in the values should be compressed to a single 
        // space.
        StringBuilder buffer = new StringBuilder();
        for (String key : sortedHeaders) {
            buffer.append(key.toLowerCase().replaceAll("\\s+", " ") + ":" + headers.get(key).replaceAll("\\s+", " "));
            buffer.append("\n");
        }

        return buffer.toString();
    }
    
    public static String getCanonicalizeHeaderNames(Map<String, String> headers) {
        List<String> sortedHeaders = new ArrayList<String>();
        sortedHeaders.addAll(headers.keySet());
        Collections.sort(sortedHeaders, String.CASE_INSENSITIVE_ORDER);

        StringBuilder buffer = new StringBuilder();
        for (String header : sortedHeaders) {
            if (buffer.length() > 0) buffer.append(";");
            buffer.append(header.toLowerCase());
        }

        return buffer.toString();
    }
    
    public static String getCanonicalRequest(URL endpoint, 
            String httpMethod,
            String queryParameters, 
            String canonicalizedHeaderNames,
            String canonicalizedHeaders, 
            String bodyHash) {
        String canonicalRequest ;
        if(bodyHash == null || bodyHash.equals("")){
            canonicalRequest =
                    httpMethod + "\n" +
                            getCanonicalizedResourcePath(endpoint) + "\n" +
                            queryParameters + "\n" +
                            canonicalizedHeaders + "\n" +
                            canonicalizedHeaderNames;
        }else{
            canonicalRequest =
                    httpMethod + "\n" +
                            getCanonicalizedResourcePath(endpoint) + "\n" +
                            queryParameters + "\n" +
                            canonicalizedHeaders + "\n" +
                            canonicalizedHeaderNames + "\n" +
                            bodyHash;
        }
        return canonicalRequest;
    }
    
    public static String getStringToSign(String scheme, String algorithm, String dateTime, String scope, String canonicalRequest) {
        String stringToSign =
                        scheme + "-" + algorithm + "\n" +
                        dateTime + "\n" +
                        scope + "\n" +
//                        BinaryUtils.toHex(hash(canonicalRequest));
                        toHex(hash(canonicalRequest));
        return stringToSign;
    }
    
    public static byte[] createSignatureKey(String key, String dateStamp, String regionName, String serviceName) {
        byte[] kSecret = (SCHEME + key).getBytes();
        byte[] kDate = sign(dateStamp, kSecret, HMAC_SHA256);
        byte[] kRegion = sign(regionName, kDate, HMAC_SHA256);
        byte[] kService = sign(serviceName, kRegion, HMAC_SHA256);
        byte[] kSigning = sign(TERMINATOR, kService, HMAC_SHA256);
        return kSigning;
    }
    
    public static byte[] sign(String stringData, byte[] key, String algorithm) {
        try {
            byte[] data = stringData.getBytes("UTF-8");
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(key, algorithm));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("Unable to calculate a request signature: " + e.getMessage(), e);
        }
    }
    
    public static String getCanonicalizedResourcePath(URL endpoint) {
        if ( endpoint == null ) {
            return "/";
        }
        String path = endpoint.getPath();
        if ( path == null || path.isEmpty() ) {
            return "/";
        }
        
//        String encodedPath = urlEncode(path, true);
        String encodedPath = path;
        if (encodedPath.startsWith("/")) {
            return encodedPath;
        } else {
            return "/".concat(encodedPath);
        }
    }
    
    public static String urlEncode(String url, boolean keepPathSlash) {
        String encoded;
        try {
            encoded = URLEncoder.encode(url, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("UTF-8 encoding is not supported.", e);
        }
        if ( keepPathSlash ) {
            encoded = encoded.replace("%2F", "/");
        }
        return encoded;
    }

    
    public static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (int i = 0; i < data.length; i++) {
            String hex = Integer.toHexString(data[i]);
            if (hex.length() == 1) {
                // Append leading zero.
                sb.append("0");
            } else if (hex.length() == 8) {
                // Remove ff prefix from negative numbers.
                hex = hex.substring(6);
            }
            sb.append(hex);
        }
        return sb.toString().toLowerCase(Locale.getDefault());
    }
    
//    public static String urlEncode(String url, boolean keepPathSlash) {
//        String encoded;
//        try {
//            encoded = URLEncoder.encode(url, "UTF-8");
//        } catch (UnsupportedEncodingException e) {
//            throw new RuntimeException("UTF-8 encoding is not supported.", e);
//        }
//        if ( keepPathSlash ) {
//            encoded = encoded.replace("%2F", "/");
//        }
//        return encoded;
//    }
    
//    public static String UriEncode(CharSequence input, boolean encodeSlash) throws UnsupportedEncodingException {
//        StringBuilder result = new StringBuilder();
//        for (int i = 0; i < input.length(); i++) {
//        char ch = input.charAt(i);
//        if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '~' || ch == '.') {
//        result.append(ch);
//        } else if (ch == '/') {
//        result.append(encodeSlash ? "%2F" : ch);
//        } else {
//        result.append(toHexUTF8(ch));
//        }
//        }
//        return result.toString();
//        }
    
    public static String toHexUTF8(char ch){
        
        return null;
    }
    
    public static byte[] hash(String text) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.reset();
            md.update(text.getBytes("UTF-8"));
            return md.digest();
        } catch (Exception e) {
            throw new RuntimeException("Unable to compute hash while signing request: " + e.getMessage(), e);
        }
    }
}
