package cn.ctyun.oos.iam.signer;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import cn.ctyun.common.BaseException;
import cn.ctyun.common.Consts;
import common.threadlocal.ThreadLocalBytes;
import common.tuple.Pair;
/**
 * 处理签名,签名流程如下：
 * <li>1.生成规范请求canonical request
 * <li>2.生成待签字符串string to sign
 * <li>3.生成signing key
 * <li>4.生成signature，加到请求头或url query
 * @author WangJing
 *
 */
public class V4Signer {
    
    public static final String HOST = "host";
    public static final String DATE = "date";
    public static final String CONTENT_TYPE = "content-type";
    public static final String CONTENT_LENGTH = "content-length";
    public static final String X_AMZ_DATE = "x-amz-date";
    public static final String X_AMZ_CONTENT_SHA256 = "x-amz-content-sha256";
    public static final String X_AMZ_ALGORITHM = "x-amz-algorithm";
    public static final String X_AMZ_CREDENTIAL = "x-amz-credential";
    public static final String X_AMZ_SIGNATURE = "x-amz-signature";
    public static final String AUTHORIZATION = "Authorization";
    public static final String HOST_CAPITAL = "Host";
    public static final String DATE_CAPITAL = "Date";
    public static final String X_AMZ_DATE_CAPITAL = "X-Amz-Date";
    public static final String X_AMZ_EXPIRES_CAPITAL = "X-Amz-Expires";
    public static final String X_AMZ_SIGNED_HEADER_CAPITAL = "X-Amz-SignedHeaders";
    public static final String X_AMZ_ALGORITHM_CAPITAL = "X-Amz-Algorithm";
    public static final String X_AMZ_CREDENTIAL_CAPITAL = "X-Amz-Credential";
    public static final String X_AMZ_SIGNATURE_CAPITAL = "X-Amz-Signature";
    public static final String CONTENT_LENGTH_CAPITAL = "Content-Length";
    public static final String X_AMZ_PREFIX = "x-amz-";

    public static final String LINE_SEPARATOR = "\n";
    public static final String COMMA_SEPARATOR = ",";
    public static final String AWS4_SIGNING_ALGORITHM = "AWS4-HMAC-SHA256";
    public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
    public static final String STREAMING_SIGNED_PAYLOAD = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
    public static final String AWS4_TERMINATOR = "aws4_request";
    public static final String SIGNEDHEADERS = "SignedHeaders";
    public static final String HMAC_SHA256 = "HmacSHA256";
    // OOS API服务
    public static final String S3_SERVICE_NAME = "s3";
    // STS临时访问凭证服务，实际由iam服务响应
    public static final String STS_SERVICE_NAME = "sts";
    
    private static Log log = LogFactory.getLog(V4Signer.class);
    
    public static void main(String[] args) throws Exception {
    }
    
    /**
     * 计算签名，签名信息放在Authorization标头，单块传输，返回签名信息及payload
     * @param request
     * @param ak
     * @param sk
     * @param regionName
     * @param service
     * @param resourcePath
     * @param contentSha256HeaderIsRequired
     * @return
     * @throws Exception
     */
    public static Pair<String,InputStream> sign(OOSRequest<?> request, String ak, String sk,
            String regionName, String service, String resourcePath, boolean contentSha256HeaderIsRequired) throws Exception {
        return sign(request, ak, sk, regionName, service, AWS4_SIGNING_ALGORITHM, resourcePath, contentSha256HeaderIsRequired);
    }
    
    public static void checkContentSignatureV4(InputStream input) throws BaseException {
        if(input != null && input.getClass().isAssignableFrom(SignerInputStream.class)){
            SignerInputStream sip = ((SignerInputStream)input);
            if(!sip.hasSigned() && sip.hasRead())
                sip.checkSignature();
        }
    }

    /**
     * 计算签名，签名信息放在Authorization标头，单块传输
     * @param request
     * @param ak
     * @param sk
     * @param regionName
     * @param serviceName
     * @param signingAlgorithm
     * @param resourcePath
     * @param contentSha256HeaderIsRequired
     * @return
     * @throws Exception
     */
    public static Pair<String, InputStream> sign(OOSRequest<?> request,
            String ak, String sk, String regionName, String serviceName,
            String signingAlgorithm, String resourcePath,
            boolean contentSha256HeaderIsRequired) throws Exception {
        Map<String, String> reqHeaders = request.getHeaders();
        // 请求头key大小写不敏感
        Map<String, String> requestHeaders = SignerUtils.changeMapKeyLowercase(reqHeaders);
        String auth = requestHeaders.get(AUTHORIZATION.toLowerCase());
        AuthorizationItem authItem = parseAndCheckAuthorizationHeader(auth);
        Pair <String,String> p = SignerUtils.getFormattedDateTimeFromHead(request);
        String formattedDateTime = p.first();
        // 参与签名的dateStamp从credential获取
        CredentialItem credential = parseAndCheckCredential(authItem.credential, regionName, serviceName);
        String formattedDate = credential.dateStamp;
        String contentSha256 = UNSIGNED_PAYLOAD;
        InputStream ip = request.getContent();
        MessageDigest mDigest = MessageDigest.getInstance("SHA-256");
        
        if ((contentSha256HeaderIsRequired
                && requestHeaders.containsKey(X_AMZ_CONTENT_SHA256)
                && !requestHeaders.get(X_AMZ_CONTENT_SHA256).equals(UNSIGNED_PAYLOAD))) {
            
            String amzContentSha256 = requestHeaders.get(X_AMZ_CONTENT_SHA256);
//            ip = new BufferedInputStream(ip);
            if (SignerUtils.usePayloadForQueryParameters(request)) {
                String encodedParameters = SignerUtils.encodeParameters(request);
                if (encodedParameters == null)
                    ip = new SignerInputStream(new ByteArrayInputStream(new byte[0]), 0, mDigest, amzContentSha256);
                else {
                    byte[] data = encodedParameters.getBytes(Consts.CS_UTF8);
                    ip = new SignerInputStream(new ByteArrayInputStream(data), data.length, mDigest, amzContentSha256);
                }
            } else {
                if(ip == null)
                    ip = new SignerInputStream(new ByteArrayInputStream(new byte[0]), 0, mDigest, amzContentSha256);
                else {
                    String cl = requestHeaders.get(V4Signer.CONTENT_LENGTH);
                    long contentLength = cl == null ? 0: Long.valueOf(cl);
                    ip = new SignerInputStream(ip, contentLength, mDigest, amzContentSha256);
                }
            }
            String sign = ((SignerInputStream)ip).trySign();
            if(sign != null)
                contentSha256 = sign;
            else
                contentSha256 = amzContentSha256;
        }
            
        if (requestHeaders.containsKey(X_AMZ_CONTENT_SHA256) && !requestHeaders.get(X_AMZ_CONTENT_SHA256).equals(contentSha256))
            throw new BaseException(403, ErrorMessage.ERROR_CODE_SIGNATURE_DOES_NOT_MATCH, ErrorMessage.ERROR_MESSAGE_SIGNATURE_DOES_NOT_MATCH);
        // Authorization请求头的 SignedHeaders的 value可以有大小写，签名时需要转成小写
        String signedHeaders = authItem.signedHeaders.toLowerCase();
        String canonicalRequest = createCanonicalRequest(request, contentSha256, signedHeaders, resourcePath);
        String scope = generateScope(formattedDate, serviceName, regionName);
        String stringToSign = createStringToSign(canonicalRequest, formattedDateTime, scope);
        byte[] signingKey = createSignatureKey(sk, formattedDate, regionName, serviceName);
        byte[] signature = computeSignature(stringToSign, signingKey);
        return new Pair<String,InputStream>(SignerUtils.toHex(signature),ip);
    }

    /**
     * 计算签名，签名信息放在URL query中，即预签名方式
     * @param request
     * @param ak
     * @param sk
     * @param regionName
     * @param expirationInSeconds
     * @param resourcePath
     * @return
     * @throws Exception
     */
    public static String preSign(OOSRequest<?> request, String ak, String sk,
            String regionName, String expirationInSeconds, String resourcePath) throws Exception {
        return preSign(request, ak, sk, regionName, S3_SERVICE_NAME, AWS4_SIGNING_ALGORITHM, expirationInSeconds, resourcePath);
    }

    /**
     * 预签名
     * @param request
     * @param ak
     * @param sk
     * @param regionName
     * @param serviceName
     * @param signingAlgorithm
     * @param expirationInSeconds
     * @param resourcePath
     * @return
     * @throws Exception
     */
    public static String preSign(OOSRequest<?> request, String ak, String sk,
            String regionName, String serviceName, String signingAlgorithm,
            String expirationInSeconds, String resourcePath) throws Exception {
        Pair <String,String> p = SignerUtils.getFormattedDateTimeFromQuery(request);
        String formattedDateTime = p.first();
        Map<String, String> requestParas = request.getParameters();
        String credential = requestParas.get(V4Signer.X_AMZ_CREDENTIAL_CAPITAL);
        CredentialItem credentialItem = parseAndCheckCredential(credential, regionName, serviceName);
        String formattedDate = credentialItem.dateStamp;
        String signedHeaders = requestParas.get(X_AMZ_SIGNED_HEADER_CAPITAL);
        String canonicalRequest = createCanonicalRequest(request, UNSIGNED_PAYLOAD, signedHeaders, resourcePath);
        String scope = generateScope(formattedDate, serviceName, regionName);
        String stringToSign = createStringToSign(canonicalRequest, formattedDateTime, scope);
        byte[] signingKey = createSignatureKey(sk, formattedDate, regionName, serviceName);
        byte[] signature = computeSignature(stringToSign, signingKey);
        return SignerUtils.toHex(signature);
    }
    
    /**
     * post表单上传请求计算签名
     * @param request
     * @param ak
     * @param sk
     * @param regionName
     * @param policy
     * @param date
     * @return
     * @throws Exception
     */
    public static String postSign(OOSRequest<?> request, String ak, String sk,
            String regionName, String policy, String date) throws Exception {
        return postSign(request, ak, sk, regionName, S3_SERVICE_NAME, AWS4_SIGNING_ALGORITHM, policy, date);
    }
    
    /**
     * post表单上传请求计算签名
     * @param request
     * @param ak
     * @param sk
     * @param regionName
     * @param serviceName
     * @param signingAlgorithm
     * @param policy
     * @param dateStamp
     * @return
     * @throws Exception
     */
    public static String postSign(OOSRequest<?> request, String ak, String sk,
            String regionName, String serviceName, String signingAlgorithm,
            String policy, String dateStamp) throws Exception {
        String stringToSign = policy;
        byte[] signingKey = createSignatureKey(sk, dateStamp, regionName, serviceName);
        byte[] signature = computeSignature(stringToSign, signingKey);
        return SignerUtils.toHex(signature);
    }
    
    /**
     * 签名第一步，生成规范请求canonical request
     * @param request
     * @param contentSha256
     * @param signedHeaders
     * @param resourcePath
     * @return
     */
    public static String createCanonicalRequest(OOSRequest<?> request,
            String contentSha256, String signedHeaders, String resourcePath) {
        StringBuilder canonicalRequestBuilder = new StringBuilder(request.getHttpMethod().toString());
        canonicalRequestBuilder.append(LINE_SEPARATOR)
                .append(resourcePath)
                .append(LINE_SEPARATOR)
                .append(getCanonicalizedQueryString(request))
                .append(LINE_SEPARATOR)
                .append(getCanonicalizedHeaderString(request, signedHeaders))
                .append(LINE_SEPARATOR)
                .append(signedHeaders).append(LINE_SEPARATOR)
                .append(contentSha256);
        String canonicalRequest = canonicalRequestBuilder.toString();
        if (log.isDebugEnabled())
            log.debug("AWS4 Canonical Request: '\"" + canonicalRequest + "\"");
        return canonicalRequest;
    }
    
    /**
     * 签名第二步，生成待签字符串string to sign
     * @param canonicalRequest
     * @param formattedSigningDateTime
     * @param scope
     * @return
     * @throws Exception
     */
    public static String createStringToSign(String canonicalRequest,
            String formattedSigningDateTime, String scope) throws Exception {
        StringBuilder stringToSignBuilder = new StringBuilder(AWS4_SIGNING_ALGORITHM);
        stringToSignBuilder.append(LINE_SEPARATOR)
                .append(formattedSigningDateTime)
                .append(LINE_SEPARATOR)
                .append(scope)
                .append(LINE_SEPARATOR)
                .append(SignerUtils.toHex(hash(canonicalRequest)));
        String stringToSign = stringToSignBuilder.toString();
        if (log.isDebugEnabled())
            log.debug("AWS4 String to Sign: '\"" + stringToSign + "\"");
        return stringToSign;
    }
    
    /**
     * 签名第三步，生成signing key
     * @param key
     * @param dateStamp
     * @param regionName
     * @param serviceName
     * @return
     * @throws Exception
     */
    public static byte[] createSignatureKey(String key, String dateStamp, String regionName, String serviceName) throws Exception {
        byte[] kSecret = ("AWS4" + key).getBytes("UTF8");
        byte[] kDate = HmacSHA256(dateStamp, kSecret);
        byte[] kRegion = HmacSHA256(regionName, kDate);
        byte[] kService = HmacSHA256(serviceName, kRegion);
        byte[] kSigning = HmacSHA256(AWS4_TERMINATOR, kService);
        return kSigning;
    }
    
    /**
     * 签名第四步，生成signature
     * @param stringToSign
     * @param signingKey
     * @return
     * @throws Exception
     */
    public static byte[] computeSignature(String stringToSign, byte[] signingKey) throws Exception {
        Mac mac = Mac.getInstance(HMAC_SHA256);
        mac.init(new SecretKeySpec(signingKey, HMAC_SHA256));
        return mac.doFinal(stringToSign.getBytes(Consts.CS_UTF8));
    }
    
    /**
     * 获取规范QueryString
     * @param request
     * @return
     */
    public static String getCanonicalizedQueryString(OOSRequest<?> request) {
        /*
         * If we're using POST and we don't have any request payload content,
         * then any request query parameters will be sent as the payload, and
         * not in the actual query string.
         */
        if (SignerUtils.usePayloadForQueryParameters(request))
            return "";
        return getCanonicalizedQueryString(request.getParameters());
    }
    
    public static String getCanonicalizedQueryString(Map<String, String> parameters) {
        SortedMap<String, String> sorted = new TreeMap<String, String>();
        /**
         * Signing protocol expects the param values also to be sorted after url
         * encoding in addition to sorted parameter names.
         */
        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            String encodedParamName = SignerUtils.urlEncode(entry.getKey(), false);
            String paramValue = entry.getValue();
            // preSign ignore X-Amz-Signature
            if (encodedParamName.equals(X_AMZ_SIGNATURE_CAPITAL))
                continue;
            String encodedValue = SignerUtils.urlEncode(paramValue, false);
            sorted.put(encodedParamName, encodedValue);
        }
        StringBuilder result = new StringBuilder();
        for(Map.Entry<String, String> entry : sorted.entrySet()) {
                if (result.length() > 0) {
                    result.append("&");
                }
                result.append(entry.getKey())
                      .append("=")
                      .append(entry.getValue());
        }
        return result.toString();
    }
    
    /**
     * 获取规范HeaderString
     * @param request
     * @param signedHeaders
     * @return
     */
    public static String getCanonicalizedHeaderString(OOSRequest<?> request, String signedHeaders) {
        String[] signedHeadersArray = signedHeaders.split(";");
        List<String> sortedHeaders = Arrays.asList(signedHeadersArray);
        Map<String, String> requestHeaders = request.getHeaders();
        StringBuilder buffer = new StringBuilder();
        for (String header : sortedHeaders) {
            Iterator<String> keys = requestHeaders.keySet().iterator();
            while(keys.hasNext()) {
                String key = keys.next();
                if (key.equalsIgnoreCase(header)) {
                    String value = requestHeaders.get(key);
                    SignerUtils.appendCompactedString(buffer, header);
                    buffer.append(":");
                    if (value != null) {
                        SignerUtils.appendCompactedString(buffer, value);
                    }
                    buffer.append("\n");
                    break;
                }
            }
        }
        return buffer.toString();
    }
    
    /**
     * checksum payload
     * @param requestHeaders
     * @param ip
     * @return
     * @throws Exception
     */
    /*public static Pair<String, InputStream> checksumPayload(
            Map<String, String> requestHeaders, InputStream ip) throws Exception {
        InputStream payloadStream = getBinaryRequestPayloadStream(request, ip);
//        payloadStream.mark(-1);
        Map<String, String> reqHeaders = requestHeaders.getHeaders();
        Map<String, String> requestHeaders = SignerUtils.changeMapKeyLowercase(reqHeaders);
        long contentLength = -1;
        if (requestHeaders.containsKey(Signer.CONTENT_LENGTH)) {
            contentLength = Long.valueOf(requestHeaders.get(Signer.CONTENT_LENGTH));
        }
        String contentSha256 = SignerUtils.toHex(hash(payloadStream, contentLength));
        try {
            payloadStream.reset();
        } catch (IOException e) {
            throw new Exception("Unable to reset stream after calculating AWS4 signature", e);
        }
        Pair<String,InputStream> p = new  Pair<String,InputStream>();
        p.first(contentSha256);
        p.second(payloadStream);
        return p;
    }*/
    
   /* public static InputStream getBinaryRequestPayloadStream(
            OOSRequest<?> request, InputStream ip) throws Exception {
        if (SignerUtils.usePayloadForQueryParameters(request)) {
            String encodedParameters = SignerUtils.encodeParameters(request);
            if (encodedParameters == null)
                return new SignerInputStream(new ByteArrayInputStream(new byte[0]), 0);
            byte[] data = encodedParameters.getBytes(Consts.CS_UTF8);
            return new SignerInputStream(new ByteArrayInputStream(data), data.length);
        }
        return getBinaryRequestPayloadStreamWithoutQueryParams(request,ip);
    }*/
    
    /*public static InputStream getBinaryRequestPayloadStreamWithoutQueryParams(OOSRequest<?> request,InputStream ip) throws Exception {
        try {
            if (ip == null)
                return new ByteArrayInputStream(new byte[0]);
            if (!ip.markSupported())
                throw new Exception("Unable to read request payload to sign request.");
            return ip;
        } catch (Exception e) {
            throw new Exception("Unable to read request payload to sign request: " + e.getMessage(), e);
        }
    }*/
    
   /*public static byte[] hash(InputStream input, long contentLength) throws Exception {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            @SuppressWarnings("resource")
            InputStream digestInputStream = new DigestInputStream(input, md);
            byte[] buffer = new byte[1024];
            //读流读到content-length长度截止
            int read = 0;
            int size = 0;
            if (contentLength > -1) {
                while ((read = digestInputStream.read(buffer)) > -1 && (size < contentLength)) {
                    size += read;
                }
            } else {
                while (digestInputStream.read(buffer) > -1) {
                    ;
                }
            }
            return ((DigestInputStream) digestInputStream).getMessageDigest().digest();
        } catch (Exception e) {
            throw new Exception("Unable to compute hash while signing request: " + e.getMessage(), e);
        }
    }*/
    
    public static class SignerInputStream extends InputStream {
        private static int KB_16 = 16 * 1024;
        private long length = -1;
        private MessageDigest md;
        private DigestInputStream digestInputStream;
        private String contentDigest = null;
        private String digest = null;
        private long available;
        private boolean hasRead = false;
        
        SignerInputStream(InputStream input, long length, MessageDigest md, String contentDigest) throws NoSuchAlgorithmException {
            this.length = length;
            this.available = length;
            this.md = md;
            digestInputStream = new DigestInputStream(input, md);
            this.contentDigest = contentDigest;
        }
        
        public int available() throws IOException {
            return (int) Math.min((long)Integer.MAX_VALUE, available);
        }

        public int read() throws IOException {
            hasRead = true;
            int b = -1;
            if(available >= 0) {
                b = digestInputStream.read();
                available--;
            }
            return b;
        }
        
        public int read(byte[] b)  throws IOException {
            return read(b, 0, b.length);
        }
        
        public int read(byte[] b, int off, int len) throws IOException {
            if (b == null) {
                throw new NullPointerException();
            } else if (off < 0 || len < 0 || len > b.length - off) {
                throw new IndexOutOfBoundsException();
            }
            hasRead = true;
            //读流读到content-length长度截止
            int readSize = 0;
            if(len > available)
                len = (int)available;
//            System.out.println("available=" + available);
//            System.out.println("len=" + len);
            if(len >= 0)
                readSize = digestInputStream.read(b, off, len);
            if(available == 0 || readSize == -1) {
                return -1;
            }
            available = length - readSize;
            return readSize;
        }
        
        /**
         * 读完流之后获取digest
         * @return
         */
        private String sign() {
            if(digest == null)
                digest = SignerUtils.toHex(digestInputStream.getMessageDigest().digest());
            return digest;
//            return digest == null ? digestInputStream.getMessageDigest().digest() : digest;
        }
        
        /**
         * 只能调用一次，对小于等于512KB的流进行digest
         * @return
         * @throws IOException
         */
        public String trySign() throws IOException {
            if(digest != null)
                return digest;
            if(length <= KB_16) {
                byte[] data = ThreadLocalBytes.current().get16KBytes();
                int off = 0;
                int n = 0;
                int len = (int)length;
                while((n = read(data, off, len)) != -1) {
                    off += n;
                    len -= n;
                }
                digest = sign();
                digestInputStream.close();
                digestInputStream = new DigestInputStream(new ByteArrayInputStream(data, 0, off), md);
                available = length;
                return digest;
            }
            return null;
        }
        
        public void checkSignature() throws BaseException {
            if(!sign().equals(contentDigest))
                throw new BaseException(403, ErrorMessage.ERROR_CODE_SIGNATURE_DOES_NOT_MATCH, ErrorMessage.ERROR_MESSAGE_SIGNATURE_DOES_NOT_MATCH);
        }
        
        public boolean hasSigned() {
            return digest != null;
        }
        
        public boolean hasRead() {
            return hasRead;
        }
        
        public void close() throws IOException {
            digestInputStream.close();
        }
    }
    
    /**
     * 创建scope
     * @param dateStamp
     * @param serviceName
     * @param regionName
     * @return
     */
    public static String generateScope(String dateStamp, String serviceName, String regionName) {
        StringBuilder scopeBuilder = new StringBuilder();
        return scopeBuilder.append(dateStamp).append("/").append(regionName)
                .append("/").append(serviceName).append("/")
                .append(AWS4_TERMINATOR).toString();
    }
    
    public static byte[] hash(String text) throws Exception {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.reset();
            md.update(text.getBytes(Consts.CS_UTF8));
            return md.digest();
        } catch (Exception e) {
            throw new Exception("Unable to compute hash while signing request: " + e.getMessage(), e);
        }
    }
    
    public static byte[] HmacSHA256(String data, byte[] key) throws Exception {
        Mac mac = Mac.getInstance(HMAC_SHA256);
        mac.init(new SecretKeySpec(key, HMAC_SHA256));
        return mac.doFinal(data.getBytes("UTF8"));
    }
    
    /**
     * 获取规范URI
     * @param resourcePath
     * @return
     */
    public static String getCanonicalizedResourcePath(String resourcePath) {
        if (resourcePath == null || resourcePath.length() == 0) {
            return "/";
        } else {
            String value = urlEncode(resourcePath, true);
            if (value.startsWith("/")) {
                return value;
            } else {
                return "/".concat(value);
            }
        }
    }
    
    public static String urlEncode(String value, boolean path) {
        if (value == null) return "";
        try {
            String encoded = URLEncoder.encode(value, "UTF-8")
                    .replace("+", "%20").replace("*", "%2A")
                    .replace("%7E", "~");
            if (path) {
                encoded = encoded.replace("%2F", "/");
            }
            return encoded;
        } catch (UnsupportedEncodingException ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * 验证Authorization标头中SignedHeaders部分合法性
     * @param request
     * @param signedHeaders
     * @param isPreSign
     * @param contentSha256HeaderIsRequired
     * @throws BaseException
     */
    public static void checkSignedHeadersValid(OOSRequest<?> request,
            String signedHeaders, boolean isPreSign,
            boolean contentSha256HeaderIsRequired) throws BaseException {
        String[] signedHeadersArray = signedHeaders.split(";");
        List<String> sortedHeaders = Arrays.asList(signedHeadersArray);
        Collections.sort(sortedHeaders, String.CASE_INSENSITIVE_ORDER);
        String sortedHeadersGen = String.join(";", sortedHeaders);
        // 检查SignedHeasers顺序
        if (!sortedHeadersGen.equals(signedHeaders)) {
            throw new BaseException(403,
                    ErrorMessage.ERROR_CODE_SIGNATURE_DOES_NOT_MATCH,
                    ErrorMessage.ERROR_MESSAGE_INVALID_SIGNED_HEADERS);
        }
        // 检查SignedHeasers，必须包含"host"、"x-amz-content-sha256"标头,共享链接无需包含"x-amz-content-sha256"标头
        if (!isPreSign) {
            // 请求头方式大小写不敏感
            if (!signedHeaders.toLowerCase().contains(HOST)) {
                throw new BaseException(
                        "SignedHeasers should include host header.", 403,
                        ErrorMessage.ERROR_CODE_SIGNATURE_DOES_NOT_MATCH,
                        ErrorMessage.ERROR_MESSAGE_SIGNATURE_DOES_NOT_MATCH);
            }
        } else {
            if (!sortedHeaders.contains(HOST)) {
                throw new BaseException(
                        "SignedHeasers should include host header.", 403,
                        ErrorMessage.ERROR_CODE_SIGNATURE_DOES_NOT_MATCH,
                        ErrorMessage.ERROR_MESSAGE_SIGNATURE_DOES_NOT_MATCH);
            }
        }
        if (!isPreSign && contentSha256HeaderIsRequired) {
            if (!signedHeaders.toLowerCase().contains(X_AMZ_CONTENT_SHA256)) {
                throw new BaseException(
                        "SignedHeasers should include x-amz-content-sha256 headers.",
                        403, ErrorMessage.ERROR_CODE_SIGNATURE_DOES_NOT_MATCH,
                        ErrorMessage.ERROR_MESSAGE_SIGNATURE_DOES_NOT_MATCH);
            }
        }
        Map<String, String> requestHeaders = request.getHeaders();
        List<String> interestingHeaders = new ArrayList<String>();
        if (requestHeaders != null && requestHeaders.size() > 0) {
            Iterator<Map.Entry<String, String>> headerIter = requestHeaders.entrySet().iterator();
            while (headerIter.hasNext()) {
                Map.Entry<String, String> entry = (Map.Entry<String, String>) headerIter.next();
                String key = entry.getKey();
                if (key == null)
                    continue;
                String lk = key.toString().toLowerCase(Locale.getDefault());
                if (lk.startsWith(X_AMZ_PREFIX)) {
                    interestingHeaders.add(lk);
                }
                if (!isPreSign && contentSha256HeaderIsRequired && lk.equals(CONTENT_TYPE)) {
                    interestingHeaders.add(lk);
                }
            }
        }
        // 检查SignedHeasers，若请求头有"Content-Type"，就必须包括进来。请求头里所有x-amz-*标头也必须包括进来
        if (!isPreSign) {
            for (String interestingHeader : interestingHeaders) {
                if (!signedHeaders.toLowerCase().contains(interestingHeader)) {
                    throw new BaseException(
                            "SignedHeasers should include content-type and any x-amz- prefix headers",
                            403, ErrorMessage.ERROR_CODE_SIGNATURE_DOES_NOT_MATCH,
                            ErrorMessage.ERROR_MESSAGE_SIGNATURE_DOES_NOT_MATCH);
                }
            }
        } else {
            for (String interestingHeader : interestingHeaders) {
                if (!sortedHeaders.contains(interestingHeader)) {
                    throw new BaseException(
                            "SignedHeasers should include content-type and any x-amz- prefix headers",
                            403, ErrorMessage.ERROR_CODE_SIGNATURE_DOES_NOT_MATCH,
                            ErrorMessage.ERROR_MESSAGE_SIGNATURE_DOES_NOT_MATCH);
                }
            }
        }
        
        // 检查SignedHeasers，忽略"connection"
        for (String header : sortedHeaders) {
            if (SignerUtils.shouldExcludeHeaderFromSigning(header)) {
                throw new BaseException(
                        "SignedHeasers should ignore connection headers",
                        403, ErrorMessage.ERROR_CODE_SIGNATURE_DOES_NOT_MATCH,
                        ErrorMessage.ERROR_MESSAGE_SIGNATURE_DOES_NOT_MATCH);
            }
        }
    }
    
    /**
     * 验证V4签名请求头Host、Date、x-amz-date、x-amz-content-sha256是否正确
     * @param req
     * @throws BaseException
     */
    public static void validAuthV4Headers(HttpServletRequest req, boolean contentSha256HeaderIsRequired) throws BaseException {
        String host = req.getHeader(HOST_CAPITAL);
        String contentSha256 = req.getHeader(X_AMZ_CONTENT_SHA256);
        String date = req.getHeader(DATE_CAPITAL);
        String xAmzDate = req.getHeader(X_AMZ_DATE);
        if (host == null || host.length() == 0)
            throw new BaseException(403, ErrorMessage.ERROR_CODE_403, ErrorMessage.ERROR_MESSAGE_INVALID_HOST);
        if (contentSha256HeaderIsRequired) {
            if (contentSha256 == null || contentSha256.length() == 0)
                throw new BaseException(400, ErrorMessage.ERROR_CODE_INVALID_REQUEST, ErrorMessage.ERROR_MESSAGE_MISSING_X_AMZ_CONTENT_SHA256);
            if (!contentSha256.equals(V4Signer.UNSIGNED_PAYLOAD) && !contentSha256.equals(V4Signer.STREAMING_SIGNED_PAYLOAD) && contentSha256.length() != 64)
                throw new BaseException(400, ErrorMessage.ERROR_CODE_INVALID_ARGUMENT, ErrorMessage.ERROR_MESSAGE_INVALID_X_AMZ_CONTENT_SHA256);
        }
        if ((date == null || date.length() == 0) && (xAmzDate == null || xAmzDate.length() == 0))
            throw new BaseException(403, ErrorMessage.ERROR_CODE_403, ErrorMessage.ERROR_MESSAGE_INVALID_DATE_HEADER);
        if (xAmzDate!= null) {
            try {
                SignerUtils.formatTimestamp(xAmzDate);
            } catch (ParseException e) {
                throw new BaseException(403, ErrorMessage.ERROR_CODE_403, ErrorMessage.ERROR_MESSAGE_INVALID_DATE_HEADER_WITH_EXPECTING);
            }
        } else if (date!= null) {
            try {
                SignerUtils.formatTimestamp(date);
            } catch (ParseException e) {
                throw new BaseException(403, ErrorMessage.ERROR_CODE_403, ErrorMessage.ERROR_MESSAGE_INVALID_DATE_HEADER_WITH_EXPECTING);
            }
        }
    }
    
    // AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/
    // s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amzdate,
    // Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7
    /**
     * 解析并验证Authorization标头合法性, Authorization标头以"AWS4-HMAC-SHA256
     * "开头，Credential、SignedHeaders、Signature顺序无关
     * @param auth
     * @return
     * @throws BaseException
     */
    public static AuthorizationItem parseAndCheckAuthorizationHeader(String auth) throws BaseException {
        AuthorizationItem authorizationItem = new AuthorizationItem();
        authorizationItem.signAlgorithm = auth.split(" ")[0];
        if (!authorizationItem.signAlgorithm.toUpperCase().equals(V4Signer.AWS4_SIGNING_ALGORITHM))
            throw new BaseException(400,
                    ErrorMessage.ERROR_CODE_INVALID_ARGUMENT,
                    ErrorMessage.ERROR_MESSAGE_UNSUPPORTED_AUTH_TYPE);
        String[] res = auth.replaceFirst(authorizationItem.signAlgorithm + " ", "").split(",");
        if (res.length != 3)
            throw new BaseException(400,
                    ErrorMessage.ERROR_CODE_AUTH_HEADER_MALFORMED,
                    ErrorMessage.ERROR_MESSAGE_AUTH_HEADER_MALFORMED);
        for (int i = 0; i < 3; i++) {
            String item = res[i].trim();
            if (item.toLowerCase().startsWith("credential=")) {
                authorizationItem.credential = item.substring(11);
            }
            if (item.toLowerCase().startsWith("signedheaders=")) {
                authorizationItem.signedHeaders = item.substring(14);
            }
            if (item.toLowerCase().startsWith("signature=")) {
                authorizationItem.signature = item.substring(10);
            }
        }
        if (authorizationItem.credential == null || authorizationItem.credential.isEmpty())
            throw new BaseException(400,
                    ErrorMessage.ERROR_CODE_AUTH_HEADER_MALFORMED,
                    ErrorMessage.ERROR_MESSAGE_AUTH_HEADER_MALFORMED
                            + " missing Credential.");
        if (authorizationItem.signedHeaders == null || authorizationItem.signedHeaders.isEmpty())
            throw new BaseException(400,
                    ErrorMessage.ERROR_CODE_AUTH_HEADER_MALFORMED,
                    ErrorMessage.ERROR_MESSAGE_AUTH_HEADER_MALFORMED
                            + " missing SignedHeaders.");
        if (authorizationItem.signature == null || authorizationItem.signature.isEmpty())
            throw new BaseException(400,
                    ErrorMessage.ERROR_CODE_AUTH_HEADER_MALFORMED,
                    ErrorMessage.ERROR_MESSAGE_AUTH_HEADER_MALFORMED
                            + " missing Signature.");
        return authorizationItem;
    }

    /**
     * 解析并验证Authorization标头中Credential部分合法性,格式为AK/YYYYMMDD/REGION/SERVICE/aws4_request
     * 
     * @param credential
     * @throws BaseException
     */
    // Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request
    public static CredentialItem parseAndCheckCredential(String credential,
            String region, String service) throws BaseException {
        String[] credentialItems = credential.split("\\/");
        if (credentialItems.length != 5)
            throw new BaseException(400,
                    ErrorMessage.ERROR_CODE_AUTH_HEADER_MALFORMED,
                    ErrorMessage.ERROR_MESSAGE_CREDENTIAL_MALFORMED);
        CredentialItem credentialItem = new CredentialItem();
        credentialItem.ak = credentialItems[0];
        credentialItem.dateStamp = credentialItems[1];
        credentialItem.region = credentialItems[2];
        credentialItem.service = credentialItems[3];
        credentialItem.aws4Terminator = credentialItems[4];
        checkCredentialItem(credentialItem, region, service);
        return credentialItem;
    }

    /**
     * 验证Authorization标头中Credential部分合法性,格式为AK/YYYYMMDD/REGION/SERVICE/aws4_request
     * 
     * @param credentialItem
     * @param region
     * @param service
     * @throws BaseException
     */
    public static void checkCredentialItem(CredentialItem credentialItem,
            String region, String service) throws BaseException {
        // AK不能为空字符串
        if (StringUtils.isEmpty(credentialItem.ak)) {
            throw new BaseException(403, "InvalidAccessKeyId", "The AccessKeyId is invalid.");
        }
        // date校验，格式为YYYYMMDD
        String regex = "[0-9]{8}";
        Pattern pattern = Pattern.compile(regex);
        Matcher endMatch = pattern.matcher(credentialItem.dateStamp);
        if (endMatch.matches()) {
            try {
                SignerUtils.parseDateStamp(credentialItem.dateStamp);
            } catch (ParseException e) {
                throw new BaseException(400,
                        ErrorMessage.ERROR_CODE_AUTH_HEADER_MALFORMED,
                        ErrorMessage.ERROR_MESSAGE_AUTH_HEADER_MALFORMED
                                + " the date format '" + credentialItem.dateStamp
                                + "' is wrong; expecting 'YYYYMMDD'");
            }
        } else {
            throw new BaseException(400,
                    ErrorMessage.ERROR_CODE_AUTH_HEADER_MALFORMED,
                    ErrorMessage.ERROR_MESSAGE_AUTH_HEADER_MALFORMED
                            + " the date format '" + credentialItem.dateStamp
                            + "' is wrong; expecting 'YYYYMMDD'");
        }
        if (!credentialItem.region.equals(region))
            throw new BaseException(400,
                    ErrorMessage.ERROR_CODE_AUTH_HEADER_MALFORMED,
                    ErrorMessage.ERROR_MESSAGE_AUTH_HEADER_MALFORMED
                            + " the region '" + credentialItem.region
                            + "' is wrong; expecting '" + region + "'");
        if (!credentialItem.service.equalsIgnoreCase(service))
            throw new BaseException(400,
                    ErrorMessage.ERROR_CODE_AUTH_HEADER_MALFORMED,
                    ErrorMessage.ERROR_MESSAGE_AUTH_HEADER_MALFORMED
                            + " incorrect service \"" + credentialItem.service
                            + "\". This endpoint belongs to \"" + service + "\".");
        if (!credentialItem.aws4Terminator.equalsIgnoreCase(V4Signer.AWS4_TERMINATOR))
            throw new BaseException(400,
                    ErrorMessage.ERROR_CODE_AUTH_HEADER_MALFORMED,
                    ErrorMessage.ERROR_MESSAGE_AUTH_HEADER_MALFORMED
                            + " incorrect terminal \""
                            + credentialItem.aws4Terminator
                            + "\". This endpoint uses \""
                            + V4Signer.AWS4_TERMINATOR + "\".");
    }
    
    public static class AuthorizationItem {
        public String signAlgorithm;
        public String credential;
        public String signedHeaders;
        public String signature;
        
        public AuthorizationItem() {}
    }
    
    public static class CredentialItem {
        public String ak;
        public String dateStamp;
        public String region;
        public String service;
        public String aws4Terminator;
        
        public CredentialItem() {}
    }

}
