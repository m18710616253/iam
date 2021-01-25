package cn.ctyun.oos.iam.signer;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.text.ParseException;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.eclipse.jetty.server.Request;

import com.amazonaws.AmazonClientException;
import com.amazonaws.HttpMethod;
import com.amazonaws.auth.SigningAlgorithm;
import com.amazonaws.services.s3.Headers;
import com.amazonaws.services.s3.internal.Constants;
import com.amazonaws.services.s3.internal.RestUtils;
import com.amazonaws.services.s3.internal.ServiceUtils;

import cn.ctyun.common.BaseException;
import cn.ctyun.common.Consts;
import cn.ctyun.common.conf.OOSConfig;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.signer.V4Signer.AuthorizationItem;
import cn.ctyun.oos.iam.signer.V4Signer.CredentialItem;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.BucketMeta;
import cn.ctyun.oos.metadata.OwnerMeta;
import cn.ctyun.oos.metadata.TokenMeta;
import common.tuple.Pair;

public class Utils {
    private static final String RESOURCE = "/";
    protected final static DateTimeFormatter formatyyyy_mm = DateTimeFormatter.ofPattern("yyyy-MM");
    
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

    public static String toResourcePath(String bucket, String key, boolean endWithSlash) {
        // refer to com.amazonaws.services.s3.AmazonS3Client.createSigner
        // 增加对斜杠的判断
        String resourcePath;
        if (endWithSlash)
            resourcePath = "/" + ((bucket != null && !bucket.equals("")) ? bucket + "/" : "")
                    + ((key != null) ? ServiceUtils.urlEncode(key) : "");
        else
            resourcePath = "/" + ((bucket != null && !bucket.equals("")) ? bucket : "")
                    + ((key != null) ? "/" + ServiceUtils.urlEncode(key) : "");
        return resourcePath;
    }

    public static String toResourcePathNotEncode(String bucket, String key, boolean endWithSlash) {
        String resourcePath;
        if (endWithSlash)
            resourcePath = "/" + ((bucket != null && !bucket.equals("")) ? bucket + "/" : "")
                    + ((key != null) ? key : "");
        else
            resourcePath = "/" + ((bucket != null && !bucket.equals("")) ? bucket : "")
                    + ((key != null) ? "/" + key : "");
        return resourcePath;
    }

    public static String getIpAddr(HttpServletRequest req) {
        String ipAddress = null;
        ipAddress = req.getHeader("x-forwarded-for");
        if (ipAddress == null || ipAddress.length() == 0 || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = req.getHeader("Proxy-Client-IP");
        }
        if (ipAddress == null || ipAddress.length() == 0 || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = req.getHeader("WL-Proxy-Client-IP");
        }
        if (ipAddress == null || ipAddress.length() == 0 || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = req.getHeader("HTTP_CLIENT_IP");
        }
        if (ipAddress == null || ipAddress.length() == 0 || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = req.getHeader("HTTP_X_FORWARDED_FOR");
        }
        if (ipAddress == null || ipAddress.length() == 0 || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = req.getRemoteAddr();
        }
        // 对于通过多个代理的情况，第一个IP为客户端真实IP,多个IP按照','分割
        if (ipAddress != null && ipAddress.length() > 15) {
            if (ipAddress.indexOf(",") > 0) {
                ipAddress = ipAddress.substring(0, ipAddress.indexOf(","));
            }
        }
        return ipAddress;
    }

    public static boolean isFrozen(OwnerMeta owner) throws ParseException {
        return owner.frozenDate != null
                && owner.frozenDate.trim().length() != 0
                && DateUtils.addHours(ServiceUtils.parseIso8601Date(owner.frozenDate),
                        Consts.FROZEN_VALIDATION_HOURS).before(new Date());
    }

    public static boolean ifCanWrite(OwnerMeta owner, BucketMeta bucket) {
        if (bucket.permission == BucketMeta.PERM_PUBLIC_READ_WRITE)
            return true;
        if (owner == null)
            return false;
        if (bucket.ownerId == owner.getId())
            return true;
        return false;
    }

    public static void checkParameter(String parameterName) throws BaseException {
        if (parameterName == null || parameterName.trim().length() == 0)
            throw new BaseException();
    }

    /**
     * 签名验证，兼容V2及V4，请求头Authorization方式
     * @param basereq
     * @param req
     * @param bucket
     * @param key
     * @param isMustBePrimaryKey
     * @return
     * @throws Exception
     */
    public static AuthResult auth(Request basereq, HttpServletRequest req, String bucket,
            String key, boolean isMustBePrimaryKey, boolean contentSha256HeaderIsRequired, String serviceName) throws Exception {
        String auth = req.getHeader(V4Signer.AUTHORIZATION);
        if (auth == null || auth.length() == 0) {
            return new AuthResult();
        }
        AuthResult authResult = null;
        if (auth.toUpperCase().startsWith("AWS ")) {
            authResult = authV2(basereq, req, bucket, key, isMustBePrimaryKey);
            authResult.inputStream = req.getInputStream();
        } else if (auth.toUpperCase().startsWith(V4Signer.AWS4_SIGNING_ALGORITHM)) {
            authResult = authV4(basereq, req, bucket, key, isMustBePrimaryKey, contentSha256HeaderIsRequired, serviceName);
        } else {
            throw new BaseException(403, ErrorMessage.ERROR_CODE_SIGNATURE_DOES_NOT_MATCH);
        }
        checkFrozenUser(authResult.owner);
        return authResult;
    }
    
    /**
     * V2签名验证，请求头Authorization方式
     * @param basereq
     * @param req
     * @param bucket
     * @param key
     * @param isMustBePrimaryKey
     * @return
     * @throws Exception
     */
    public static AuthResult authV2(Request basereq, HttpServletRequest req, String bucket,
            String key, boolean isMustBePrimaryKey) throws Exception {
        String auth = req.getHeader("Authorization");
        String origId = null;
        String origSign = null;
        try {
            origId = Misc.getUserIdFromAuthentication(auth);
            origSign = auth.substring(auth.indexOf(':') + 1);
        } catch (Exception e) {
            throw new BaseException();
        }
        String token = req.getHeader("X-Amz-Security-Token");
        AuthResult authResult = new AuthResult();
        String sk;
        if (token== null || token.length() == 0) {
            AkSkMeta asKey = getSecretKeyFromAccessKey(origId);
            authResult.owner = checkAkSk(asKey, isMustBePrimaryKey, req, bucket, key);
            authResult.accessKey = asKey;
            sk = asKey.getSecretKey();
        } else {
            // sts临时授权访问，aksk信息从stsToken表获取
            Pair<TokenMeta, OwnerMeta> p = checkAndGetTokenSkAndOwner(token, origId);
            sk = p.first().getSecretKey();
            authResult.owner = p.second();
            authResult.tokenMeta = p.first();
            authResult.isSts = true;
        }
        checkAuth(origSign, sk, bucket, key, basereq, req, null);
        return authResult;
    }
    
    /**
     * 从token表获取aksk信息
     * @param token
     * @return
     * @throws BaseException
     * @throws IOException
     */
    public static TokenMeta getStsTokenFromToken(String token) throws BaseException, IOException {
        MetaClient client = MetaClient.getGlobalClient();
        TokenMeta stsToken = new TokenMeta(token);
        if (!client.stsTokenSelect(stsToken))
            throw new BaseException(403, "InvalidToken", "InvalidToken:" + token);
        return stsToken;
    }
    
    /**
     * 校验stsToken的有效性，并从token表中获取aksk信息，返回sk及ownerMeta
     * @param token
     * @return
     * @throws BaseException
     * @throws IOException
     * @throws ParseException
     * @throws Exception
     */
    public static Pair<TokenMeta, OwnerMeta> checkAndGetTokenSkAndOwner(
            String token,String clientAk) throws BaseException, IOException, Exception {
        TokenMeta stsToken = getStsTokenFromToken(token);
        String expiration = stsToken.expiration;
        Date expiredate = Misc.formatIso8601time(expiration);
        if (expiredate.compareTo(new Date()) < 0)
            throw new BaseException(403, "AccessDenied", "the secret token is expired. expiration: "+expiration + ".");
        if(StringUtils.isBlank(clientAk) || !clientAk.equals(stsToken.stsAccessKey))
            throw new BaseException(403, "InvalidAccessKeyId", "The specified accessKey: "+ clientAk +" does not exist");
        OwnerMeta owner = new OwnerMeta(stsToken.ownerId);
        MetaClient client = MetaClient.getGlobalClient();
        client.ownerSelectById(owner);
        return new Pair<TokenMeta,OwnerMeta>(stsToken, owner);
    }

    /**
     * V4签名验证，请求头Authorization方式
     * @param basereq
     * @param req
     * @param bucket
     * @param key
     * @param isMustBePrimaryKey
     * @return
     * @throws Exception
     */
    public static AuthResult authV4(Request basereq, HttpServletRequest req, String bucket,
            String key, boolean isMustBePrimaryKey, boolean contentSha256HeaderIsRequired,String serviceName) throws Exception {
        // 验证V4签名请求头
        V4Signer.validAuthV4Headers(req, contentSha256HeaderIsRequired);
        // 解析并验证Authorization标头合法性
        AuthorizationItem authItem = V4Signer.parseAndCheckAuthorizationHeader(req.getHeader("Authorization"));
        // 解析并验证Authorization标头中Credential部分合法性
        String regionName = getRegionNameFromReqHost(req.getHeader(V4Signer.HOST_CAPITAL), serviceName);
        CredentialItem credential = V4Signer.parseAndCheckCredential(authItem.credential, regionName, serviceName);
        // 验证Authorization标头中SignedHeaders部分合法性
        V4Signer.checkSignedHeadersValid(new OOSRequest<Object>(req), authItem.signedHeaders, false,contentSha256HeaderIsRequired);
        // 验证aksk
        String ak = credential.ak;
        String sk;
        String token = req.getHeader("X-Amz-Security-Token");
        // 签名认证返回信息
        AuthResult authResult = new AuthResult();
        if (token== null || token.length() == 0) {
            AkSkMeta asKey = getSecretKeyFromAccessKey(ak);
            authResult.owner = checkAkSk(asKey, isMustBePrimaryKey, req, bucket, key);
            authResult.accessKey = asKey;
            sk = asKey.getSecretKey();
        } else {
            // sts临时授权访问，aksk信息从stsToken表获取
            Pair<TokenMeta, OwnerMeta> pair = checkAndGetTokenSkAndOwner(token, ak);
            sk = pair.first().getSecretKey();
            authResult.owner = pair.second();
            authResult.tokenMeta = pair.first();
            authResult.isSts = true;
        }
        // 验证签名是否一致
        String uri = req.getRequestURI();
        try {
            uri = URLDecoder.decode(uri, Constants.DEFAULT_ENCODING);
        } catch (UnsupportedEncodingException e) {
            throw new BaseException(400, "InvalidURI", "the uri is:" + uri);
        }
        String resourcePath = V4Signer.getCanonicalizedResourcePath(uri);
        Pair<String, InputStream> pair = V4Signer.sign(new OOSRequest<Object>(req), ak, sk, regionName, serviceName, resourcePath,contentSha256HeaderIsRequired);
        String expectedSign = pair.first();
        String origSign = authItem.signature;
        if (!expectedSign.equals(origSign)) {
            throw new BaseException(403, ErrorMessage.ERROR_CODE_SIGNATURE_DOES_NOT_MATCH, ErrorMessage.ERROR_MESSAGE_SIGNATURE_DOES_NOT_MATCH);
        }
        authResult.inputStream = pair.second();
        return authResult;
    }
    
    public static String getRegionNameFromReq(HttpServletRequest req, String serviceName) throws BaseException {
        StringBuffer url = req.getRequestURL();
        String uri = req.getRequestURI();
        int end = url.length() - uri.length();
        String domain = url.substring(0, end);
        String scheme = req.getScheme();
        String host = domain.replaceFirst(scheme+"://", "");
        String regionName = getRegionNameFromReqHost(host, serviceName);
        return regionName;
    }
    
    public static void checkNotPrimaryKey(String bucket, String key, HttpServletRequest req,String accessKey) throws BaseException {
        if ((bucket != null && bucket.length() > 0) // bucket
                && (key == null || key.length() == 0)) {
            if (req.getMethod().equals(HttpMethod.GET.toString())
                    && (req.getParameterMap().size() == 0 || req.getParameter("prefix") != null
                            || req.getParameter("delimiter") != null
                            || req.getParameter("max-keys") != null || req.getParameter("marker") != null)) {// list
                // objects操作
                if (req.getParameter("prefix") == null
                        || !req.getParameter("prefix").startsWith(accessKey))
                    throw new BaseException("non-primary key can not list without prefix or prefix is not start with access key.", 403, "AccessDenied", "Access Denied");
            } else
                throw new BaseException("non-primary key can not operate bucket.", 403, "AccessDenied", "Access Denied");
        } else if ((bucket != null && bucket.length() > 0) // key
                && (key != null && key.length() > 0)) {
            if (!key.startsWith(accessKey))
                throw new BaseException("non-primary key can not operate object that not start with access key.", 403, "AccessDenied", "Access Denied");
        }
    }

    public static boolean checkAuth(String origSign, String secret, String bucket, String key,
            Request basereq, HttpServletRequest req, String expirationInSeconds)
            throws BaseException {
        String uri = req.getRequestURI();
        uri = uri.split("\\?")[0];
        String resourcePath = Utils.toResourcePath(bucket, key, uri.endsWith("/"));
        String method = req.getMethod();
        String canonicalString = RestUtils.makeS3CanonicalString(method, resourcePath,
                new OOSRequest<Object>(basereq), expirationInSeconds);
        // log.info(canonicalString);
        String signature = Utils.sign(canonicalString, secret, SigningAlgorithm.HmacSHA1);
        if (!signature.equals(origSign)) {
            // 先用urlencode方式计算签名，如果不匹配，再用非encode方式计算一遍
            if (key != null && key.length() != 0) {
                if (!uri.startsWith("/" + bucket + "/"))
                    key = uri.substring(1);
                else
                    key = uri.substring(bucket.length() + 2);
            }
            resourcePath = Utils.toResourcePathNotEncode(bucket, key, uri.endsWith("/"));
            canonicalString = RestUtils.makeS3CanonicalString(method, resourcePath, new OOSRequest<Object>(
                    basereq), expirationInSeconds);
            signature = Utils.sign(canonicalString, secret, SigningAlgorithm.HmacSHA1);
            if (!signature.equals(origSign))
                throw new BaseException(403, ErrorMessage.ERROR_CODE_SIGNATURE_DOES_NOT_MATCH);
        }
        return true;
    }

    //amazon s3的签名中不支持action，fromDate，toDate参数，需要加上
    public static boolean checkAuth2(String origSign, String secret, String bucket, String key,
            Request basereq, HttpServletRequest req, String expirationInSeconds)
            throws BaseException {
        String query = req.getQueryString();
        String uri = req.getRequestURI();
        uri = uri.split("\\?")[0];
        String resourcePath = Utils.toResourcePath(bucket, key, uri.endsWith("/"));
        String method = req.getMethod();
        String canonicalString = RestUtils.makeS3CanonicalString(method, resourcePath,
                new OOSRequest<Object>(basereq), expirationInSeconds);
        //query参数加上
        canonicalString = canonicalString + "?" + query;
        // log.info(canonicalString);
        String signature = Utils.sign(canonicalString, secret, SigningAlgorithm.HmacSHA1);
        if (!signature.equals(origSign)) {
            // 先用urlencode方式计算签名，如果不匹配，再用非encode方式计算一遍
            if (key != null && key.length() != 0) {
                if (!uri.startsWith("/" + bucket + "/"))
                    key = uri.substring(1);
                else
                    key = uri.substring(bucket.length() + 2);
            }
            resourcePath = Utils.toResourcePathNotEncode(bucket, key, uri.endsWith("/"));           
            canonicalString = RestUtils.makeS3CanonicalString(method, resourcePath, new OOSRequest<Object>(
                    basereq), expirationInSeconds);
            //query参数加上
            canonicalString = canonicalString + "?" + query;
            signature = Utils.sign(canonicalString, secret, SigningAlgorithm.HmacSHA1);
            if (!signature.equals(origSign))
                throw new BaseException(403, ErrorMessage.ERROR_CODE_SIGNATURE_DOES_NOT_MATCH);
        }
        return true;
    }


    /**
     * 从请求头Host获取regionName，用于验证V4签名scope，如host=oos-hz.ctyuanapi.cn，则regionName=hz
     * @param host
     * @param serviceName
     * @return
     * @throws BaseException
     */
    public static String getRegionNameFromReqHost(String host, String serviceName) throws BaseException {
        String pattern;
        if (serviceName.equals(V4Signer.STS_SERVICE_NAME)) {
            pattern = "oos-([\\w-]*)-iam.ctyunapi.cn(:\\d*)?$";
        } else {
            pattern = "oos-([\\w-]*).ctyunapi.cn(:\\d*)?$";
        }
        Pattern r = Pattern.compile(pattern);
        Matcher m = r.matcher(host);
        if (m.find( )) {
            return m.group(1).toLowerCase();
        } else {
            throw new BaseException("can not get regionName from request host header", 403, "AccessDenied", "Access Denied");
        }
    }

    public static AkSkMeta getSecretKeyFromAccessKey(String accessKey)
            throws BaseException, IOException {
        MetaClient client = MetaClient.getGlobalClient();
        AkSkMeta asKey = new AkSkMeta(accessKey);
        if (!client.akskSelect(asKey))
            throw new BaseException(403, "InvalidAccessKeyId", "InvalidAccessKeyId");
        return asKey;
    }

    public static OwnerMeta checkAkSk(AkSkMeta asKey, boolean isMustBePrimaryKey, HttpServletRequest req, String bucket, String key)
            throws Exception {
        OwnerMeta owner = new OwnerMeta(asKey.ownerId);
        if (asKey.status == 0)
            throw new BaseException("the access key is disabled.", 403, "AccessDenied", "AccessDenied");
        MetaClient client = MetaClient.getGlobalClient();
        if (!client.ownerSelectById(owner))
            throw new BaseException("the owner is not exists.", 403, "InvalidAccessKeyId");
        if (owner.verify != null)
            throw new BaseException("the owner is not verify.", 403, "NotVerify", "The user is not verify");
        if (isMustBePrimaryKey && asKey.isPrimary == 0)
            throw new BaseException("the access key is not primary key.", 403, "AccessDenied", "please use primary access key");
        if (asKey.isPrimary == 0){
            checkNotPrimaryKey( bucket, key,req, asKey.accessKey);
        }
        return owner;
    }

    public static void checkFrozenUser(OwnerMeta owner) throws BaseException, ParseException {
        if (Utils.isFrozen(owner))
            throw new BaseException("the user has been frozen.", 403, "AccessDenied", "the user's balance is not enough");
    }
    

    public static long getTimeStamp() throws BaseException {
        return System.currentTimeMillis();
    }

    public static void setCommonHeader(HttpServletResponse resp, Date date, String requestId) {
        resp.setHeader(Headers.DATE, ServiceUtils.formatRfc822Date(date));
        resp.setHeader(Headers.REQUEST_ID, requestId);
    }
 

    public static void checkDate(HttpServletRequest req) throws BaseException {
        Date clientDate = Utils.getDate(req);
        Date serverDateMax = DateUtils.addMinutes(new Date(), OOSConfig.getTimeDifference());
        Date serverDateMin = DateUtils.addMinutes(new Date(), 0 - OOSConfig.getTimeDifference());
        if (clientDate != null) {
            if (serverDateMax.compareTo(clientDate) == -1
                    || serverDateMin.compareTo(clientDate) == 1) {
                throw new BaseException("The time difference between the server and the client is over 15 minutes.", 403, "RequestTimeTooSkewed");
            }
        }
    }

    public static Date getDate(HttpServletRequest req) throws BaseException {
        if (req.getHeader(Headers.S3_ALTERNATE_DATE) != null) {
            try {
                return Misc.parseDateFormat(req.getHeader(Headers.S3_ALTERNATE_DATE));
            } catch (Exception e) {
                throw new BaseException("invalid date.", 400, ErrorMessage.ERROR_CODE_INVALID_ARGUMENT, ErrorMessage.ERROR_MESSAGE_INVALID_DATE_HEADER);
            }
        } else if (req.getHeader("Date") != null) {
            try {
                return Misc.parseDateFormat(req.getHeader("Date"));
            } catch (Exception e) {
                throw new BaseException("invalid date.", 400, ErrorMessage.ERROR_CODE_INVALID_ARGUMENT, ErrorMessage.ERROR_MESSAGE_INVALID_DATE_HEADER);
            }
        } else if (req.getHeader("Authorization") != null)
            throw new BaseException("invalid date.", 400, ErrorMessage.ERROR_CODE_INVALID_ARGUMENT, ErrorMessage.ERROR_MESSAGE_INVALID_DATE_HEADER);
        return null;
    }
    
    //--------------------------------------------------内部api 签名算法---------
    /**
     * 计算签名
     * @param httpVerb
     * @param accessKey
     * @param secretKey
     * @param headers
     * @return
     */
    public static String authorize(String httpVerb, String accessKey, String secretKey, Map<String, String> headers) {
        String contentMD5 = headers.get(Headers.CONTENT_MD5);
        contentMD5 = (contentMD5 == null) ? "" : contentMD5;
        String contentType = headers.get(Headers.CONTENT_TYPE);
        contentType = (contentType == null) ? "" : contentType;
        String date = headers.get(Headers.DATE);
        StringBuilder builder = new StringBuilder();
        builder.append(httpVerb).append("\n").append(contentMD5).append("\n").append(contentType).append("\n")
                .append(date).append("\n");
        List<String> amzHeaders = new ArrayList<>();
        for (Entry<String, String> header : headers.entrySet()) {
            String key = header.getKey().toLowerCase();
            if (key.startsWith("x-amz-")) {
                amzHeaders.add(key.trim() + ":" + header.getValue().trim());
            }
        }
        Collections.sort(amzHeaders);
        for (String header : amzHeaders) {
            builder.append(header).append("\n");
        }
        builder.append(RESOURCE);
        String stringToSign = builder.toString();
        String signature = Utils.sign(stringToSign, secretKey, SigningAlgorithm.HmacSHA1);
        String authorization = "AWS " + accessKey + ":" + signature;
        return authorization;
    }
}
