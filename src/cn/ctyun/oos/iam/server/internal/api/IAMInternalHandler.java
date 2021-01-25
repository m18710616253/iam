package cn.ctyun.oos.iam.server.internal.api;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.eclipse.jetty.server.Request;

import com.amazonaws.services.s3.Headers;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;

import cn.ctyun.common.BaseException;
import cn.ctyun.common.Consts;
import cn.ctyun.common.conf.GlobalIamConfig;
import cn.ctyun.common.conf.OOSConfig;
import cn.ctyun.oos.iam.accesscontroller.util.IPUtils;
import cn.ctyun.oos.iam.server.entity.AccountSummary;
import cn.ctyun.oos.iam.server.entity.Policy;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.result.PageResult;
import cn.ctyun.oos.iam.server.util.HttpUtils;
import cn.ctyun.oos.iam.server.util.JSONUtils;
import cn.ctyun.oos.iam.signer.Utils;

/**
 * IAM内部接口调用处理
 * 供其他的服务调用
 * @author wangduo
 *
 */
public class IAMInternalHandler {
    
    private static final Log log = LogFactory.getLog(IAMInternalHandler.class);
    
    /**
     * 内部接口处理
     * @param baseRequest
     * @param request
     * @param response
     * @return 返回是否是内部接口调用
     * @throws IOException
     */
    public static boolean handle(Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException {
        String[] uris = StringUtils.split(baseRequest.getUri().toString(), "/");
        if (uris.length < 2) {
            return false;
        }
        // 不是内部接口的url不做处理
        if (!"internal".equals(uris[0])) {
            return false;
        }
        InputStream inputStream = request.getInputStream();
        // 响应内容
        String reponseStr = "";
        try {
            String requestBody = IOUtils.toString(inputStream);
            // api名称
            String apiName = uris[1];
            reponseStr = handleInternalAPI(apiName, requestBody, baseRequest, request);
            response.setContentType("application/json");
        } catch (BaseException e) {
            log.error("", e);
            response.setStatus(e.status);
            e.reqId = (String) request.getAttribute(Headers.REQUEST_ID);
            reponseStr = JSONUtils.MAPPER.writeValueAsString(e);
        } catch (Throwable t) {
            log.error("", t);
            BaseException be = new BaseException();
            be.status = 500;
            be.message = "Internal Error";
            be.code = "InternalError";
            be.reqId = (String) request.getAttribute(Headers.REQUEST_ID);
            response.setStatus(be.status);
            reponseStr = JSONUtils.MAPPER.writeValueAsString(be);
        } finally {
            inputStream.close();
        }
        try {
            HttpUtils.writeResponseEntity(response, reponseStr);
        } catch (IOException e) {
            log.error("", e);
        }
        return true;
    }
    
    /**
     * 处理内部API请求
     * @param apiName
     * @param requestBody
     * @return
     * @throws Throwable 
     */
    private static String handleInternalAPI(String apiName, String requestBody, Request baseRequest, HttpServletRequest request) throws  Throwable {

        try {
            // policy接口，给其他需要进行访问控制获取用户策略的服务使用
            if ("policy".equals(apiName)) {
                // 共用的AccessKey认证
                checkAuth(baseRequest, request);
                // 获取单个用户策略 内部服务调用
                User user = JSONUtils.MAPPER.readValue(requestBody, User.class);
                List<String> policy = IAMInternalAPI.getUserPolices(user);
                return JSONUtils.MAPPER.writeValueAsString(policy);
            } else if ("policies".equals(apiName)) {
                // 共用的AccessKey认证
                checkAuth(baseRequest, request);
                // 批量获取用户策略 内部服务调用
                List<String> userKeys = JSONUtils.toList(requestBody, String.class);
                Map<String, List<String>> policies = IAMInternalAPI.getUsersPolicyDocuments(userKeys);
                return JSONUtils.MAPPER.writeValueAsString(policies);
            }
            
            // 校验是否由proxy发起的请求
            checkProxy(request);
            if ("login".equals(apiName)) {
                // 子用户登录请求
                LoginParam loginParam = JSONUtils.MAPPER.readValue(requestBody, LoginParam.class);
                loginParam.loginIp = IPUtils.getIpAddress(request);
                LoginResult loginResult = IAMInternalAPI.login(loginParam);
                return JSONUtils.MAPPER.writeValueAsString(loginResult);
            } else if ("checkCode".equals(apiName)) {
            	LoginParam loginParam = JSONUtils.MAPPER.readValue(requestBody, LoginParam.class);
            	CheckMFACodeResult result = IAMInternalAPI.checkMFACode(loginParam);
                return JSONUtils.MAPPER.writeValueAsString(result);
            } else if ("getAccountSummary".equals(apiName)) {
            	//获取账户配置信息
            	invalidArgumentException(requestBody);
                AccountSummary accountSummary = JSONUtils.MAPPER.readValue(requestBody, AccountSummary.class);
                AccountSummary getAccountSummary = IAMInternalAPI.getAccountSummary(accountSummary.accountId);
                return JSONUtils.MAPPER.writeValueAsString(getAccountSummary);
            } else if ("putAccountQuota".equals(apiName)) {
            	//修改账户配置信息
            	invalidArgumentException(requestBody);
            	AccountSummary accountQuota = JSONUtils.MAPPER.readValue(requestBody, AccountSummary.class);
                IAMInternalAPI.putAccountQuota(accountQuota);
                return JSONUtils.MAPPER.writeValueAsString(accountQuota);
            } else if ("getSystemQuota".equals(apiName)) {
            	//获取全局配置信息
                AccountSummary systemQuota = IAMInternalAPI.getSystemQuota();
                return JSONUtils.MAPPER.writeValueAsString(systemQuota);
            } else if ("putSystemQuota".equals(apiName)) {
            	//修改全局配置信息
            	invalidArgumentException(requestBody);
            	AccountSummary systemQuota = JSONUtils.MAPPER.readValue(requestBody, AccountSummary.class);
                IAMInternalAPI.putSystemQuota(systemQuota);
                return JSONUtils.MAPPER.writeValueAsString(systemQuota);
            } else if ("createPolicy".equals(apiName)) {
                // 创建系统策略
                OOSPolicyParam param = JSONUtils.MAPPER.readValue(requestBody, OOSPolicyParam.class);
                Policy policy = OOSPolicyAPI.createPolicy(param);
                return JSONUtils.MAPPER.writeValueAsString(policy);
            } else if ("updatePolicy".equals(apiName)) {
                // 更新系统策略
                OOSPolicyParam param = JSONUtils.MAPPER.readValue(requestBody, OOSPolicyParam.class);
                Policy policy = OOSPolicyAPI.updatePolicy(param);
                return JSONUtils.MAPPER.writeValueAsString(policy);
            } else if ("deletePolicy".equals(apiName)) {
                // 删除系统策略
                OOSPolicyParam param = JSONUtils.MAPPER.readValue(requestBody, OOSPolicyParam.class);
                OOSPolicyAPI.deletePolicy(param);
                return JSONUtils.MAPPER.writeValueAsString(param);
            } else if ("getPolicy".equals(apiName)) {
                // 获取系统策略
                OOSPolicyParam param = JSONUtils.MAPPER.readValue(requestBody, OOSPolicyParam.class);
                Policy policy = OOSPolicyAPI.getPolicy(param);
                return JSONUtils.MAPPER.writeValueAsString(policy);
            } else if ("listPolicies".equals(apiName)) {
                ListOOSPoliciesParam param = JSONUtils.MAPPER.readValue(requestBody, ListOOSPoliciesParam.class);
                // 获取系统策略列表
                PageResult<Policy> pageResult = OOSPolicyAPI.listPolicies(param);
                return JSONUtils.MAPPER.writeValueAsString(pageResult);
            }
        } catch (JsonParseException | JsonMappingException e) {
            log.error("", e);
            throw new BaseException(400, "InvalidArgument", "Request body must be vaild json object.");
        }
        throw new BaseException(400, "InvalidInternalApi");
    }
    
    private static void invalidArgumentException(String requestBody) throws BaseException {
    	if(requestBody.equals("{}")) {
        	throw new BaseException(400, "InvalidArgument", "Request body must not be empty.");
        }
    }
    
    /**
     * 验证签名
     * @param baseRequest
     * @param request
     * @throws BaseException 签名错误
     */
    private static void checkAuth(Request baseRequest, HttpServletRequest request) throws BaseException {
        String auth = request.getHeader(Consts.AUTHORIZATION);
        String signature = auth.substring(auth.indexOf(':') + 1);
        Utils.checkAuth(signature, GlobalIamConfig.getSk(), null, null, baseRequest, request, null);
    }
    
    
    /**
     * IP限制
     * @param req
     * @throws BaseException
     */
    private static void checkProxy(HttpServletRequest req) throws BaseException {
        String ip = req.getRemoteAddr();
        log.info("proxy ip is:" + ip);
        List<String> ips = OOSConfig.getProxyIp();
        if (ips.contains(ip))
            return;
        throw new BaseException(400, "Invalid ProxyIp");
    }
}
