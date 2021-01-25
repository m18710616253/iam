package cn.ctyun.oos.iam.server;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.time.DateUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;

import com.amazonaws.services.s3.Headers;
import com.amazonaws.services.s3.internal.ServiceUtils;
import com.fasterxml.jackson.core.JsonProcessingException;

import cn.ctyun.common.BaseException;
import cn.ctyun.common.Consts;
import cn.ctyun.common.conf.OOSConfig;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.util.IAMStringUtils;
import cn.ctyun.oos.iam.server.action.ActionMethod;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.action.IAMActions;
import cn.ctyun.oos.iam.server.hbase.IAMHBaseTables;
import cn.ctyun.oos.iam.server.internal.api.IAMInternalHandler;
import cn.ctyun.oos.iam.server.result.ResponseMetadata;
import cn.ctyun.oos.iam.server.result.Result;
import cn.ctyun.oos.iam.server.util.HttpUtils;
import cn.ctyun.oos.iam.server.util.IAMAccessControlUtils;
import cn.ctyun.oos.iam.server.util.JSONUtils;
import cn.ctyun.oos.iam.server.util.XmlResultUtils;
import cn.ctyun.oos.iam.signer.AuthResult;
import cn.ctyun.oos.iam.signer.ErrorMessage;
import cn.ctyun.oos.iam.signer.Utils;
import cn.ctyun.oos.iam.signer.V4Signer;
import cn.ctyun.oos.metadata.CloudTrailEvent;
import cn.ctyun.oos.metadata.CloudTrailManageEvent;
import cn.ctyun.oos.metadata.ManageEventMeta;

/**
 * IAM HTTP请求处理类
 * @author wangduo
 *
 */
public class IAMHttpHandler extends AbstractHandler {
    
    private static final Log log = LogFactory.getLog(IAMHttpHandler.class);
    private static final String API_VERSION = "2010-05-08";
    
    private static MetaClient metaClient = MetaClient.getGlobalClient();
    private int timeDifference;

    public IAMHttpHandler() throws Exception {
        // hbase表创建初始化
        IAMHBaseTables.createTables();
        // 初始化static块，加载Action参数对应的方法
        new IAMActions();
        this.timeDifference = OOSConfig.getTimeDifference();
    }
    
    private void log(HttpServletRequest req, String ipAddress) {
        log.info("**************************");
        log.info("request id:" + req.getAttribute(Headers.REQUEST_ID) + " Http Method:"
                + req.getMethod() + " User-Agent:" + req.getHeader("User-Agent") + " RequestURI:"
                + req.getRequestURI() + " IP:" + ipAddress);
        Enumeration<?> e = req.getHeaderNames();
        String logs = "Headers:";
        while (e.hasMoreElements()) {
            String k = (String) e.nextElement();
            String v = req.getHeader(k);
            logs += k + "=" + v + " ";
        }
        log.info(logs);
    }
    
    @Override
    public void handle(String target, Request basereq, HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String reqid = Long.toHexString(UUID.randomUUID().getMostSignificantBits());
        resp.setHeader(Headers.REQUEST_ID, reqid);
        resp.setHeader(Headers.DATE, ServiceUtils.formatRfc822Date(new Date()));
        req.setAttribute(Headers.DATE, new Date().getTime());
        req.setAttribute(Headers.REQUEST_ID, reqid);
        
        // 内部API处理
        boolean isInternalApi = IAMInternalHandler.handle(basereq, req, resp);
        if (isInternalApi) {
            return;
        }
        
        ManageEventMeta manageEvent = null;
        InputStream inputStream = null;
        try {
            log(req, Utils.getIpAddr(req));
            Date clientDate = Utils.getDate(req);
            Date serverDateMax = DateUtils.addMinutes(new Date(), timeDifference);
            Date serverDateMin = DateUtils.addMinutes(new Date(), 0 - timeDifference);
            if (clientDate != null) {
                if (serverDateMax.compareTo(clientDate) == -1
                        || serverDateMin.compareTo(clientDate) == 1) {
                    throw new BaseException("The time difference between the server and the client is over 15 minutes.", 403, "RequestTimeTooSkewed"
                            ,"The difference between the request time and the server's time is too large.");
                }
            }
            // 不支持V2签名
            if (isAuthV2(req)) {
                throw new BaseException(403, ErrorMessage.ERROR_CODE_SIGNATURE_DOES_NOT_MATCH, "The request signature does not conform to IAM standards.");
            }
            // 签名认证
            AuthResult authResult = Utils.auth(basereq, req, null, null, true, true, V4Signer.STS_SERVICE_NAME);
            inputStream = authResult.inputStream;
            if (inputStream == null) {
                throw new BaseException(403, ErrorMessage.ERROR_CODE_403, ErrorMessage.ERROR_MESSAGE_403);
            }
            // 请求参数处理
            String params[] = IOUtils.toString(inputStream).split("&");
            Map<String, String> param = new HashMap<String, String>();
            if (params.length < 1 || params[0].trim().length() == 0) {
                throw new BaseException(400, "MissingAction","Missing Action");
            }
            for (int i = 0; i < params.length; i++) {
                log.info("params:" + params[i]);
                String[] strs = params[i].split("=", -1);
                if (strs.length < 2)
                    throw new BaseException(400, "InvalidArgument", params[i]);
                param.put(strs[0], URLDecoder.decode(strs[1], "UTF-8"));
            }
            if (!param.containsKey("Action")) {
                throw new BaseException(400, "MissingAction","Missing Action");
            }
            //判断version是否存在以及正确
            if(param.containsKey("Version")) {
        		String version = param.get("Version");
            	if(!API_VERSION.equals(version))
                   throw new BaseException(400, "InvalidAction","Could not find operation " + param.get("Action") + " for version " + version + ".");
        	}
            manageEvent = createCloudTrailEvent(req, param, authResult);
            // 处理IAM API请求
            handleIAMAPI(basereq, req, resp, param, authResult, manageEvent);
        } catch (BaseException e) {
            log.error("requestId: " + reqid + " ,url: " + req.getRequestURL(), e);
            resp.setStatus(e.status);
            e.reqId = (String) req.getAttribute(Headers.REQUEST_ID);
            if(manageEvent != null) {
                manageEvent.getEvent().errorStatus = e.status;
                manageEvent.getEvent().errorCode = e.code;
                manageEvent.getEvent().errorMessage = e.message;
            }
            writeError(req, resp, e);
        } catch (Throwable e) {
            log.error("requestId: " + reqid + " ,url: " + req.getRequestURL(), e);
            BaseException be = new BaseException();
            be.status = 500;
            be.reqId = (String) req.getAttribute(Headers.REQUEST_ID);
            be.resource = req.getRequestURI();
            be.message = "We encountered an internal error. Please try again.";
            be.code = "InternalError";
            resp.setStatus(be.status);
            if(manageEvent != null) {
                manageEvent.getEvent().errorStatus = be.status;
                manageEvent.getEvent().errorCode = be.code;
                manageEvent.getEvent().errorMessage = be.message;
            }
            writeError(req, resp, be);
        } finally {
            basereq.setHandled(true);
            try {
                if (inputStream != null)
                    inputStream.close();
            } catch (IOException e) {
                log.error(e.getMessage(), e);
            }
            // 当manageEvent不为空时，表示需要记录用户的管理事件
            if(manageEvent != null)
                try {
                    metaClient.manageEventInsert(manageEvent);
                } catch (Exception e) {
                    log.error("cloudTrailServer error: insert manageEvent error!" + manageEvent.getRowKey());
                }
        }
    }
    
    /**
     * 创建日志审计事件
     * @param req
     * @param param
     * @param authResult
     * @return
     * @throws ParseException
     * @throws BaseException
     */
    public ManageEventMeta createCloudTrailEvent(HttpServletRequest req, Map<String, String> param, AuthResult authResult) throws ParseException, BaseException {
        String action = param.get("Action");
        String requestId = req.getAttribute(Headers.REQUEST_ID).toString();
        ManageEventMeta manageEvent = null;
        // 记录管理事件
        CloudTrailManageEvent eventAction = checkAndGetCloudTrailAction(action);
        if (authResult.owner.ifRecordManageEvent && eventAction != null) {
            manageEvent = new ManageEventMeta();
            CloudTrailEvent event = manageEvent.getEvent();
            // 固定参数
            event.eventSource = "oos-cn-iam.ctyunapi.cn";
            event.eventType = "ApiCall";
            event.serviceName = "IAM";
            event.managementEvent = true;
            // 用户参数
            if (authResult.isSts) {
                event.userType = "STSUser";
                event.accessKeyId = authResult.tokenMeta.stsAccessKey;
            } else if (authResult.isRoot()) {
                event.userType = "Root";
                event.principalId = authResult.owner.getAccountId();
                event.arn = authResult.getUserArn();
                event.accessKeyId = authResult.accessKey.accessKey;
            } else {
                event.userType = "IAMUser";
                event.userName = authResult.accessKey.userName;
                event.principalId = authResult.accessKey.userId;
                event.arn = authResult.getUserArn();
                event.accessKeyId = authResult.accessKey.accessKey;
            }            
            event.ownerId = authResult.owner.getId();
            event.eventOwnerId = authResult.owner.getId();
            

            // 请求的事件参数
            event.eventTime = (long) req.getAttribute(Headers.DATE);
            event.requestId = requestId;
            event.userAgent = req.getHeader(HttpHeaders.USER_AGENT);
            event.sourceIpAddress = Utils.getIpAddr(req);
            event.requestRegion = Utils.getRegionNameFromReq(req, V4Signer.STS_SERVICE_NAME);
            
            String protocol = req.getHeader("x-forwarded-proto");
            String requestURLString = req.getRequestURL().toString();
            int reqPort = req.getServerPort();
            requestURLString = requestURLString.replace(":" + reqPort, "");
            if (protocol != null && requestURLString.contains("https://")) {
                requestURLString = requestURLString.replace("https://", protocol + "://");
            } else if (protocol != null && requestURLString.contains("http://")) {
                requestURLString = requestURLString.replace("http://", protocol + "://");
            }
            event.requestURL = requestURLString;
            
            event.eventName = eventAction.getName();
            event.readOnly = eventAction.getReadOnly();
            
            if (req.getHeader("OOS-PROXY-HOST") != null && req.getHeader("OOS-PROXY-HOST").equals("oos-proxy")) {// 来自proxy转发的请求
                event.accessKeyId = null;
                event.eventSource = "oos-cn.ctyun.cn";
                event.userAgent =  "oos-cn.ctyun.cn";
                event.requestURL = req.getParameter("proxyURL");
                event.sourceIpAddress = req.getHeader("x-ctyun-client-ip");
            }
        }
        return manageEvent;
    }
    
    /**
     * 判断签名是否是V2签名
     * @return
     */
    private boolean isAuthV2(HttpServletRequest req) {
        String auth = req.getHeader(V4Signer.AUTHORIZATION);
        if (auth == null || auth.length() == 0) {
            return false;
        }
        return auth.toUpperCase().startsWith("AWS ");
    }
    
    /**
     * 处理用户发起的IAM API的请求
     * 查找请求参数Action对应的方法，并执行方法处理请求
     * 
     * @param basereq
     * @param req
     * @param resp
     * @param param
     * @param owner
     * @param accessKey
     * @throws Throwable
     */
    private ManageEventMeta handleIAMAPI(Request basereq, HttpServletRequest req, HttpServletResponse resp,
            Map<String, String> param, AuthResult authResult, ManageEventMeta manageEvent) throws Throwable {
        if (authResult.owner == null) {
            throw new BaseException(403, "AccessDenied");
        }
        String action = param.get("Action");
        String requestId = req.getAttribute(Headers.REQUEST_ID).toString();
        
        // 通用请求处理
        // 获取请求Action对应的方法
        ActionMethod actionMethod = IAMActions.getActionMethod(action);
        if (actionMethod == null) {
           String version = param.containsKey("Version") ? version = param.get("Version") : API_VERSION;
           throw new BaseException(400, "InvalidAction","Could not find operation " + action + " for version " + version + ".");
        }
        
        // 创建请求操作的参数
        ActionParameter actionParam = actionMethod.createActionParameter(param, authResult);
        try {
            actionParam.request = req;
            // 请求是否来自于控制台
            actionParam.isFromConsole = req.getHeader("OOS-PROXY-HOST") != null;
            // 如果不是根用户，进行访问控制
            IAMAccessControlUtils.auth(action, actionParam);
            
            // 日志审计资源与请求参数
            if (manageEvent != null) {
                manageEvent.getEvent().resources = actionParam.getTrailResources();
                manageEvent.getEvent().requestParameters = actionParam.toJson();
            }

            // 处理请求，执行请求action对应的方法
            Result result = actionMethod.invoke(actionParam);
            
            // 日志审计响应参数
            if (manageEvent != null) {
                if (result != null) {
                    manageEvent.getEvent().responseElements = result.toJson();
                }
            }

            // 处理方法返回
            String resultStr = null;
            if (acceptJson(req)) {
                resultStr = toJsonResult(action, result, requestId);
                resp.setContentType("application/json");
            } else {
                resultStr = toXmlResult(action, result, requestId);
                resp.setContentType("text/xml");
            }
            // 返回处理结果
            HttpUtils.writeResponseEntity(resp, resultStr);
            
            // 统一的日志
            if (log.isDebugEnabled()) {
                log.debug(resultStr);
            }
        } catch (BaseException e) {
            // 向BaseException中添加resource信息
            String resource = actionParam.getResource() == null ? "" : actionParam.getResource();
            e.resource = resource;
            throw e;
        }
        return manageEvent;
    }
    

    
    /**
     * 返回请求是否期望的返回格式为json
     * @param request
     * @return
     */
    private boolean acceptJson(HttpServletRequest request) {
        String accept = request.getHeader("Accept");
        if (accept == null) {
            return false;
        }
        return accept.contains("application/json");
    }
    
    /**
     * 将错误信息写到响应中
     * @param req
     * @param resp
     * @param be
     * @throws JsonProcessingException
     * @throws UnsupportedEncodingException
     */
    private void writeError(HttpServletRequest req, HttpServletResponse resp, BaseException be) throws JsonProcessingException, UnsupportedEncodingException {
        String errorMessage = null;
        if (acceptJson(req)) {
            errorMessage = JSONUtils.MAPPER.writeValueAsString(be);
            resp.setContentType("application/json");
        } else {
            // 解决toXmlWriter逻辑中会对resource进行decode，造成+号被替换为空格的问题
            be.resource = URLEncoder.encode(be.resource, Consts.STR_UTF8);
            errorMessage = be.toXmlWriter().toString();
            resp.setContentType("text/xml");
        }
        try {
            HttpUtils.writeResponseEntity(resp, errorMessage);
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }
    }
    
    /**
     * 判断是否属于操作审计的action
     * @param action
     * @throws BaseException 
     */
    private static CloudTrailManageEvent checkAndGetCloudTrailAction(String action) throws BaseException {
        CloudTrailManageEvent[] eventArray = CloudTrailManageEvent.class.getEnumConstants();
        Optional<CloudTrailManageEvent> op = Arrays.stream(eventArray).filter(e -> e.getName().equals(action)).findAny();
        if (op.isPresent())
            return op.get();
        return null;
    }
    
    
    /**
     * 将接口返回的结果转换为XML的格式
     * @param action
     * @param result
     * @param requestId
     * @return
     */
    public String toXmlResult(String action, Object result, String requestId) {
        if (result == null) {
            return XmlResultUtils.toXml(action, requestId);
        } else {
            // 方法返回字符串，直接作为返回内容
            if (result instanceof String) {
                return result.toString();
            } else {
                // 将返回对象转换为XML
                return XmlResultUtils.toXml(result, requestId);
            }
        }
    }
    
    /**
     * 将接口返回的结果转换为JSON的格式
     * @param action
     * @param result
     * @param requestId
     * @return
     */
    public String toJsonResult(String action, Object result, String requestId) throws JsonProcessingException {
        if (result != null && result instanceof String) {
            return result.toString();
        } 
        Map<String, Object> resultMap = new HashMap<>();
        if (result != null) {
            resultMap.put(IAMStringUtils.firstCharLowerCase(action) + "Result", result);
        }
        ResponseMetadata responseMetadata = new ResponseMetadata();
        responseMetadata.requestId = requestId;
        resultMap.put("responseMetadata", responseMetadata);
        return JSONUtils.MAPPER.writeValueAsString(resultMap);
    }
    
}