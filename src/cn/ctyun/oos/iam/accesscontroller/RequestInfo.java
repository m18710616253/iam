package cn.ctyun.oos.iam.accesscontroller;

import java.util.TimeZone;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.time.DateFormatUtils;

import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.accesscontroller.util.IAMErrorMessage;
import cn.ctyun.oos.iam.accesscontroller.util.IPUtils;

/**
 * 请求信息
 * @author wangduo
 *
 */
public class RequestInfo {

    private static TimeZone UTC = TimeZone.getTimeZone("UTC");
    public static final String DEFAULT_DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss'Z'";
    
    /** 请求的Action */
    public String action;
    /** 请求的资源 */
    public String resource;
    /** 请求者的身份 */
    public String principal;
    
    /** 请求者的ID */
    public String accountId;
    
    // condition
    /** 请求者的ID */
    public String userId;
    /** 请求者的用户名  */
    public String userName;
    /** 请求时间 */
    public String currentTime;
    /** 请求是否使用SSL发送 */
    public String secureTransport;
    /** 请求这的客户端应用程序 */
    public String userAgent;
    /** 请求中的Referer请求头信息 */
    public String referer;
    /** 请求者的IP */
    public String sourceIp;
    /** OOS ListBucket 请求参数 */
    public String oosPrefix;
    /** OOS PutBucket ACL 请求头 */
    public String xAmzAcl;
    
    /** 
     * 是否经过多因子认证
     * 当请求来自控制台时，proxy必须携带Multi-Factor-Auth-Present请求头，表示用户当前会话是否输入过正确的MFA验证码
     */
    public String multiFactorAuthPresent;
    /**
     * 最后一次多因子认证的间隔时间（秒）
     * 当用户当前会话正确输入MFA验证码时，记录该时间，使用Multi-Factor-Auth-Time请求头传递
     */
    public String multiFactorAuthAge;
    
    /** 请求是否来自控制台 */
    public Boolean fromConsole = false;
    
    /** 错误提示时展示的resource信息 */
    public String resourceTip;
    
    public RequestInfo(String action, String resource, String accountId, String userId, String userName, HttpServletRequest request) {
        this.action = action;
        this.resource = resource;
        this.accountId = accountId;
        this.userId = userId;
        this.userName = userName;
        // 获取当前时间
        this.currentTime = DateFormatUtils.format(System.currentTimeMillis(), DEFAULT_DATE_FORMAT, UTC);
        // 是否是https请求
        this.secureTransport = String.valueOf("https".equalsIgnoreCase(request.getHeader("X-Forwarded-Proto")) || request.isSecure());
        this.userAgent = request.getHeader("User-Agent");
        this.referer = request.getHeader("Referer");
        this.sourceIp = IPUtils.getIpAddress(request);
        // 请求是否来自控制台
        this.fromConsole = request.getHeader("OOS-PROXY-HOST") != null;
        if (this.fromConsole) {
            // 是否经过多因子认证
            this.multiFactorAuthPresent = request.getHeader("Multi-Factor-Auth-Present");
            // 最后一次多因子认证的间隔时间
            this.multiFactorAuthAge = request.getHeader("Multi-Factor-Auth-Age");
        }
        // OOS ListBucket 请求参数
        this.oosPrefix = request.getParameter("prefix");
        // OOS PutBucket ACL 请求头
        this.xAmzAcl = request.getHeader("x-amz-acl");
    }
    
    /**
     * 获取请求者的ARN
     * @return
     */
    public String getUserArn() {
        return ARNUtils.generateUserArn(accountId, userName);
    }
    
    /**
     * 错误提示时展示的资源
     * @return
     */
    public String getResourceTip() {
        return resourceTip == null ? resource : resourceTip;
    }

    /**
     * 获取错误提示信息
     * @return
     */
    public String getErrorMessage() {
        return getIAMErrorMessage().generateMessage();
    }
    
    /**
     * 获取有错误code的异常信息
     * @return
     */
    public IAMErrorMessage getIAMErrorMessage() {
        return  new IAMErrorMessage("identityAccessDenied", "User: %s is not authorized to perform: %s on resource: %s.", 
                getUserArn(), action, getResourceTip());
    }
    
    @Override
    public String toString() {
        return "RequestInfo [action=" + action + ", resource=" + resource + ", principal=" + principal + ", accountId=" + accountId + ", userId=" + userId + ", userName=" + userName + ", currentTime="
                + currentTime + ", secureTransport=" + secureTransport + ", userAgent=" + userAgent + ", referer=" + referer + ", sourceIp=" + sourceIp + "]";
    }
    
}
