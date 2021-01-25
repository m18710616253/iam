package cn.ctyun.oos.iam.server.util;

import java.io.IOException;

import cn.ctyun.common.BaseException;
import cn.ctyun.oos.iam.accesscontroller.AccessController;
import cn.ctyun.oos.iam.accesscontroller.AccessEffect;
import cn.ctyun.oos.iam.accesscontroller.RequestInfo;
import cn.ctyun.oos.iam.accesscontroller.util.IAMException;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.entity.AccountPasswordPolicy;
import cn.ctyun.oos.iam.server.service.AccountPasswordPolicyService;
import cn.ctyun.oos.iam.server.service.IAMPolicyService;
import cn.ctyun.oos.iam.signer.AuthResult;

/**
 * IAM访问控制工具类
 * @author wangduo
 *
 */
public class IAMAccessControlUtils {

    private static final AccessController accessController = new AccessController(new IAMPolicyService());
    
    /**
     * 对请求进行访问控制
     * @param action
     * @param actionParam
     * @throws BaseException 
     * @throws IOException 
     */
    public static void auth(String action, ActionParameter actionParam) throws BaseException, IOException {

        // 根用户不做访问控制
        if (actionParam.isRoot()) {
            return;
        }
        // 子用户不能访问GetSessionToken接口
        if ("GetSessionToken".equals(action)) {
            throw new BaseException(403, "AccessDenied", "IAM User is not authorized to perform: iam: GetSessionToken");
        }
        
        AuthResult authResult = actionParam.authResult;
        // 获取访问控制需要的请求信息
        String requestAction = "iam:" + action;
        RequestInfo requestInfo = new RequestInfo(requestAction, actionParam.getResourceArn(), 
                authResult.owner.getAccountId(), authResult.accessKey.userId, authResult.accessKey.userName, actionParam.request);
        // 无权限时，展示resource的特殊处理，例如GetAccessKeyLastUsed接口
        if (actionParam.getResourceTip() != null) {
            requestInfo.resourceTip = actionParam.getResourceTip();
        }
        // 进行访问控制操作
        AccessEffect accessEffect = accessController.allow(requestInfo);
        // 拒绝或隐式拒绝
        if (accessEffect == AccessEffect.Deny || 
                (accessEffect == AccessEffect.ImplicitDeny && needImplicitDeny(action, authResult.owner.getAccountId(), authResult.accessKey.userName))) {
            // 拒绝访问处理
            throw new IAMException(403, "AccessDenied", requestInfo.getIAMErrorMessage());
        }
    
    }
    
    /**
     * 判断当前用户的操作是否需要进行隐式拒绝
     * 目前用户对ChangePassword接口做特殊处理
     * @return
     * @throws IOException 
     */
    private static boolean needImplicitDeny(String action, String accountId, String userName) throws IOException {
        
        // 如果不是ChangePassword的接口都需要隐式拒绝
        if (!"ChangePassword".equals(action)) {
            return true;
        }
        // 获取当前账户密码策略
        AccountPasswordPolicy passwordPolicy = AccountPasswordPolicyService.getAccountPasswordPolicy(accountId);
        // 如果当前账户允许用户自己改密码，不需要隐式拒绝
        if (passwordPolicy.allowUsersToChangePassword != null && passwordPolicy.allowUsersToChangePassword) {
            return false;
        }
        return true;
    }

    /**
     * 复制需要进行访问控制权限校验的属性
     * @param from
     * @param to
     */
    public static void setProperty(ActionParameter from, ActionParameter to) {
        to.currentOwner = from.currentOwner;
        to.currentAccessKey = from.currentAccessKey;
        to.authResult = from.authResult;
        to.request = from.request;
    }
}
