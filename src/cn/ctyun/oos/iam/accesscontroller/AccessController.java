package cn.ctyun.oos.iam.accesscontroller;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import cn.ctyun.common.BaseException;
import cn.ctyun.oos.iam.accesscontroller.policy.AccessPolicy;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.Condition;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.ConditionKey;
import cn.ctyun.oos.iam.accesscontroller.policy.reader.JsonDocumentFields;
import cn.ctyun.oos.iam.accesscontroller.service.DefaultPolicyService;
import cn.ctyun.oos.iam.accesscontroller.service.PolicyService;
import cn.ctyun.oos.iam.accesscontroller.util.IAMStringUtils;
import cn.ctyun.oos.iam.accesscontroller.util.MatchUtils;
import cn.ctyun.oos.iam.server.entity.MFADevice;
import cn.ctyun.oos.iam.server.service.MFAService;

/**
 * 访问控制工具
 * 
 * @author wangduo
 *
 */
public class AccessController {

    private static final Log log = LogFactory.getLog(AccessController.class);
    
    /** 获取策略的类 */
    private PolicyService policyService;
    
    public AccessController() {
        this.policyService = new DefaultPolicyService();
    }
    
    /**
     * IAM本地服务传入本地获取的实现类获取策略
     * @param policyService
     */
    public AccessController(PolicyService policyService) {
        this.policyService = policyService;
    }

    /**
     * 判断请求是被允许还是拒绝
     * 拒绝会抛出相应的异常
     * 
     * @param requestInfo 请求信息
     * @param policyDocuments 当前用户的策略内容列表
     * @throws IOException 
     */
    public AccessEffect allow(RequestInfo requestInfo) throws IOException, BaseException {
        // 获取用户策略
        // IAM自身获取用户策略和其他服务获取用户策略的方式不同
        // 其他服务走http接口，iam服务走本地调用
        List<AccessPolicy> policies = policyService.getUserPolicies(requestInfo.accountId, requestInfo.userName);
        
        // XXX 没有获取到数据的处理
        if (policies == null || policies.isEmpty()) {
            log.info("user has not policies, access implicit deny, " + toLogString(requestInfo, policies));
            return AccessEffect.ImplicitDeny;
        }
        
        // 只有请求来自于用户控制台访问才需要做MFA校验，通知用户输入MFA
        if (requestInfo.fromConsole) {
            validateMFAAuth(requestInfo, policies);
        }   
        
        // 匹配deny
        if (match(requestInfo, policies, Effect.Deny)) {
            log.error("access deny, " + toLogString(requestInfo, policies));
            // 拒绝
            return AccessEffect.Deny;
        }
        // 匹配allow
        if (match(requestInfo, policies, Effect.Allow)) {
            if (log.isDebugEnabled()) {
                log.debug("access allow, " + toLogString(requestInfo, policies));
            }
            // 允许
            return AccessEffect.Allow;
        }
        // 隐式拒绝，该情况下，如果有基于资源策略（OOS bucket policy）允许该操作，那么请求是应该被允许的
        log.info("access implicit deny, " + toLogString(requestInfo, policies));
        return AccessEffect.ImplicitDeny;
    }

    private String toLogString(RequestInfo requestInfo, List<AccessPolicy> policies) {
        List<String> policiesJson = new ArrayList<>();
        for (AccessPolicy accessPolicy : policies) {
            policiesJson.add(accessPolicy.jsonString);
        }
        return "requestInfo : " + requestInfo + ", polices : " + String.join(" ,", policiesJson);
    }
    
    /**
     * 判断请求信息是否匹配到了策略表中的策略 
     * @param requestInfo 请求信息
     * @param policies 策略列表
     * @param effect 匹配的允许和拒绝
     * @return
     */
    private boolean match(RequestInfo requestInfo, List<AccessPolicy> policies, Effect effect) {
        for (AccessPolicy policy : policies) {
            if (match(requestInfo, policy, effect)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * 判断请求信息是否和策略匹配 
     * @param requestInfo 请求信息
     * @param policy 策略
     * @param effect 匹配的允许和拒绝
     * @return
     */
    private boolean match(RequestInfo requestInfo, AccessPolicy policy, Effect effect) {
        
        for (Statement statement : policy.statements) {
            if (statement.effect != effect) {
                continue;
            }
            // 判断是否和策略中的statement匹配
            if (match(requestInfo, statement)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * 判断请求信息是否和Statement匹配 
     * @param requestInfo 请求信息
     * @param statement
     * @return
     */
    private boolean match(RequestInfo requestInfo, Statement statement) {
        
        // 匹配到action
        if (!matchAction(requestInfo.action, statement.actions, statement.ationEffect)) {
            return false;
        }
        // resource匹配
        if (!matchResource(requestInfo, statement.resources, statement.resourceEffect)) {
            return false;
        }
        // condition匹配
        if (!matchCondition(requestInfo, statement.conditions)) {
            return false;
        }
        return true;
    }
    
    /**
     * 匹配action
     * @param action 待匹配action
     * @param actionPatterns 规则列表
     * @param actionEffect
     * @return
     */
    private boolean matchAction(String action, List<String> actionPatterns, String actionEffect) {
        boolean actionMatch = false;
        for (String actionPattern : actionPatterns) {
            if (MatchUtils.isMatch(action, actionPattern)) {
                actionMatch = true;
                break;
            }
        }
        // 是否是Action元素
        boolean effect = JsonDocumentFields.ACTION.equals(actionEffect);
        // 如果字符串匹配同时是Action元素，为匹配
        // 如果字符串不匹配同时是NotAction元素，为匹配
        return actionMatch == effect;
    }
    
    /**
     * 匹配多个resource
     * @param resourceArn
     * @param resourcePatterns 
     * @param resourceEffect
     * @return
     */
    private boolean matchResource(RequestInfo requestInfo, List<String> resourcePatterns, String resourceEffect) {
        boolean resourceMatched = matchResource(requestInfo, resourcePatterns);
        // 是否是Resource元素
        boolean effect = JsonDocumentFields.RESOURCE.equals(resourceEffect);
        // 如果字符串匹配同时是Resource元素，为匹配
        // 如果字符串不匹配同时是NotResource元素，为匹配
        return resourceMatched == effect;
    }
    
    /**
     * 匹配resource
     * @param resourceArn
     * @param resourcePatterns
     * @return
     */
    private boolean matchResource(RequestInfo requestInfo, List<String> resourcePatterns) {
        // 服务没有传入resourceArn，不对resourceArn进行判断，直接返回true
        if (StringUtils.isEmpty(requestInfo.resource)) {
            return true;
        }
        for (String resourcePattern : resourcePatterns) {
            // 子用户名策略变量替换
            resourcePattern = IAMStringUtils.replaceUserNameVariable(resourcePattern, requestInfo.userName);
            if (MatchUtils.isMatch(requestInfo.resource, resourcePattern)) {
                return true;
            }
        }
        return false;
    }
    
    
    /**
     * 匹配condition
     * 多个condition之间是AND的关系
     * @param requestInfo
     * @param conditionPatterns
     * @return
     * XXX 条件键 和 条件运算符不匹配的情况如何处理
     */
    private boolean matchCondition(RequestInfo requestInfo, List<Condition> conditionPatterns) {
        // 没有条件，返回true
        if (conditionPatterns == null || conditionPatterns.size() == 0) {
            return true;
        }
        for (Condition condition : conditionPatterns) {
            // 有条件不匹配，返回不匹配
            if (!condition.match(requestInfo)) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * 校验是否有因为MFA条件键导致的匹配问题
     * @param requestInfo
     * @param policies
     * @throws BaseException 
     * @throws IOException 
     */
    private void validateMFAAuth(RequestInfo requestInfo, List<AccessPolicy> policies) throws BaseException, IOException {
        for (AccessPolicy policy : policies) {
            for (Statement statement : policy.statements) {
                // 如果不包含MFA相关的条件键，不做处理
                if (!statement.containsMFAKey) {
                    continue;
                }
                // action不匹配不做处理
                if (!matchAction(requestInfo.action, statement.actions, statement.ationEffect)) {
                   continue;
                }
                // resource不匹配不做处理
                if (!matchResource(requestInfo, statement.resources, statement.resourceEffect)) {
                    continue;
                }

                List<Condition> conditions = moveMFAToEnd(statement.conditions);
                // condition匹配
                for (Condition condition : conditions) {
                    boolean match = condition.match(requestInfo);
                    // deny mfa 匹配的情况 报错
                    if (statement.effect == Effect.Deny) {
                        if (!match) {
                            break;
                        }
                        // 对MFA条件造成的拒绝的匹配进行处理
                        mFAAuthValidate(condition, requestInfo);
                    }
                    // allow mfa 不匹配的情况 报错
                    if (statement.effect == Effect.Allow) {
                        if (!match) {
                            // 对MFA条件造成的允许的不匹配进行处理
                            mFAAuthValidate(condition, requestInfo);
                            break;
                        }
                    }
                }
            }
        }
    }
    
    /**
     * 判断是否是由于MFA验证码没有输入，或者时间条件匹配问题，造成的拒绝和没有匹配到allow条件
     * @param condition
     * @param requestInfo
     * @throws BaseException
     * @throws IOException 
     */
    private void mFAAuthValidate(Condition condition, RequestInfo requestInfo) throws BaseException, IOException {
    	// 如果匹配到是否输入过MFA
        if (ConditionKey.MULTI_FACTOR_AUTH_PRESENT.keys.contains(condition.conditionKey)) {
            boolean multiFactorAuthPresent = Boolean.valueOf(requestInfo.multiFactorAuthPresent);
            if (!multiFactorAuthPresent) {
            	hasMFADevice(requestInfo);
                throw new BaseException(403, "MFAAuthRequired", "Please input your MFA code.");
            }
        }
        // 校验MFA时间
        if (ConditionKey.MULTI_FACTOR_AUTH_AGE.keys.contains(condition.conditionKey)) {
        	hasMFADevice(requestInfo);
        	throw new BaseException(403, "MFAAuthRequired", "Please input your MFA code.");
        }
    }
    
    /**
     * 将MFA条件移动到尾部
     * @param conditions
     * @return
     */
    private List<Condition> moveMFAToEnd(List<Condition> conditions) {
        List<Condition> result = new ArrayList<>();
        List<Condition> mfas = new ArrayList<>(2);
        for (Condition condition : conditions) {
            if (condition.hasMFAKey()) {
                mfas.add(condition);
            } else {
                result.add(condition);
            }
        }
        result.addAll(mfas);
        return result;
    }
    
    /**
     * 判断用户是否有MFA设备，若没有MFA设备，抛出异常
     * @param requestInfo
     * @throws IOException 
     * @throws BaseException 
     */
    private void hasMFADevice(RequestInfo requestInfo) throws IOException, BaseException {
    	MFADevice mFADevice = MFAService.getUserMFADevice(requestInfo.accountId, requestInfo.userName);
    	if(mFADevice==null)
    		throw new BaseException(403, "NoSuchMFADevice", "The MFA must not be empty.");
    }
}
