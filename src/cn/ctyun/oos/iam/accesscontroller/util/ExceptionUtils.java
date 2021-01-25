package cn.ctyun.oos.iam.accesscontroller.util;

/**
 * 异常工具，异常通用代码
 * @author wangduo
 *
 */
public class ExceptionUtils {

    /**
     * 没有此用户
     * @param userName
     * @return
     */
    public static IAMException newNoSuchUserException(String userName) {
        IAMErrorMessage errorMessage = new IAMErrorMessage("noSuchUser", "The user with name %s cannot be found.", userName);
        return new IAMException(404, "NoSuchEntity", errorMessage);
    }
    
    /**
     * 没有此AK
     * @param accessKeyId
     * @return
     */
    public static IAMException newNoSuchAccessKeyException(String accessKeyId) {
        IAMErrorMessage errorMessage = new IAMErrorMessage("noSuchAccessKey", "The Access Key with id %s cannot be found.", accessKeyId);
        return new IAMException(404, "NoSuchEntity", errorMessage);
    }
    
    /**
     * 没有此账户密码策略
     * @param accountId
     * @return
     */
    public static IAMException newNoSuchAccountPasswordPolicyException(String accountId) {
        IAMErrorMessage errorMessage = new IAMErrorMessage("noSuchAccountPasswordPolicy", "The Password Policy with domain name %s cannot be found.", accountId);
        return new IAMException(404, "NoSuchEntity", errorMessage);
    }
    
    /**
     * 没有此账户
     * @param accountId
     * @return
     */
    public static IAMException newNoSuchAccountException(String accountId) {
        IAMErrorMessage errorMessage = new IAMErrorMessage("noSuchAccount", "The account with id '%s' cannot be found.", accountId);
        return new IAMException(404, "NoSuchEntity", errorMessage);
    }
    
    /**
     * 没有此组
     * @param groupName
     * @return
     */
    public static IAMException newNoSuchGroupException(String groupName) {
        IAMErrorMessage errorMessage = new IAMErrorMessage("noSuchGroup", "The group with name %s cannot be found.", groupName);
        return new IAMException(404, "NoSuchEntity", errorMessage);
    }
    
    /**
     * 没有此MFA设备
     * @param serialNumber
     * @return
     */
    public static IAMException newNoSuchMFADeviceException(String serialNumber) {
        IAMErrorMessage errorMessage = new IAMErrorMessage("noSuchMFADevice", "VirtualMFADevice with serial number %s does not exist.", serialNumber);
        return new IAMException(404, "NoSuchEntity", errorMessage);
    }
    
    /**
     * 不是用户有效的MFA设备
     * @param serialNumber
     * @return
     */
    public static IAMException newMFADeviceInvalidForUserException() {
        IAMErrorMessage errorMessage = new IAMErrorMessage("mfaDeviceInvalidForUser", "MFA Device invalid for user.");
        return new IAMException(404, "NoSuchEntity", errorMessage);
    }
    
    /**
     * 没有此策略
     * @param policyArn
     * @return
     */
    public static IAMException newNoSuchPolicyException(String policyArn) {
        IAMErrorMessage errorMessage = new IAMErrorMessage("noSuchPolicy", "Policy %s does not exist or is not attachable.", policyArn);
        return new IAMException(404, "NoSuchEntity", errorMessage);
    }
    
    /**
     * 没有此用户的登录配置
     * @param userName
     * @return
     */
    public static IAMException newNoSuchLoginProfileException(String userName) {
        IAMErrorMessage errorMessage = new IAMErrorMessage("noSuchLoginProfile", "Login Profile for User %s cannot be found.", userName);
        return new IAMException(404, "NoSuchEntity", errorMessage);
    }
}
