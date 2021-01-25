package cn.ctyun.oos.iam.accesscontroller.util;

/**
 * ARN工具
 * @author wangduo
 *
 */
public class ARNUtils {

    public static final String ARN_PREFIX = "arn:ctyun:iam::";
    public static final String ARN_AWS_PREFIX = "arn:aws:iam::";

    
    /**
     * 生成ARN
     * @return
     */
    public static String generateArn(String accountId, String resourceType, String resourceName) {
        String resource = resourceType + "/" + resourceName;
        return generateArn(accountId, resource);
    }
    
    /**
     * 生成ARN
     * @return
     */
    public static String generateArn(String accountId, String resource) {
        return ARN_PREFIX + accountId + ":" + resource;
    }
    
    /**
     * 生成AWS格式的ARN
     * @return
     */
    public static String generateAWSArn(String accountId, String resourceType, String resourceName) {
        String resource = resourceType + "/" + resourceName;
        return generateAWSArn(accountId, resource);
    }
    
    /**
     * 生成AWS格式的ARN
     * @return
     */
    public static String generateAWSArn(String accountId, String resource) {
        return ARN_AWS_PREFIX + accountId + ":" + resource;
    }
    
    /**
     * 生成根用户的ARN
     * @param accountId
     * @return
     */
    public static String generateRootArn(String accountId) {
        return generateArn(accountId, "root");
    }
    
    /**
     * 生成用户的ARN
     * @return
     */
    public static String generateUserArn(String accountId, String resourceName) {
        return generateArn(accountId, "user", resourceName);
    }
    
    /**
     * 生成用户的AWS格式的ARN
     * @return
     */
    public static String generateUserAWSArn(String accountId, String resourceName) {
        return generateAWSArn(accountId, "user", resourceName);
    }
    
    /**
     * 生成用户组的ARN
     * @param accountId
     * @param resourceName
     * @return
     */
    public static String generateGroupArn(String accountId, String resourceName) {
        return generateArn(accountId, "group", resourceName);
    }
    
    /**
     * 生成策略的ARN
     * @param accountId
     * @param path
     * @param resourceName
     * @return
     */
    public static String generatePolicyArn(String accountId, String resourceName) {
        return generateArn(accountId, "policy", resourceName);
    }
    
    /**
     * 生成策略的ARN
     * @param accountId
     * @param path
     * @param resourceName
     * @return
     */
    public static String generateMFAArn(String accountId, String resourceName) {
        return generateArn(accountId, "mfa", resourceName);
    }
    
    /**
     * 获取ARN中的资源名称
     * @param arn
     * @return
     */
    public static String getResourceName(String arn) {
        if (arn == null) {
            return null;
        }
        String[] arnSplits = arn.split("/");
        if (arnSplits.length > 1) {
            return arnSplits[1];
        }
        return "";
    }
}
