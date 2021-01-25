package cn.ctyun.oos.iam.accesscontroller.util;

import cn.ctyun.oos.metadata.CloudTrailEvent.Resources;

/**
 * 日志审计资源内容生成工具
 * @author wangduo
 *
 */
public class ResourcesUtils {

    /**
     * 生成子用户组的资源
     * @param accountId
     * @param userName
     * @return
     */
    public static Resources generateUserResources(String accountId, String userName) {
        Resources resources = new Resources();
        resources.resourceARN = ARNUtils.generateUserArn(accountId, userName);
        resources.resourceName = userName;
        resources.resourceType = "IAM User";
        return resources;
    }
    
    /**
     * 生成根用户组的资源
     * @param accountId
     * @param userName
     * @return
     */
    public static Resources generateRootUserResources(String accountId) {
        Resources resources = new Resources();
        resources.resourceARN = ARNUtils.generateRootArn(accountId);
        resources.resourceName = "root";
        resources.resourceType = "IAM User";
        return resources;
    }
    
    /**
     * 生成组的资源
     * @param accountId
     * @param groupName
     * @return
     */
    public static Resources generateGroupResources(String accountId, String groupName) {
        Resources resources = new Resources();
        resources.resourceARN = ARNUtils.generateGroupArn(accountId, groupName);
        resources.resourceName = groupName;
        resources.resourceType = "IAM Group";
        return resources;
    }
    
    /**
     * 生成策略的资源
     * @param accountId
     * @param policyName
     * @return
     */
    public static Resources generatePolicyResources(String accountId, String policyName) {
        Resources resources = new Resources();
        resources.resourceARN = ARNUtils.generatePolicyArn(accountId, policyName);
        resources.resourceName = policyName;
        resources.resourceType = "IAM Policy";
        return resources;
    }
    
    /**
     * 生成策略的资源
     * @param arn
     * @return
     */
    public static Resources generatePolicyResources(String arn) {
        Resources resources = new Resources();
        resources.resourceARN = arn;
        resources.resourceName = ARNUtils.getResourceName(arn);
        resources.resourceType = "IAM Policy";
        return resources;
    }
    
    /**
     * 生成多因子认证设备的资源
     * @param accountId
     * @param mfaDeviceName
     * @return
     */
    public static Resources generateMfaDeviceResources(String accountId, String mfaDeviceName) {
        Resources resources = new Resources();
        resources.resourceARN = ARNUtils.generateMFAArn(accountId, mfaDeviceName);
        resources.resourceName = mfaDeviceName;
        resources.resourceType = "IAM MfaDevice";
        return resources;
    }
    
    /**
     * 生成多因子认证设备的资源
     * @param arn
     * @return
     */
    public static Resources generateMfaDeviceResources(String arn) {
        Resources resources = new Resources();
        resources.resourceARN = arn;
        resources.resourceName = ARNUtils.getResourceName(arn);
        resources.resourceType = "IAM MfaDevice";
        return resources;
    }
    
    /**
     * 生成AccessKey的资源
     * @param accountId
     * @param mfaDeviceName
     * @return
     */
    public static Resources generateAccessKeyResources(String accessKeyId) {
        Resources resources = new Resources();
        resources.resourceARN = accessKeyId;
        resources.resourceName = accessKeyId;
        resources.resourceType = "IAM AccessKey";
        return resources;
    }
    
    
}
