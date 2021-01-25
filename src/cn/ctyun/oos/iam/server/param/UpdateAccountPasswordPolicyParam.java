package cn.ctyun.oos.iam.server.param;

import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.util.ValidationUtils;

/**
 * 更新账户的密码策略设置
 * @author wangduo
 *
 */
public class UpdateAccountPasswordPolicyParam extends ActionParameter {

    /** 是否允许用户更改其密码 */
    public Boolean allowUsersToChangePassword;
    /** 密码过期需要管理员重置 */
    public Boolean hardExpiry;
    /** 密码有效期（天）1-1095 */
    public Integer maxPasswordAge;
    /** 密码最小长度 8-128 */
    public Integer minimumPasswordLength;
    /** 防止密码重复使用，记录密码个数 1-24，0代表可以重复 */
    public Integer passwordReusePrevention;
    /** 至少需要一个小写字母 */
    public Boolean requireLowercaseCharacters;
    /** 至少需要一个大写字母 */
    public Boolean requireUppercaseCharacters;
    /** 至少需要一个数字 */
    public Boolean requireNumbers;
    /** 至少需要一个非字母数字字符 */
    public Boolean requireSymbols;

    
    @Override
    public void validate() {
        if (maxPasswordAge != null) {
            ValidationUtils.validateMinValue("maxPasswordAge", maxPasswordAge, 0, errorMessages);
            ValidationUtils.validateMaxValue("maxPasswordAge", maxPasswordAge, 1095, errorMessages);
        }
        if (minimumPasswordLength != null) {
            ValidationUtils.validateMinValue("minimumPasswordLength", minimumPasswordLength, 8, errorMessages);
            ValidationUtils.validateMaxValue("minimumPasswordLength", minimumPasswordLength, 128, errorMessages);
        }
        if (passwordReusePrevention != null) {
            ValidationUtils.validateMinValue("passwordReusePrevention", passwordReusePrevention, 0, errorMessages);
            ValidationUtils.validateMaxValue("passwordReusePrevention", passwordReusePrevention, 24, errorMessages);
        }
    }
}
