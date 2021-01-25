package cn.ctyun.oos.iam.server.util;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import cn.ctyun.oos.iam.accesscontroller.util.IAMErrorMessage;

/**
 * 参数校验工具
 * 
 * @author wangduo
 *
 */
public class ValidationUtils {
    
    /** 名称表达式 */
    public static final Pattern NAME_PATTERN = Pattern.compile("^[\\w+=,.@-]+$");
    /** 标签key表达式 */
    public static final Pattern TAG_KEY_PATTERN = Pattern.compile("^[\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]+$");
    /** 标签value表达式 */
    public static final Pattern TAG_VALUE_PATTERN = Pattern.compile("^[\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]*$");
    /** accessKeyId表达式 */
    public static final Pattern ACCESS_KEY_ID_PATTERN = Pattern.compile("^[\\w]+$");
    /** 策略JSON内容表达式 */
    public static final Pattern POLICY_DOCUMENT_PATTERN = Pattern.compile("^[\\u0009\\u000A\\u000D\\u0020-\\u00FF]+$");
    /** 密码表达式 */
    public static final Pattern PASSWORD_PATTERN = Pattern.compile("^[\\u0009\\u000A\\u000D\\u0020-\\u00FF]+$");
    /** 名称表达式 */
    public static final Pattern MFA_SERIAL_NUMBER_PATTERN = Pattern.compile("^[\\w+=/:,.@-]+$");
    /** MFA验证码 */
    public static final Pattern MFA_CODE_PATTERN = Pattern.compile("^[\\d]+$");
    
    /**
     * 校验正则表达式格式和字符串是否匹配
     * @param pattern
     * @param value
     * @return
     */
    public static boolean match(Pattern pattern, String value) {
        Matcher matcher = pattern.matcher(value);
        return matcher.matches();
    }
    
    /**
     * 校验用户名称格式
     * @param userName
     * @param errorMessages 错误消息
     */
    public static void validateUserName(String userName, List<IAMErrorMessage> errorMessages) {
        validateName("userName", userName, 64, errorMessages);
    }
    
    /**
     * 校验组名称格式
     * @param groupName
     * @param errorMessages 错误消息
     */
    public static void validateGroupName(String groupName, List<IAMErrorMessage> errorMessages) {
        validateName("groupName", groupName, 128, errorMessages);
    }
    
    /**
     * 校验策略名称格式
     * @param policyName
     * @param errorMessages 错误消息
     */
    public static void validatePolicyName(String policyName, List<IAMErrorMessage> errorMessages) {
        validateName("policyName", policyName, 128, errorMessages);
    }
    
    /**
     * 校验虚拟MFA设备名称格式
     * @param policyName
     * @param errorMessages 错误消息
     */
    public static void validateVirtualMFADeviceName(String virtualMFADeviceName, List<IAMErrorMessage> errorMessages) {
        validateName("virtualMFADeviceName", virtualMFADeviceName, 128, errorMessages);
    }
    
    
    /**
     * 校验名称格式
     * @param paramName 参数名
     * @param value 参数值
     * @param maxLength 最大长度
     * @param errorMessages 错误消息
     */
    private static void validateName(String paramName, String value, int maxLength, List<IAMErrorMessage> errorMessages) {
        if (isNull(paramName, value, errorMessages)) {
            return;
        }
        validateMaxLength(paramName, value, maxLength, errorMessages);
        if (!match(NAME_PATTERN, value)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage(paramName + "Invalid", 
                    "The specified value for '" + paramName + "' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-");
            errorMessages.add(errorMessage);
        }
    }
    
    /**
     * 校验参数是否为空
     * @param paramName
     * @param value
     * @param errorMessages
     * @return
     */
    private static boolean isNull(String paramName, String value, List<IAMErrorMessage> errorMessages) {
        if (value == null) {
            IAMErrorMessage errorMessage = new IAMErrorMessage(paramName + "Null", 
                    "Value null at '" + paramName + "' failed to satisfy constraint: Member must not be null");
            errorMessages.add(errorMessage);
            return true;
        }
        return false;
    }
    
    /**
     * 校验策略内容
     * @param policyDocument
     * @param errorMessages 错误消息
     */
    public static void validatePolicyDocument(String policyDocument, List<IAMErrorMessage> errorMessages) {
        if (isNull("policyDocument", policyDocument, errorMessages)) {
            return;
        }
        validateMaxLength("policyDocument", policyDocument, 131072, errorMessages);
        if (!match(POLICY_DOCUMENT_PATTERN, policyDocument)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("policyDocumentInvalid", 
                    "Value at 'policyDocument' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\u0009\\u000A\\u000D\\u0020-\\u00FF]+");
            errorMessages.add(errorMessage);
        }
    }
    
    /**
     * 校验描述
     * @param description
     * @param errorMessages
     */
    public static void validateDescription(String description, List<IAMErrorMessage> errorMessages) {
        if (description == null) {
            return;
        }
        validateMaxLength("description", description, 1000, errorMessages);
    }
    
    /**
     * 校验策略的ARN
     * @param policyArn
     * @param errorMessages
     */
    public static void validatePolicyArn(String policyArn, List<IAMErrorMessage> errorMessages) {
        if (isNull("policyArn", policyArn, errorMessages)) {
            return;
        }
        // 长度校验
        validateMinLength("policyArn", policyArn, 20, errorMessages);
        validateMaxLength("policyArn", policyArn, 2048, errorMessages);
    }
    
    /**
     * MFA SerialNumber校验
     * @param serialNumber
     * @param errorMessages
     */
    public static void validateMFASerialNumber(String serialNumber, List<IAMErrorMessage> errorMessages) {
        if (isNull("serialNumber", serialNumber, errorMessages)) {
            return;
        }
        if (!match(MFA_SERIAL_NUMBER_PATTERN, serialNumber)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("serialNumberInvalid", 
                    "The specified value for 'serialNumber' is invalid");
            errorMessages.add(errorMessage);
        }
        // 长度校验
        validateMaxLength("serialNumber", serialNumber, 2048, errorMessages);
    }
    
    /**
     * MFA验证码校验
     * @param paramName
     * @param code
     * @param errorMessages
     */
    public static void validateMFACode(String paramName, String code, List<IAMErrorMessage> errorMessages) {
        if (isNull(paramName, code, errorMessages)) {
            return;
        }
        if (code.length() != 6 || !match(MFA_CODE_PATTERN, code)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage(paramName + "Invalid", 
                    "The specified value for '" + paramName + "' is invalid. It must be a six-digit decimal number");
            errorMessages.add(errorMessage);
        }
    }
    
    /**
     * tagKey参数校验
     * @param tagKey
     * @param errorMessages 错误消息
     */
    public static void validateTagKey(String tagKey, int index, List<IAMErrorMessage> errorMessages) {
        if (tagKey == null) {
            return;
        }
        validateMaxLength("tags." + index + ".member.key", tagKey, 128, errorMessages);
        if (!match(TAG_KEY_PATTERN, tagKey)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("tagKeyInvalid", 
                    "Value '" + tagKey + "' at 'tags." + index + ".member.key' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]+");
            errorMessages.add(errorMessage);
        }
    }
    
    /**
     * tagValue参数校验
     * @param tagValue
     * @param errorMessages 错误消息
     */
    public static void validateTagValue(String tagValue, int index, List<IAMErrorMessage> errorMessages) {
        if (tagValue == null) {
            return;
        }
        validateMaxLength("tags." + index + ".member.value", tagValue, 256, errorMessages);
        if (!match(TAG_VALUE_PATTERN, tagValue)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("tagValueInvalid", 
                    "Value '" + tagValue + "' at 'tags." + index + ".member.value' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]*");
            errorMessages.add(errorMessage);
        }
    }
    
    /**
     * marker参数校验
     * @param marker
     * @param errorMessages 错误消息
     */
    public static void validateMarker(String marker, List<IAMErrorMessage> errorMessages) {
        if ("".equals(marker)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("markerInvalid", 
                    "The specified value for 'marker' is invalid. It must contain only printable ASCII characters");
            errorMessages.add(errorMessage);
        }
    }
    
    /**
     * maxItems参数校验
     * @param maxItems
     * @param errorMessages 错误消息
     */
    public static void validateMaxItems(Integer maxItems, List<IAMErrorMessage> errorMessages) {
        if (maxItems == null) {
            return;
        }
        validateMinValue("maxItems", maxItems, 1, errorMessages);
        validateMaxValue("maxItems", maxItems, 1000, errorMessages);
    }
    
    /**
     * accessKeyId参数校验
     * @param accessKeyId
     * @param errorMessages 错误消息
     */
    public static void validateAccessKeyId(String accessKeyId, List<IAMErrorMessage> errorMessages) {
        if (isNull("accessKeyId", accessKeyId, errorMessages)) {
            return;
        }
        validateMinLength("accessKeyId", accessKeyId, 16, errorMessages);
        validateMaxLength("accessKeyId", accessKeyId, 128, errorMessages);
        if (!match(ACCESS_KEY_ID_PATTERN, accessKeyId)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("accessKeyIdInvalid", 
                    "The specified value for 'accessKeyId' is invalid. It must contain only alphanumeric characters");
            errorMessages.add(errorMessage);
        }
    }
    
    /**
     * accessKeyId查询条件校验
     * @param accessKeyId
     * @param errorMessages 错误消息
     */
    public static void validateAccessKeyIdCond(String accessKeyId, List<IAMErrorMessage> errorMessages) {
        validateMaxLength("accessKeyId", accessKeyId, 128, errorMessages);
        if (!match(ACCESS_KEY_ID_PATTERN, accessKeyId)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("accessKeyIdInvalid", 
                    "The specified value for 'accessKeyId' is invalid. It must contain only alphanumeric characters");
            errorMessages.add(errorMessage);
        }
    }
    
    /**
     * accessKey isPrimary参数校验
     * @param isPrimary
     * @param errorMessages 错误消息
     */
    public static void validateAccessKeyIsPrimary(String isPrimary, List<IAMErrorMessage> errorMessages) {
        if (isPrimary == null) {
            return;
        }
        if (!"true".equalsIgnoreCase(isPrimary) && !"false".equalsIgnoreCase(isPrimary)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("accessKeyIsPrimaryInvalid", 
                    "Value '" + isPrimary + "' at 'isPrimary' failed to satisfy constraint: Member must satisfy enum value set: [true, false]");
            errorMessages.add(errorMessage);
        }
    }
    
    /**
     * accessKey status参数校验
     * @param status
     * @param errorMessages 错误消息
     */
    public static void validateAccessKeyStatus(String status, List<IAMErrorMessage> errorMessages) {
        if (isNull("status", status, errorMessages)) {
            return;
        }
        if (!"Active".equalsIgnoreCase(status) && !"Inactive".equalsIgnoreCase(status)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("accessKeyStatusInvalid", 
                    "Value '" + status + "' at 'status' failed to satisfy constraint: Member must satisfy enum value set: [Active, Inactive]");
            errorMessages.add(errorMessage);
        }
    }
    
    
    /**
     * 密码校验
     * @param errorMessages 错误消息
     */
    public static void validatePassword(String name, String value, List<IAMErrorMessage> errorMessages) {
        if (isNull(name, value, errorMessages)) {
            return;
        }
        // 长度校验
        validateMinLength(name, value, 8, errorMessages);
        validateMaxLength(name, value, 128, errorMessages);
        
        if (!match(PASSWORD_PATTERN, value)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage(name + "Invalid", 
                    "Value at '" + name + "' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\u0009\\u000A\\u000D\\u0020-\\u00FF]+");
            errorMessages.add(errorMessage);
        }
    }
    
    
    /**
     * 最小长度校验
     * @param paramName
     * @param value
     * @param minLength
     * @param errorMessages
     */
    private static void validateMinLength(String paramName, String value, int minLength, List<IAMErrorMessage> errorMessages) {
        if (value.length() < minLength) {
            IAMErrorMessage errorMessage = new IAMErrorMessage(paramName + "MinLength", 
                    "Value '" + value + "' at '" + paramName + "' failed to satisfy constraint: Member must have length greater than or equal to " + minLength);
            errorMessages.add(errorMessage);
        }
    }
    
    /**
     * 最大长度校验
     * @param paramName
     * @param value
     * @param maxLength
     * @param errorMessages
     */
    private static void validateMaxLength(String paramName, String value, int maxLength, List<IAMErrorMessage> errorMessages) {
        if (value.length() > maxLength) {
            IAMErrorMessage errorMessage = new IAMErrorMessage(paramName + "MaxLength", 
                    "Value '" + value + "' at '" + paramName + "' failed to satisfy constraint: Member must have length less than or equal to " + maxLength);
            errorMessages.add(errorMessage);
        }
    }
    
    /**
     * 最小值校验
     * @param paramName
     * @param value
     * @param minValue
     * @param errorMessages
     */
    public static void validateMinValue(String paramName, int value, int minValue, List<IAMErrorMessage> errorMessages) {
        if (value < minValue) {
            IAMErrorMessage errorMessage = new IAMErrorMessage(paramName + "MinValue", 
                    "Value '" + value + "' at '" + paramName + "' failed to satisfy constraint: Member must have value greater than or equal to " + minValue);
            errorMessages.add(errorMessage);
        }
    }
    
    /**
     * 最大值校验
     * @param paramName
     * @param value
     * @param maxValue
     * @param errorMessages
     */
    public static void validateMaxValue(String paramName, int value, int maxValue, List<IAMErrorMessage> errorMessages) {
        if (value > maxValue) {
            IAMErrorMessage errorMessage = new IAMErrorMessage(paramName + "MaxValue", 
                    "Value '" + value + "' at '" + paramName + "' failed to satisfy constraint: Member must have value less than or equal to " + maxValue);
            errorMessages.add(errorMessage);
        }
    }
    
}
