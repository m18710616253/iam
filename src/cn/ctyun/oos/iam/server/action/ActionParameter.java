package cn.ctyun.oos.iam.server.action;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.fasterxml.jackson.core.JsonProcessingException;

import cn.ctyun.common.BaseException;
import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.accesscontroller.util.IAMErrorMessage;
import cn.ctyun.oos.iam.accesscontroller.util.IAMException;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.util.JSONUtils;
import cn.ctyun.oos.iam.signer.AuthResult;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.CloudTrailEvent.Resources;
import cn.ctyun.oos.metadata.OwnerMeta;

/**
 * 请求参数基类
 * String及基本数据类型可以被自动赋值
 * 
 * @author wangduo
 *
 */
public abstract class ActionParameter {

    private static final Log log = LogFactory.getLog(ActionParameter.class);
    
    /** 账户信息 */
    public OwnerMeta currentOwner;
    
    /** 当前用户请求用的AK（根用户或子用户） */
    public AkSkMeta currentAccessKey;
    
    /** 请求参数 */
    public Map<String, String> requestParams;
    
    /** 参数校验错误信息列表 */
    public List<IAMErrorMessage> errorMessages = new ArrayList<>();
    
    /** 请求是否来自于用户控制台访问 */
    public boolean isFromConsole = false;
    
    /** 认证信息 */
    public AuthResult authResult;
    
    /** 当前类的成员变量 */
    public Field[] paramFields;
    
    public HttpServletRequest request;
    
    /** 
     * 是否是根用户 
     */
    public boolean isRoot() {
        return authResult.isRoot();
    }
    
    /**
     * 获取账户ID
     * @return
     */
    public String getAccountId() {
        return currentOwner.getAccountId();
    }
    
    /**
     * 返回当前请求的用户
     * 只包含账户ID和用户名
     * @return
     */
    public User getCurrentUser() {
        User user = new User();
        user.accountId = getAccountId();
        user.userName = currentAccessKey.userName;
        return user;
    }
    
    /**
     * 请求参数解析
     * String及基本数据类型不需要处理，在ActionMethod的invoke方法中通过通用逻辑进行赋值
     * @throws BaseException 
     */
    public void parseParams() throws BaseException {
    }
    
    /**
     * 参数验证
     * 这里只处理400的错误
     * 需要收集所有的400错误信息，全部提示给用户
     */
    public abstract void validate();
    
    /**
     * 描述请求的资源
     * 用于请求出错时，设置到异常的Resource中进行展示
     */
    public String getResource() {
        return "/";
    }
    
    /**
     * 访问资源的ARN
     * @return
     */
    public String getResourceArn() {
        return ARNUtils.generateArn(getAccountId(), "*");
    }
    
    /**
     * 当没有权限时，给出的错误中的资源提示
     * 目前用于GetAccessKeyLastUsed接口的特殊处理
     * 默认情况下，都使用resourceArn作为提示
     * @return
     */
    public String getResourceTip() {
        return null;
    }
    
    /**
     * 处理参数解析和参数校验时的错误信息
     * @throws BaseException
     */
    public void processErrorMessages() throws BaseException {
        if (errorMessages.size() == 0) {
            return;
        }
        String errorStr = errorMessages.size() == 1 ? "error" : "errors";
        String message = errorMessages.size() + " validation " + errorStr + " detected: " + StringUtils.join(errorMessages, "; ");
        throw new IAMException(400, "ValidationError", message, errorMessages);
    }
    
    /**
     * 向参数中设值
     * XXX 参数类型是否需要支持这么多
     * @param field
     * @param value
     * @throws BaseException
     */
    public void set(Field field, String value) throws BaseException {
        if (value == null) {
            return;
        }
        try {
            if (field.getType() == String.class) {
                field.set(this, value);
                return;
            }
            if (field.getType() == Integer.class) {
                field.set(this, Integer.valueOf(value));
                return;
            }
            if (field.getType() == Short.class) {
                field.set(this, Short.valueOf(value));
                return;
            }
            if (field.getType() == Long.class) {
                field.set(this, Long.valueOf(value));
                return;
            }
            if (field.getType() == Byte.class) {
                field.set(this, Byte.valueOf(value));
                return;
            }
            if (field.getType() == Float.class) {
                field.set(this, Float.valueOf(value));
                return;
            }
            if (field.getType() == Double.class) {
                field.set(this, Double.valueOf(value));
                return;
            }
            if (field.getType() == Character.class) {
                field.set(this, value.charAt(0));
                return;
            }
            if (field.getType() == Boolean.class) {
                // 不是true false报错
                if (!value.equalsIgnoreCase("true") && !value.equalsIgnoreCase("false")) {
                    throw new IllegalArgumentException("value must be true or false.");
                }
                field.set(this, Boolean.valueOf(value));
                return;
            }
            // 忽略list
            if (List.class.isAssignableFrom(field.getType())) {
                return;
            }
        } catch (IllegalAccessException e) {
            throw new RuntimeException("set class [" + this.getClass().getName() + "] field [" + field.getName() + "] value [" + value + "] failed.", e);
        } catch (Exception e) {
            // 参数转换时引起的错误
            BaseException baseException = new BaseException(400, "MalformedInput", "Invalid Argument.");
            String message = "parse paramater " + field.getName() + " value " + value + " failed";
            log.error(message, e);
            throw baseException;
        }
        // 成员变量的类型没有对应的解析逻辑
        throw new RuntimeException("Cannot set type [" + field.getType() + "] of class [" + this.getClass().getName() + "] field [" + field.getName() + "].");
    }

    /**
     * 将当前参数对象转换为json
     * 该参数中只包含当前类的成员变量，不包括父类的成员变量
     * @return
     * @throws JsonProcessingException 
     */
    public String toJson() throws JsonProcessingException {
        Map<String, Object> map = new LinkedHashMap<>();
        for (Field field : paramFields) {
            try {
                Object value = field.get(this);
                if (value != null) {
                    map.put(field.getName(), value);
                }
            } catch (IllegalArgumentException | IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        }
        return JSONUtils.toTrailJSON(map);
    }
    
    /**
     * 返回日志审计记录的ARN
     * @return
     */
    public List<Resources> getTrailResources() {
        return null;
    }
}
