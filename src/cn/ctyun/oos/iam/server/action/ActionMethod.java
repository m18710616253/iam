package cn.ctyun.oos.iam.server.action;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Map;

import cn.ctyun.common.BaseException;
import cn.ctyun.oos.iam.accesscontroller.util.IAMStringUtils;
import cn.ctyun.oos.iam.server.result.Result;
import cn.ctyun.oos.iam.signer.AuthResult;

/**
 * Action方法，对应一个Action类中的方法
 * 当请求中包含Action参数时，会找到对应的ActionMethod，执行Action类中的方法
 * @author wangduo
 *
 */
public class ActionMethod {
    
    /** Action对应的方法 */
    public Method method;
    /** 方法参数的类 */
    public Class<? extends ActionParameter> paramClass;
    /** 参数类的成员变量 */
    public Field[] paramFields;
    
    public ActionMethod(Method method, Class<? extends ActionParameter> paramClass) {
        this.method = method;
        this.paramClass = paramClass;
        paramFields = paramClass.getDeclaredFields();
        for (Field field : paramFields) {
            field.setAccessible(true);
        }
    }

    /**
     * 创建请求操作的参数
     * 传入到接口对应的方法中
     * 
     * @param requestParams
     * @param owner
     * @param accessKey
     * @return
     * @throws BaseException
     * @throws IOException 
     */
    public ActionParameter createActionParameter(Map<String, String> requestParams, AuthResult authResult) throws BaseException, IOException {
        ActionParameter actionParam;
        try {
            // 实例化方法参数
            actionParam = paramClass.newInstance();
        } catch (InstantiationException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
        actionParam.requestParams = requestParams;
        actionParam.paramFields = paramFields;
        actionParam.currentOwner = authResult.owner;
        actionParam.currentAccessKey = authResult.accessKey;
        actionParam.authResult = authResult;
        try {
            BaseException paramSetException = null;
            // 遍历参数进行设值
            for (Field field : paramFields) {
                field.setAccessible(true);
                String paramKey = IAMStringUtils.firstCharUpperCase(field.getName());
                String value = requestParams.get(paramKey);
                try {
                    actionParam.set(field, value);
                } catch (BaseException e) {
                    paramSetException = e;
                }
            }
            // 设置完所有参数，再抛出异常
            // 解决错误提示时，getResource()对应的参数还没有被赋值就抛出异常，错误提示中没有resource的问题
            if (paramSetException != null) {
               throw paramSetException;
            }
            // 参数解析
            actionParam.parseParams();
            // 参数验证
            actionParam.validate();
            // 处理参数解析和参数校验时的错误信息
            actionParam.processErrorMessages();
        } catch (BaseException e) {
            // 设置请求的资源名称
            String resource = actionParam.getResource() == null ? "" : actionParam.getResource();
            e.resource = resource;
            throw e;
        }
        
        return actionParam;
    }
    
    /**
     * 执行Action对应的方法
     * 
     * @param actionParam 请求参数
     * @return 请求响应内容
     * @throws Throwable 
     */
    public Result invoke(ActionParameter actionParam) throws Throwable {
        try {
            // 执行方法
            Object result = method.invoke(null, actionParam);
            return result == null ? null : (Result) result;
        } catch (InvocationTargetException e) {
            // 抛出方法执行时抛出的异常
            Throwable targetException = e.getTargetException();
            throw targetException;
        }
    }
 
}