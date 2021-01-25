package cn.ctyun.oos.iam.server.action;

import java.lang.reflect.Method;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import cn.ctyun.oos.iam.accesscontroller.util.IAMStringUtils;
import cn.ctyun.oos.iam.server.util.ClasspathPackageScanner;

/**
 * IAM API action 操作
 * 可以通过该类获取action对应要执行的方法
 * 
 * @author wangduo
 *
 */
public class IAMActions {

    private static final Log log = LogFactory.getLog(IAMActions.class);
    
    /** Action的参数字符串与方法的MAP，只是在类初始化时被加载 */
    private static final Map<String, ActionMethod> actionMethodMap = new LinkedHashMap<>();
    
    static {
        
        // 获取指定包下的Action注解的类
        ClasspathPackageScanner packageScanner = new ClasspathPackageScanner(IAMActions.class.getClassLoader());
        List<Class<?>> actionClasses = packageScanner.getClasses("cn.ctyun.oos.iam.server.action.api", Action.class);
        
        // 加载Action处理类
        for (Class<?> clazz : actionClasses) {
            // 获取action中的所有方法
            for (Method method : clazz.getMethods()) {
                // 获取方法名，首字符转大写
                String methodKey = IAMStringUtils.firstCharUpperCase(method.getName());
                // 获取每个方法的参数
                Class<? extends ActionParameter> paramClass = null;
                for (Class<?> pClass : method.getParameterTypes()) {
                    // 只获取继承ActionParameter的参数
                    if (ActionParameter.class.isAssignableFrom(pClass)) {
                        paramClass =  (Class<? extends ActionParameter>) pClass;
                    }
                }
                // 没有获取到继承ActionParameter的参数，不做处理
                if (paramClass == null) {
                    continue;
                }
                // 创建一个Action方法
                ActionMethod actionMethod = new ActionMethod(method, paramClass);
                // 将action方法放到map中，对应请求中的action参数
                actionMethodMap.put(methodKey, actionMethod);
            }
        }
        log.info("Action init finished, Actions:" + actionMethodMap.keySet());
    }
    
    /**
     * 通过请求中的Action参数获取Action方法
     * @param action
     * @return
     */
    public static ActionMethod getActionMethod(String action) {
        return actionMethodMap.get(action);
    }

}
