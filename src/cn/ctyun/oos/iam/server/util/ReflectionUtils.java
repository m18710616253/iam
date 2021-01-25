package cn.ctyun.oos.iam.server.util;

import java.lang.reflect.Field;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;

/**
 * 反射工具类
 * @author wangduo
 *
 */
public class ReflectionUtils {
    
    /**
     * 获取成员变量的泛型
     * @param field
     * @return
     */
    public static Class<?> getGenericClass(Field field) {
        // 得到其Generic的类型
        Type fc = field.getGenericType();
        // 如果没有泛型参数类型
        if (fc == null || !(fc instanceof ParameterizedType)) {
            throw new ReflectionException("Field [" + field.getName() + "] has no generic class.");
        }
        ParameterizedType pt = (ParameterizedType) fc;
        // 得到泛型里的class类型
        return (Class<?>) pt.getActualTypeArguments()[0];
    }
    
    /**
     * 从orig对象中复制成员变量的值到dest对象
     * 不复制值为null的成员变量
     * @param dest
     * @param orig
     */
    public static <T> void copyProperties(T dest, T orig) {
        for (Field field : orig.getClass().getFields()) {
            // 获取修饰符只为public的成员变量
            if (field.getModifiers() != 1) continue;
            // 值为null不复制
            Object value;
            try {
                value = field.get(orig);
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            }
            if (value == null) continue;
            try {
                field.set(dest, value);
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        }
    }
    
}
