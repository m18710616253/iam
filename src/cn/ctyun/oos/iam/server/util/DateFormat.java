package cn.ctyun.oos.iam.server.util;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 列时间格式注解
 * 用户返回数据时，将long型的时间转为指定格式的字符串时间
 * @author wangduo
 *
 */
@Target({ ElementType.FIELD })
@Retention(value=RetentionPolicy.RUNTIME)
public @interface DateFormat {

}
