package cn.ctyun.oos.iam.server.hbase;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * HBase列注解
 * 
 * @author wangduo
 *
 */
@Target({ ElementType.FIELD })
@Retention(value=RetentionPolicy.RUNTIME)
public @interface Qualifier {

    /** 列族默认名称 */
    public static final String DEFAULT_FAMILY = "i";

    /** 列族名称 */
    String columnFamily() default DEFAULT_FAMILY;
    
    /** HBase列名，该值为空时会使用成员变量的名称作为列名 */
    String name() default "";
}
