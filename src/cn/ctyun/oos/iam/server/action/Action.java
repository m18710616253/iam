package cn.ctyun.oos.iam.server.action;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Action注解
 */
@Target({ ElementType.TYPE })
@Retention(value=RetentionPolicy.RUNTIME)
public @interface Action {
	
    String name() default "";
}
