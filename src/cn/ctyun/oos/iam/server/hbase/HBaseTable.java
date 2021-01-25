package cn.ctyun.oos.iam.server.hbase;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 用于标记实体类对应的HBase表
 * @author wangduo
 *
 */
@Target({ ElementType.TYPE })
@Retention(value=RetentionPolicy.RUNTIME)
public @interface HBaseTable {

    /** 表名 */
    String name() default "";
    
    /** 表包含的列族 */
    String[] columnFamilies() default { Qualifier.DEFAULT_FAMILY };
    
    /** 当类只是实体关系时，用此属性标志出对应的实体类 */
    Class<? extends HBaseEntity> entityClass() default HBaseEntity.class;
    
    int maxVersions() default 1;
    
    int timeToLive() default 0;
}
