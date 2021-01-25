package cn.ctyun.oos.iam.server.util;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import com.fasterxml.jackson.annotation.JacksonAnnotationsInside;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

/**
 * 日志审计要展示的时间，将long型的时间转为指定格式的字符串时间
 * @author wangduo
 *
 */
@Target({ ElementType.FIELD })
@Retention(value=RetentionPolicy.RUNTIME)
@JacksonAnnotationsInside
@JsonSerialize(using = TrailDateSerializer.class)
public @interface TrailDate {

}
