package cn.ctyun.oos.iam.server.util;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * JSON工具
 * @author wangduo
 *
 */
public class JSONUtils {

    /** JSON转换MAPPER */
    public static final ObjectMapper MAPPER = new ObjectMapper()
            // 禁用检测getter方法
            .disable(MapperFeature.AUTO_DETECT_GETTERS)
            // 禁用注解
            .disable(MapperFeature.USE_ANNOTATIONS)
            // 禁用未知属性的失败
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            // 不包含null成员
            .setSerializationInclusion(Include.NON_NULL);
    
    /** 日志审计结果输出专用MAPPER */
    public static final ObjectMapper TRAIL_MAPPER = new ObjectMapper()
            // 禁用检测getter方法
            .disable(MapperFeature.AUTO_DETECT_GETTERS)
            // 禁用未知属性的失败
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            // 不包含null成员
            .setSerializationInclusion(Include.NON_NULL);
    
    /**
     * 将object转换为JSON
     * @param list
     * @return
     * @throws JsonProcessingException 
     */
    public static String toJSON(Object obj) throws JsonProcessingException {
        if (obj == null) {
            return null;
        }
        return MAPPER.writeValueAsString(obj);
    }
    
    /**
     * 日志审计专用JSON转换
     * @param obj
     * @return
     * @throws JsonProcessingException
     */
    public static String toTrailJSON(Object obj) throws JsonProcessingException {
        if (obj == null) {
            return null;
        }
        return TRAIL_MAPPER.writeValueAsString(obj);
    }
    
    /**
     * 将list转换为JSONArray
     * @param list
     * @return
     * @throws JsonProcessingException 
     */
    public static String toJSONArray(List<?> list) throws JsonProcessingException {
        if (list == null) {
            return null;
        }
        return MAPPER.writeValueAsString(list);
    }
    
    /**
     * jsonArray转list
     * @param jsonArray
     * @param clazz
     * @return
     * @throws IOException
     */
    public static <T> List<T> toList(String jsonArray, Class<T> clazz) throws IOException {
        JavaType javaType = getCollectionType(ArrayList.class, clazz); 
        List<T> list = MAPPER.readValue(jsonArray, javaType);
        return list;
    }
    
   /**   
    * 获取泛型的Collection Type  
    * @param collectionClass 泛型的Collection   
    * @param elementClasses 元素类   
    * @return JavaType Java类型   
    */   
    public static JavaType getCollectionType(Class<?> collectionClass, Class<?>... elementClasses) {   
        return MAPPER.getTypeFactory().constructParametrizedType(collectionClass, collectionClass, elementClasses);   
    }
}
