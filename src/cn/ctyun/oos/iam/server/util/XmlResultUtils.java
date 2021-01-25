package cn.ctyun.oos.iam.server.util;

import java.lang.reflect.Field;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.amazonaws.services.s3.internal.XmlWriter;

import cn.ctyun.oos.iam.accesscontroller.util.IAMStringUtils;

/**
 * XML返回结果工具
 * 
 * @author wangduo
 *
 */
public class XmlResultUtils {

    // TODO  class field缓存
    /**
     * 将对象转换为XML
     * @param object
     * @param requestId
     * @return
     */
    public static String toXml(Object object, String requestId) {
        XmlWriter xml = new XmlWriter();
        String resultTag = object.getClass().getSimpleName();
        // 响应标签名
        String responseTag = resultTag.replace("Result", "Response");
        // response开始
        xml.start(responseTag);
        // result开始
        xml.start(resultTag);
        // 遍历成员变量
        addField(xml, object);
        // result结束
        xml.end();
        // ResponseMetadata
        addResponseMetadata(xml, requestId);
        // response结束
        xml.end();
        return xml.toString();
    }
    
    /**
     * 返回requestId信息
     * 当方法返回值为空时，使用该方法进行返回
     * @param methodName
     * @param requestId
     * @return
     */
    public static String toXml(String methodName, String requestId) {
        XmlWriter xml = new XmlWriter();
        // 响应标签名
        String responseTag = IAMStringUtils.firstCharUpperCase(methodName) + "Response";
        // response开始
        xml.start(responseTag);
        // ResponseMetadata
        addResponseMetadata(xml, requestId);
        // response结束
        xml.end();
        return xml.toString();
    }
    
    private static void addResponseMetadata(XmlWriter xml, String requestId) {
        xml.start("ResponseMetadata");
        xml.start("RequestId").value(requestId).end();
        xml.end();
    }
    
    private static void addField(XmlWriter xml, Object object) {
        for (Field field : object.getClass().getFields()) {
            try {
                // 获取修饰符只为public的成员变量
                if (field.getModifiers() != 1) continue;
                // 值为null不返回
                Object fieldObject = field.get(object);
                if (fieldObject == null) continue;
                // 首字母转大写
                String tagName = IAMStringUtils.firstCharUpperCase(field.getName());
                xml.start(tagName);
                if (isBaseDataType(field.getType())) {
                    // 基本类型及封装类型处理
                    if (field.isAnnotationPresent(DateFormat.class)) {
                        // 将long转换为时间格式
                        xml.value(DateUtils.format((long) fieldObject));
                    } else {
                        // 基本类型和String写入value
                        xml.value(fieldObject.toString());
                    }
                } else if (List.class.isAssignableFrom(field.getType())) {
                    // List数据处理
                    List<?> list = (List<?>)fieldObject;
                    // list操作
                    for (Object obj : list) {
                        xml.start("member");
                        addField(xml, obj);
                        xml.end();
                    }
                } else if (Map.class.isAssignableFrom(field.getType())) {
                    // Map数据处理
                    Map<?, ?> map = (Map<?, ?>)fieldObject;
                    for (Entry<?, ?> entry : map.entrySet()) {
                        xml.start("entry");
                        xml.start("key");
                        String key = entry.getKey() == null ? "" : entry.getKey().toString();
                        xml.value(key);
                        xml.end();
                        xml.start("value");
                        String value = entry.getValue() == null ? "" : entry.getValue().toString();
                        xml.value(value);
                        xml.end();
                        xml.end();
                    }
                } else {
                    addField(xml, fieldObject);
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            xml.end();
        }
    }
    
    /**  
     * 判断一个类是否为基本数据类型。  
     * @param clazz 要判断的类。  
     * @return true 表示为基本数据类型。  
     */ 
    private static boolean isBaseDataType(Class<?> clazz)  throws Exception  {   
        return 
        (   
            clazz.equals(String.class) ||   
            clazz.equals(Integer.class)||   
            clazz.equals(Boolean.class) ||   
            clazz.equals(Byte.class) ||   
            clazz.equals(Long.class) ||   
            clazz.equals(Double.class) ||   
            clazz.equals(Float.class) ||   
            clazz.equals(Character.class) ||   
            clazz.equals(Short.class) ||   
            clazz.equals(BigDecimal.class) ||   
            clazz.equals(BigInteger.class) ||   
            clazz.isPrimitive()   
        );   
    }
    
}
