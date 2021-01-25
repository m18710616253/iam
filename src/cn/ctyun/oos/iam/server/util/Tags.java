package cn.ctyun.oos.iam.server.util;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.lang3.StringUtils;

import cn.ctyun.common.BaseException;
import cn.ctyun.oos.iam.accesscontroller.util.IAMErrorMessage;
import cn.ctyun.oos.iam.server.entity.Tag;

/**
 * 用户标签解析工具
 * @author wangduo
 *
 */
public class Tags {

    /** 用户最大标签数 */
    public static final int TAGS_LIMIT_SIZE = 10;
    
    /**
     * 解析请求参数中的用户标签相关信息
     * @param params
     * @param messages 错误消息
     * @return
     * @throws BaseException 
     */
    public static List<Tag> parse(Map<String, String> params, List<IAMErrorMessage> messages) throws BaseException {
        Map<String, Tag> tagMap = new LinkedHashMap<>();
        // tag参数中最大的index
        int maxIndex = 0;
        for (Entry<String, String> entry : params.entrySet()) {
            if (entry.getKey().startsWith("Tags.member")) {
                String[] strs = entry.getKey().split("\\.");
                // 拆分后长度不为4，忽略，不做处理
                if (strs.length != 4) continue;
                // 获取参数的index
                String indexStr = strs[2];
                // 忽略非数字
                if (!StringUtils.isNumeric(indexStr))  continue;
                int index = Integer.parseInt(indexStr);
                if (index <= 0 || index > TAGS_LIMIT_SIZE) {
                    throw new BaseException(400, "MalformedInput", index+" is not a valid index.");
                }
                maxIndex = Math.max(maxIndex, index);
                
                Tag tag = tagMap.get(indexStr);
                if (tag == null) {
                    tag = new Tag();
                    tagMap.put(indexStr, tag);
                }
                if ("Key".equals(strs[3])) {
                    tag.key = entry.getValue();
                }
                if ("Value".equals(strs[3])) {
                    tag.value = entry.getValue();
                }
            }
        }
        
        List<Tag> tags = new LinkedList<>();
        // 校验index的连续及tag的key、value
        for (int i = 1; i <= maxIndex; i++) {
            Tag tag = tagMap.get(String.valueOf(i));
            if (tag == null || tag.key == null) {
                IAMErrorMessage errorMessage = new IAMErrorMessage("tagKeyNull", 
                        "Value null at 'tags." + i + ".member.key' failed to satisfy constraint: Member must not be null");
                messages.add(errorMessage);
            } else {
                // 验证tag的key
                ValidationUtils.validateTagKey(tag.key, i, messages);
            }
            if (tag == null || tag.value == null) {
                IAMErrorMessage errorMessage = new IAMErrorMessage("tagValueNull", 
                        "Value null at 'tags." + i + ".member.value' failed to satisfy constraint: Member must not be null");
                messages.add(errorMessage);
            } else {
                // 验证tag的value
                ValidationUtils.validateTagValue(tag.value, i, messages);
            }
            tags.add(tag);
        }
        return tags;
    }
    
    
    /**
     * 解析请求参数中的用户标签KEY
     * TagKeys.member.1=test_key1&TagKeys.member.2=tag_key2
     * @param params
     * @param messages 错误消息
     * @return
     * @throws BaseException 
     */
    public static List<String> parseKey(Map<String, String> params, List<IAMErrorMessage> messages) throws BaseException {
        Map<String, String> tagKeyMap = new LinkedHashMap<>();
        // tag参数中最大的index
        int maxIndex = 0;
        for (Entry<String, String> entry : params.entrySet()) {
            if (entry.getKey().startsWith("TagKeys.member")) {
                String[] strs = entry.getKey().split("\\.");
                // 拆分后长度不为3，忽略，不做处理
                if (strs.length != 3) continue;
                // 获取参数的index
                String indexStr = strs[2];
                // 忽略非数字
                if (!StringUtils.isNumeric(indexStr))  continue;
                int index = Integer.parseInt(indexStr);
                if (index <= 0 || index > TAGS_LIMIT_SIZE) {
                    throw new BaseException(400, "MalformedInput", index+" is not a valid index.");
                }
                maxIndex = Math.max(maxIndex, index);
                // 标签key
                tagKeyMap.put(indexStr, entry.getValue());
            }
        }
        // 校验index的连续及tag的key、value
        for (int i = 1; i <= maxIndex; i++) {
            String tagKey = tagKeyMap.get(String.valueOf(i));
            if (tagKey == null) {
                IAMErrorMessage errorMessage = new IAMErrorMessage("tagKeyNull", 
                        "Value null at 'tags." + i + ".member.key' failed to satisfy constraint: Member must not be null");
                messages.add(errorMessage);
            } else {
                // 验证tag的key
                ValidationUtils.validateTagKey(tagKey, i, messages);
            }
        }
        List<String> tagKeys = new ArrayList<>(tagKeyMap.values());
        return tagKeys;
    }
}
