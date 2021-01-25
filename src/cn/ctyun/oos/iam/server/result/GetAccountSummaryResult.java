package cn.ctyun.oos.iam.server.result;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.LinkedHashMap;
import java.util.Map;

import cn.ctyun.oos.iam.accesscontroller.util.IAMStringUtils;
import cn.ctyun.oos.iam.server.entity.AccountSummary;

/**
 * 获取IAM的实体使用和配额信息返回结果
 * @author wangduo
 *
 */
public class GetAccountSummaryResult extends Result {

    public Map<String, Object> summaryMap = new LinkedHashMap<>();
    
    public GetAccountSummaryResult(AccountSummary accountSummary) {
        
        for (Field field : AccountSummary.class.getDeclaredFields()) {
            field.setAccessible(true);
            String fieldName = field.getName();
            if (Modifier.isStatic(field.getModifiers()) || AccountSummary.ACCOUNT_ID.equals(fieldName)) {
                continue;
            }
            String key = IAMStringUtils.firstCharUpperCase(fieldName);
            try {
                Object value = field.get(accountSummary);
                if (value != null) {
                    summaryMap.put(key, value);
                }
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        }
        
    }
}
