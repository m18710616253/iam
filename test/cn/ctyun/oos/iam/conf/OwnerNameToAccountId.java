package cn.ctyun.oos.iam.conf;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import cn.ctyun.oos.iam.server.util.DateUtils;
import cn.ctyun.oos.metadata.OwnerMeta;

/**
 * 通过ownerName 计算 accountId
 */
public class OwnerNameToAccountId {

    public static void main(String[] args) {
        
        List<String> accountIdList = new ArrayList<>();
        for (String arg : args) {
            OwnerMeta ownerMeta = new OwnerMeta(arg);
            accountIdList.add(ownerMeta.getAccountId());
        }
        System.out.println(StringUtils.join(accountIdList, ","));
    }
}
