package cn.ctyun.oos.iam.server.util;

import java.util.List;

import org.apache.hadoop.hbase.util.Bytes;

import cn.ctyun.oos.iam.server.hbase.HBaseEntity;
import cn.ctyun.oos.iam.server.result.PageResult;

/**
 * 分页工具
 * @author wangduo
 *
 */
public class PageUtils {

    /**
     * 对HBaseEntity列表进行分页
     * @param entities
     * @param marker
     * @param maxItems
     * @param isFromProxy
     * @return
     */
    public static <T extends HBaseEntity> PageResult<T> toPageResult(List<T> entities, String marker, Integer maxItems, boolean isFromProxy) {
        if (maxItems == null) {
            maxItems = 100;
        }
        PageResult<T> result = new PageResult<>();
        // 分页开始索引
        int fromIndex = 0;
        if (marker != null) {
            for (int i = 0; i < entities.size(); i++) {
                HBaseEntity data = entities.get(i);
                if (marker.equals(Bytes.toString(data.getRowKey()))) {
                    fromIndex = i;
                }
            }
        }
        // 分页结束索引
        int toIndex = fromIndex + maxItems;
        if (toIndex >= entities.size()) {
            // 无后续分页
            result.list = entities.subList(fromIndex, entities.size());
        } else {
            // 有后续分页
            result.list = entities.subList(fromIndex, toIndex);
            result.isTruncated = true;
            result.marker = Bytes.toString(entities.get(toIndex).getRowKey());
        }
        // 当marker为空，并且请求来自于proxy时获取数据总数
        boolean getTotal = marker == null && isFromProxy;
        if (getTotal) {
            result.total = (long) entities.size();
        }
        return result;
    }
}
