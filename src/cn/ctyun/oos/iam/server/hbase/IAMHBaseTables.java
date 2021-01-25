package cn.ctyun.oos.iam.server.hbase;

import java.io.IOException;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import cn.ctyun.oos.iam.server.util.ClasspathPackageScanner;

/**
 * 用户扫描实体类，使用实体的HBaseTable注解获取表信息，对表进行创建
 * @author wangduo
 *
 */
public class IAMHBaseTables {

    private static final Log log = LogFactory.getLog(IAMHBaseTables.class);
    
    public static void createTables() throws IOException {
        // 获取指定包下的HBaseTable注解的类
        ClasspathPackageScanner packageScanner = new ClasspathPackageScanner(IAMHBaseTables.class.getClassLoader());
        List<Class<?>> tableClasses = packageScanner.getClasses("cn.ctyun.oos.iam.server.entity", HBaseTable.class);
        
        for (Class<?> clazz : tableClasses) {
            HBaseTable hbaseTable = clazz.getAnnotation(HBaseTable.class);
            // 没有表名不做处理
            if (StringUtils.isEmpty(hbaseTable.name())) {
                continue;
            }
            try {
                HBaseUtils.createTable(hbaseTable);
            } catch (IOException e) {
                log.error("create hbase tables failed.", e);
                throw e;
            }
        }
        HBaseUtils.createTables();
    }
}
