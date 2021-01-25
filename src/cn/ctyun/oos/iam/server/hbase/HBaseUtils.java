package cn.ctyun.oos.iam.server.hbase;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.hbase.Cell;
import org.apache.hadoop.hbase.CellUtil;
import org.apache.hadoop.hbase.HColumnDescriptor;
import org.apache.hadoop.hbase.HTableDescriptor;
import org.apache.hadoop.hbase.KeepDeletedCells;
import org.apache.hadoop.hbase.TableExistsException;
import org.apache.hadoop.hbase.TableName;
import org.apache.hadoop.hbase.client.Delete;
import org.apache.hadoop.hbase.client.Get;
import org.apache.hadoop.hbase.client.HBaseAdmin;
import org.apache.hadoop.hbase.client.HConnection;
import org.apache.hadoop.hbase.client.HTableInterface;
import org.apache.hadoop.hbase.client.Put;
import org.apache.hadoop.hbase.client.Result;
import org.apache.hadoop.hbase.client.ResultScanner;
import org.apache.hadoop.hbase.client.Scan;
import org.apache.hadoop.hbase.client.coprocessor.AggregationClient;
import org.apache.hadoop.hbase.client.coprocessor.LongColumnInterpreter;
import org.apache.hadoop.hbase.io.compress.Compression.Algorithm;
import org.apache.hadoop.hbase.util.Bytes;

import com.fasterxml.jackson.core.JsonProcessingException;

import cn.ctyun.common.conf.GlobalHHZConfig;
import cn.ctyun.oos.hbase.HBaseConnectionManager;
import cn.ctyun.oos.hbase.HBaseIamChangeEvent;
import cn.ctyun.oos.iam.server.result.PageResult;
import cn.ctyun.oos.iam.server.util.JSONUtils;
import cn.ctyun.oos.iam.server.util.ReflectionUtils;

/**
 * HBASE工具
 * 
 * @author wangduo
 *
 */
public class HBaseUtils {

    private static final Log log = LogFactory.getLog(HBaseUtils.class);
    
    private static final String COPROCESS_CLASS_NAME = "org.apache.hadoop.hbase.coprocessor.AggregateImplementation";
    
    static {
        try {
            connection = HBaseConnectionManager.createConnection(GlobalHHZConfig.getConfig());
        } catch (IOException e) {
            throw new RuntimeException("Create global connection to hbase failed.", e);
        }
    }
    
    private static HConnection connection;
    
    public static HTableInterface getTable(String tableName) throws IOException {
        return connection.getTable(tableName);
    }
    
    /**
     * 创建表
     * @param tableName
     * @param familyNames
     * 
     * @throws IOException
     */
    @SuppressWarnings("resource")
    public static void createTable(HBaseTable hbaseTable) throws IOException {
        
        // 此处不需要关闭
        HBaseAdmin hbaseAdmin = new HBaseAdmin(connection);
        HTableDescriptor tableDesc = new HTableDescriptor(TableName.valueOf(hbaseTable.name()));
        // 添加聚合函数功能
        tableDesc.addCoprocessor(COPROCESS_CLASS_NAME);
        for (String familyName : hbaseTable.columnFamilies()) {
            HColumnDescriptor familyDesc = new HColumnDescriptor(Bytes.toBytes(familyName));
            tableDesc.setCompactionEnabled(true);
            familyDesc.setCompressionType(Algorithm.LZO);
            familyDesc.setKeepDeletedCells(KeepDeletedCells.FALSE);
            familyDesc.setMaxVersions(hbaseTable.maxVersions());
            if (hbaseTable.timeToLive() > 0) {
                familyDesc.setTimeToLive(hbaseTable.timeToLive());
            }
            tableDesc.addFamily(familyDesc);
        }
        try {
            hbaseAdmin.createTable(tableDesc);
            log.info("create table: " + hbaseTable.name() + ", family: " + hbaseTable.columnFamilies() + " success.");
        } catch (TableExistsException e) {
            log.info("create table, table: " + hbaseTable.name() + " already exists.");
        }
    }
    
    public static void createTables() throws IOException {
        HBaseAdmin hbaseAdmin = new HBaseAdmin(connection);
        HBaseIamChangeEvent.createTable(hbaseAdmin);
    }
    
    /**
     * 删除表
     * 测试使用
     * @param tableName
     * @throws IOException
     */
    @SuppressWarnings("resource")
    public static void dropTable(String tableName) throws IOException {
        HBaseAdmin hbaseAdmin = new HBaseAdmin(connection);
        hbaseAdmin.disableTable(tableName);
        hbaseAdmin.deleteTable(tableName);
    }
    
    /**
     * PUT数据
     * @param entity
     * @throws IOException 
     */
    public static void put(HBaseEntity entity) throws IOException {
        HTableInterface table = getTable(entity);
        Put put = getPut(entity);
        try {
            table.put(put);
        } finally {
            table.close();
        }
    }
    
    /**
     * 如果实体对应的rowKey不存在，创建数据
     * @param entity
     * @return 是否成功创建hh
     * @throws IOException 
     * 
     */
    public static boolean checkAndCreate(HBaseEntity entity) throws IOException {
        HTableInterface table = getTable(entity);
        entity.deleted = false;
        Put put = getPut(entity);
        try {
            return table.checkAndPut(entity.getRowKey(), Bytes.toBytes(Qualifier.DEFAULT_FAMILY), 
                    Bytes.toBytes(HBaseEntity.QUALIFIER_DELETED), null, put);
        } finally {
            table.close();
        }
    }
    
    /**
     * 如果实体对应的rowKey存在，删除数据
     * @param entity
     * @return 是否删除了数据
     * @throws IOException 
     */
    public static boolean checkAndDelete(HBaseEntity entity) throws IOException {
        HTableInterface table = getTable(entity);
        try {
            Delete delete = new Delete(entity.getRowKey());
            return table.checkAndDelete(entity.getRowKey(), Bytes.toBytes(Qualifier.DEFAULT_FAMILY), 
                    Bytes.toBytes(HBaseEntity.QUALIFIER_DELETED), Bytes.toBytes(false), delete);
        } finally {
            table.close();
        }
    }
    
    /**
     * 实体的原子更新
     * @param entity 实体
     * @param family 列族
     * @param qualifier 列
     * @param value 期望的目前数据的值
     * @return 是否执行成功
     * @throws IOException 
     */
    public static boolean checkAndPut(HBaseEntity entity, byte[] family, byte[] qualifier, byte[] value) throws IOException {
        HTableInterface table = getTable(entity);
        Put put = getPut(entity);
        try {
            return table.checkAndPut(entity.getRowKey(), family, qualifier, value, put);
        } finally {
            table.close();
        }
    }
    
    /**
     * 对实体的需要原子加的值进行更新
     * @param entity
     * @param family
     * @param qualifier
     * @param value
     * @return
     * @throws IOException
     */
    public static long incrementColumnValue(HBaseEntity entity, byte[] family, byte[] qualifier, long value) throws IOException {
        HTableInterface table = getTable(entity);
        try {
            return table.incrementColumnValue(entity.getRowKey(), family, qualifier, value);
        } finally {
            table.close();
        }
    }
    
    /**
     * 对实体的需要原子加的值进行更新
     * @param entity
     * @param qualifier
     * @param value
     * @return
     * @throws IOException
     */
    public static long incrementColumnValue(HBaseEntity entity, byte[] qualifier, long value) throws IOException {
        HTableInterface table = getTable(entity);
        try {
            return table.incrementColumnValue(entity.getRowKey(), Bytes.toBytes(Qualifier.DEFAULT_FAMILY), qualifier, value);
        } finally {
            table.close();
        }
    }
    
    /**
     * 获取实体的put对象
     * @param entity
     * @return
     */
    private static Put getPut(HBaseEntity entity) {
        Put put = new Put(entity.getRowKey());
        // FIXME 反射结果缓存 考虑效率性能问题 
        for (Field field : entity.getClass().getFields()) {
            field.setAccessible(true);
            // 列处理
            Qualifier qualifier = field.getAnnotation(Qualifier.class);
            if (qualifier == null) {
                continue;
            }
            putQualifier(entity, field, qualifier, put);
        }
        return put;
    }
    /**
     * 读取entity的field值，向put中添加Qualifier数据
     * @param entity
     * @param field
     * @param qualifier
     * @param put
     */
    private static void putQualifier(HBaseEntity entity, Field field, Qualifier qualifier, Put put) {
        // 获取列名
        String qualifierName = getQualifierName(field, qualifier);
        Object value =getFieldValue(entity, field);
        // 空值不做处理
        if (value == null) return;
        put.add(Bytes.toBytes(qualifier.columnFamily()), Bytes.toBytes(qualifierName), toBytes(value));
    }
    
    private static Object getFieldValue(HBaseEntity entity, Field field) {
        try {
            return field.get(entity);
        } catch (IllegalAccessException e) {
            throw new RuntimeException("Class [" + entity.getClass().getName() +  "] field [" + field.getName() + "] reflect failed", e);
        }
    }
    
    private static String getQualifierName(Field field, Qualifier qualifier) {
        return "".equals(qualifier.name()) ? field.getName() : qualifier.name();
    }
    
    /**
     * 判断entity的rowkey是否存在数据
     * @param entity
     * @return
     * @throws IOException 
     */
    @SuppressWarnings("unchecked")
    public static <T extends HBaseEntity> T get(T entity) throws IOException {
        HTableInterface table = getTable(entity);
        try {
            Get get = new Get(entity.getRowKey());
            Result hbaseResult = table.get(get);
            if (hbaseResult.isEmpty()) {
                return null;
            }
            return (T) convertResultToEntity(hbaseResult, entity.getClass());
        } finally {
            table.close();
        }
    }
    
    /**
     * 通过rowkey批量获取数据
     * @param rowKeys
     * @param clazz
     * @return
     * @throws IOException 
     */
    public static <T extends HBaseEntity> List<T> get(List<byte[]> rowKeys, Class<T> clazz) throws IOException {
        HTableInterface table = getTable(clazz);
        List<Get> gets = new ArrayList<>();
        for (byte[] rowKey : rowKeys) {
            Get get = new Get(rowKey);
            gets.add(get);
        }
        try {
            Result[] results = table.get(gets);
            if (results == null || results.length == 0) {
                return Collections.emptyList();
            }
            List<T> entities = new ArrayList<>();
            for (Result result : results) {
                if (result.isEmpty()) {
                    continue;
                }
                T entity = convertResultToEntity(result, clazz);
                entities.add(entity);
            }
            return entities;
        } finally {
            table.close();
        }
    }
    
    /**
     * 批量获取多行数据指定列的值
     * @param rowKeys
     * @param clazz
     * @param family
     * @param qualifier
     * @return map  key: rowKey, value: 指定的列的值
     * @throws IOException
     */
    public static <T extends HBaseEntity> Map<String, String> get(List<byte[]> rowKeys, Class<T> clazz, byte[] family, byte[] qualifier) throws IOException {
        HTableInterface table = getTable(clazz);
        List<Get> gets = new ArrayList<>();
        for (byte[] rowKey : rowKeys) {
            Get get = new Get(rowKey);
            get.addColumn(family, qualifier);
            gets.add(get);
        }
        try {
            Result[] results = table.get(gets);
            if (results == null || results.length == 0) {
                return Collections.emptyMap();
            }
            Map<String, String> map = new HashMap<>();
            for (Result result : results) {
                if (result.isEmpty()) {
                    continue;
                }
                map.put(Bytes.toString(result.getRow()), Bytes.toString(result.getValue(family, qualifier)));
            }
            return map;
        } finally {
            table.close();
        }
    }

    /**
     * 获取指定表中单行指定列的数据
     * @param <T>
     * @param rowKey
     * @param clazz
     * @param family
     * @param qualifier
     * @return
     * @throws IOException
     */
    public static <T extends HBaseEntity> byte[] get(byte[] rowKey, Class<T> clazz, byte[] family, byte[] qualifier) throws IOException {
        HTableInterface table = getTable(clazz);
        Get get = new Get(rowKey);
        get.addColumn(family, qualifier);
        try {
            Result result = table.get(get);
            if (result == null ) {
                return null;
            }
            return result.getValue(family, qualifier);
        } finally {
            table.close();
        }
    }
    
    
    /**
     * 分页查询
     * @param scan
     * @param maxItems 返回数据条数
     * @param clazz
     * @param getTotal 是否返回分页信息，包括数据总数以及分页的marker列表
     * @return
     * @throws Throwable 
     */
    public static <T extends HBaseEntity> PageResult<T> scan(Scan scan, Integer maxItems, Class<T> clazz, boolean getTotal) throws Throwable {
        HTableInterface table = getTable(clazz);
        // 默认查询100条数据
        if (maxItems == null) {
            maxItems = 100;
        }
        scan.setCaching(maxItems);
        ResultScanner scanner = table.getScanner(scan);
        try {
            List<T> list = new ArrayList<>();
            Iterator<Result> results = scanner.iterator();
            Result result = null;
            int num = 0;
            while(results.hasNext() && num++ < maxItems) {
                result = results.next();
                T t = convertResultToEntity(result, clazz);
                list.add(t);
            }
            // 创建分页返回结果
            PageResult<T> pageResult = new PageResult<>();
            pageResult.list = list;
            pageResult.isTruncated = results.hasNext();
            // 设置marker
            if (results.hasNext() && result != null) {
                pageResult.marker = Bytes.toString(result.getRow());
            }
            // 如果需要获取总数
            if (getTotal) {
                if (pageResult.isTruncated) {
                    // 设置分页信息
                    pageResult.total = rowCount(table, scan);
                } else {
                    pageResult.total = (long) list.size();
                }
            }
            return pageResult;
        } finally {
            scanner.close();
            table.close();
        }
    }
    
    /**
     * 获取符合条件的所有rowkey
     * @param scan
     * @param clazz
     * @return
     * @throws IOException
     */
    public static <T extends HBaseEntity> List<T> listResult(Scan scan, Class<T> clazz) throws IOException {
        HTableInterface table = getTable(clazz);
        scan.setCaching(10);
        ResultScanner scanner = table.getScanner(scan);
        try {
            List<T> list = new ArrayList<>();
            Iterator<Result> results = scanner.iterator();
            while(results.hasNext()) {
                Result result = results.next();
                T t = convertResultToEntity(result, clazz);
                list.add(t);
            }
            return list;
        } finally {
            scanner.close();
            table.close();
        }
    }
    
    /**
     * 
     * @param scan
     * @param maxItems
     * @param clazz
     * @return
     * @throws Throwable 
     */
    public static <T extends HBaseEntity> PageResult<T> scan(Scan scan, Integer maxItems, Class<T> clazz) throws Throwable {
        return scan(scan, maxItems, clazz, false);
    }
    
    /**
     * 获取查询条件下的总数
     * @param table
     * @param scan
     * @throws Throwable 
     */
    private static long rowCount(HTableInterface table, Scan scan) throws Throwable {
        AggregationClient aggClient = new AggregationClient(GlobalHHZConfig.getConfig());
        return aggClient.rowCount(table.getName(), new LongColumnInterpreter(), scan);
    }
    
    /**
     * 将hbase返回结果转换为实体对象
     * @param result
     * @param clazz
     * @return
     */
    public static <T extends HBaseEntity> T convertResultToEntity(Result result, Class<T> clazz) {
        T entity;
        try {
            entity = clazz.newInstance();
        } catch (InstantiationException | IllegalAccessException e) {
            throw new RuntimeException("Class [" + clazz.getName() + "] newInstance failed.", e);
        }
        entity.parseRowKey(result.getRow());
        for (Field field : clazz.getFields()) {
            field.setAccessible(true);
            Qualifier qualifier = field.getAnnotation(Qualifier.class);
            if (qualifier == null) {
                continue;
            }
            setQualifier(result, entity, field, qualifier);
        }
        return entity;
    }
    
    /**
     * 设置列的值到指定成员变量
     * @param result
     * @param entity
     * @param field
     * @param qualifier
     */
    private static void setQualifier(Result result, Object entity, Field field, Qualifier qualifier) {
        // 获取列名
        String qualifierName = "".equals(qualifier.name()) ? field.getName() : qualifier.name();
        // 获取列值
        byte[] bytes = result.getValue(Bytes.toBytes(qualifier.columnFamily()), Bytes.toBytes(qualifierName));
        // 空值不做处理
        if (bytes == null || bytes.length == 0) return;
        set(entity, field, bytes);
    }
    
    /**
     * 判断entity的rowkey是否存在数据
     * @param entity
     * @return
     * @throws IOException 
     */
    public static boolean exist(HBaseEntity entity) throws IOException {
        HTableInterface table = getTable(entity);
        try {
            Get get = new Get(entity.getRowKey());
            return table.exists(get);
        } finally {
            table.close();
        }
    }
    
    /**
     * 删除数据
     * @param entity
     * @throws IOException 
     */
    public static void delete(HBaseEntity entity) throws IOException {
        HTableInterface table = getTable(entity);
        try {
            Delete delete = new Delete(entity.getRowKey());
            table.delete(delete);
        } finally {
            table.close();
        }
    }
    
    /**
     * 构建一个通用的Scan
     * 该scan使用默认的列族以及默认的path列名
     * 如果有列族列名不一致的情况，可以自行创建scan
     * 
     * @param rowPrefix key前缀
     * @param marker 起始key
     * @return
     */
    public static Scan buildScan(String rowPrefix, String marker) {
        Scan scan = new Scan();
        // marker为空或者小于rowPrefix，使用rowPrefix
        marker = (StringUtils.isBlank(marker) || marker.compareTo(rowPrefix) < 0) ? rowPrefix : marker;
        scan.setStartRow(Bytes.toBytes(marker + Character.MIN_VALUE));
        scan.setStopRow(Bytes.toBytes(rowPrefix + Character.MAX_VALUE));
        // 只查info列族
        scan.addFamily(Bytes.toBytes(Qualifier.DEFAULT_FAMILY));
        return scan;
    }
    
    public static HTableInterface getTable(HBaseEntity entity) throws IOException {
        return getTable(entity.getClass());
    }
    
    public static HTableInterface getTable(Class<?> clazz) throws IOException {
        HBaseTable hbaseTable = clazz.getAnnotation(HBaseTable.class);
        if (hbaseTable == null) {
            throw new RuntimeException("The class [" + clazz.getName() +  "] must have annotation @HBaseTable");
        }
        // 如果指定了当前类归属的实体类，使用归属的类
        if (!HBaseEntity.class.equals(hbaseTable.entityClass())) {
            HBaseTable entityHbaseTable = hbaseTable.entityClass().getAnnotation(HBaseTable.class);
            if (entityHbaseTable == null) {
                throw new RuntimeException("The class [" + hbaseTable.entityClass().getName() +  "] must have annotation @HBaseTable");
            }
            hbaseTable = entityHbaseTable;
        }
        return getTable(hbaseTable.name());
    }
    
    /**
     * 将基本类型、String、List转换为bytes
     * List先转换为JsonArray
     * @param object
     * @return
     */
    private static byte[] toBytes(Object object) {
        if (object instanceof String) {
            return Bytes.toBytes((String)object);
        }
        if (object instanceof Integer) {
            return Bytes.toBytes((Integer)object);
        }
        if (object instanceof Boolean) {
            return Bytes.toBytes((Boolean)object);
        }
        if (object instanceof Short) {
            return Bytes.toBytes((Short)object);
        }
        if (object instanceof Long) {
            return Bytes.toBytes((Long)object);
        }
        if (object instanceof Float) {
            return Bytes.toBytes((Float)object);
        }
        if (object instanceof Double) {
            return Bytes.toBytes((Double)object);
        }
        // List转jsonArray
        if (object instanceof List) {
            String jsonArray;
            try {
                jsonArray = JSONUtils.toJSONArray((List<?>)object);
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
            return Bytes.toBytes(jsonArray.toString());
        }
        throw new RuntimeException(object.getClass().getSimpleName() + " cannot convert to bytes");
    }
    
    /**
     * 将bytes转换为字段对应的类型，设置到对象的指定字段中
     * @param obj
     * @param field
     * @param bytes
     */
    private static void set(Object obj, Field field, byte[] bytes) {
        try {
            if (field.getType() == String.class) {
                field.set(obj, Bytes.toString(bytes));
                return;
            }
            if (field.getType() == Integer.class) {
                field.set(obj, Bytes.toInt(bytes));
                return;
            }
            if (field.getType() == Short.class) {
                field.set(obj, Bytes.toShort(bytes));
                return;
            }
            if (field.getType() == Long.class) {
                field.set(obj, Bytes.toLong(bytes));
                return;
            }
            if (field.getType() == Float.class) {
                field.set(obj, Bytes.toFloat(bytes));
                return;
            }
            if (field.getType() == Double.class) {
                field.set(obj, Bytes.toDouble(bytes));
                return;
            }
            if (field.getType() == Boolean.class) {
                field.set(obj, Bytes.toBoolean(bytes));
                return;
            }
            //  jsonArray转list
            if (field.getType() == List.class) {
                String str = Bytes.toString(bytes);
                List<?> list = JSONUtils.toList(str, ReflectionUtils.getGenericClass(field));
                field.set(obj, list);
                return;
            }
        } catch (IllegalAccessException | IOException e) {
            throw new RuntimeException("set class [" + obj.getClass().getName() + "] field [" + field.getName() + "] failed.", e);
        }
        throw new RuntimeException("set class [" + obj.getClass().getName() + "] field [" + field.getName() + "] failed, " + field.getType() + " cannot convert from bytes");
    }
    
	/**
	 * 获取某一行中一列的多版本数据
	 * 
	 * @param entity
	 * @param family
	 * @param qualifier
	 * @param get
	 * @return
	 * @throws IOException
	 */
	public static <T extends HBaseEntity> List<Long> getVersions(T entity, byte[] family, byte[] qualifier, Get get)
			throws IOException {
		HTableInterface table = getTable(entity);
		List<Long> list = new ArrayList<Long>();
		try {
			get.addColumn(family, qualifier);
			Result result = table.get(get);
			if (result == null || result.isEmpty()) {
				return null;
			}
			Cell[] cells = result.rawCells();
			for (Cell cell : cells) {
				list.add(Bytes.toLong(CellUtil.cloneValue(cell)));
			}
			return list;
		} finally {
			table.close();
		}
	}
}
