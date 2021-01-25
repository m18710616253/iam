package cn.ctyun.oos.utils;

import java.io.IOException;

import org.apache.hadoop.hbase.HColumnDescriptor;
import org.apache.hadoop.hbase.HTableDescriptor;
import org.apache.hadoop.hbase.KeepDeletedCells;
import org.apache.hadoop.hbase.TableName;
import org.apache.hadoop.hbase.client.HBaseAdmin;
import org.apache.hadoop.hbase.client.HConnection;
import org.apache.hadoop.hbase.client.HConnectionManager;
import org.apache.hadoop.hbase.client.HTableInterface;
import org.apache.hadoop.hbase.client.Put;
import org.apache.hadoop.hbase.util.Bytes;

import cn.ctyun.common.conf.GlobalHHZConfig;
import cn.ctyun.oos.hbase.HBaseUtil;

public class HbaseUtils {
    
    public static void main(String[] args) {
//        createTable("ostor-object-xiao", "fy");
        TruncateTable("oos-owner-yx");
        TruncateTable("oos-aksk-yx");
        TruncateTable("oos-bucket-yx");
        TruncateTable("oos-objects-yx");
        TruncateTable("oos-objectsMeta-yx");
        TruncateTable("oos-objectsMD5-yx");
        TruncateTable("oos-initialUpload-yx");
        TruncateTable("oos-initialUploadMeta-yx");
        TruncateTable("oos-initialUploadMD5-yx");
        TruncateTable("oos-upload-yx");
        TruncateTable("ostor-object-xiao");
        
    }

    public static void dropTable(String tableName)  {
        HBaseAdmin hbaseAdmin = null;
        try {
            hbaseAdmin=new HBaseAdmin(GlobalHHZConfig.getConfig());
            if (!hbaseAdmin.tableExists(tableName))
                return;
            hbaseAdmin.disableTable(tableName);
            hbaseAdmin.deleteTable(tableName);
        }  catch (Exception e) {
            e.printStackTrace();
        }finally {
            if (hbaseAdmin != null) {
                try {
                    hbaseAdmin.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
    
    public static void TruncateTable(String tableName) {
        HBaseAdmin hbaseAdmin=null;
        try {
            hbaseAdmin=new HBaseAdmin(GlobalHHZConfig.getConfig());
            hbaseAdmin.disableTable(tableName);
            hbaseAdmin.truncateTable(TableName.valueOf(tableName), true);
        } catch (Exception e) {
            e.printStackTrace();
        }finally {
            if (hbaseAdmin != null) {
                try {
                    hbaseAdmin.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
    
    public static void createTable(String tableName,String familyName){
        HTableDescriptor desc = new HTableDescriptor(TableName.valueOf(tableName));
        HColumnDescriptor fyDesc = new HColumnDescriptor(Bytes.toBytes(familyName));
        desc.setCompactionEnabled(true);
//        fyDesc.setCompressionType(Algorithm.LZO);
        fyDesc.setKeepDeletedCells(KeepDeletedCells.FALSE);
        fyDesc.setMaxVersions(1);
        desc.addFamily(fyDesc);
        
        HBaseAdmin hbaseAdmin=null;
        try {
            hbaseAdmin=new HBaseAdmin(GlobalHHZConfig.getConfig());
            hbaseAdmin.createTable(desc);
        } catch (Exception e) {
            e.printStackTrace();
        }finally {
            if (hbaseAdmin != null) {
                try {
                    hbaseAdmin.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
    
    /*
     * 设置value
     */
    public static void setValueString(String tableName,String rowkey,String familyName,String columnName,String v) {
        HConnection connection=null;
        try {
            connection = HConnectionManager
                    .createConnection(GlobalHHZConfig.getConfig());
            HTableInterface htable = connection.getTable(tableName);
            Put put = new Put(rowkey.getBytes());
            put.add(familyName.getBytes(), columnName.getBytes(), Bytes.toBytes(v)); 
            HBaseUtil.put(htable, put);
        } catch (IOException e) {
            throw new RuntimeException("Create connection to hbase failed.", e);
        }finally {
            if (connection!=null) {
                try {
                    connection.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
    
    /*
     * 删除前缀为XXX的row记录
     */
    public void Delete() {
        
    }
    
}
