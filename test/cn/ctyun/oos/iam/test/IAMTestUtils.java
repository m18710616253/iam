package cn.ctyun.oos.iam.test;

import java.io.IOException;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.io.IOUtils;
import org.apache.hadoop.hbase.TableName;
import org.apache.hadoop.hbase.client.Delete;
import org.apache.hadoop.hbase.client.HBaseAdmin;
import org.apache.hadoop.hbase.client.HConnection;
import org.apache.hadoop.hbase.client.HTableInterface;
import org.apache.hadoop.hbase.client.Put;
import org.apache.hadoop.hbase.client.Result;
import org.apache.hadoop.hbase.client.ResultScanner;
import org.apache.hadoop.hbase.client.Scan;
import org.apache.hadoop.hbase.filter.Filter;
import org.apache.hadoop.hbase.filter.PrefixFilter;
import org.apache.hadoop.hbase.util.Bytes;
import org.apache.hadoop.hdfs.qjournal.protocol.QJournalProtocolProtos.NewEpochRequestProto;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.json.JSONObject;
import org.xml.sax.InputSource;

import com.fasterxml.jackson.core.JsonProcessingException;

import cn.ctyun.common.conf.GlobalHHZConfig;
import cn.ctyun.oos.hbase.HBaseConnectionManager;
import cn.ctyun.oos.iam.accesscontroller.JsonPolicyWriter;
import cn.ctyun.oos.iam.accesscontroller.policy.AccessPolicy;
import cn.ctyun.oos.iam.accesscontroller.policy.Principal;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.Condition;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.Matcher;
import cn.ctyun.oos.iam.server.util.JSONUtils;
import common.tuple.Pair;

public class IAMTestUtils {
	
	public static final String OOS_IAM_DOMAIN="https://oos-cd-iam.ctyunapi.cn:9460/";
	public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
	public static final String regionName="cd";
	
	public static final String iamUserTable="iam-user-yx";
	public static final String iamGroupTable="iam-group-yx";
	public static final String iamPolicyTable="iam-policy-yx";
	public static final String iammfaDeviceTable="iam-mfaDevice-yx";
	public static final String iamAccountSummaryTable="iam-accountSummary-yx";
	
	/*
	 * 创建一个statement的policy String
	 */
	public static String CreateOneStatementPolicyString(Effect effect,String principalEffect, List<Principal> principals,String ationEffect,List<String> actions, String resourceEffect,List<String> resources,List<Condition> conditions) {
		AccessPolicy policy= new AccessPolicy();
		policy.id=String.valueOf(System.currentTimeMillis());
		policy.version="2012-10-17";
		
		List<Statement> statements = new ArrayList<Statement>();
		Statement s=new Statement(effect);
		s.id=policy.id+"_1";
		if (principalEffect!=null&&principals!=null) {
			s.principalEffect=principalEffect;
			s.principals=principals;
		}
		s.ationEffect=ationEffect;
		s.resourceEffect=resourceEffect;
		s.actions=actions;
		s.resources=resources;
		s.conditions=conditions;
		statements.add(s);
		policy.statements=statements;
		JsonPolicyWriter jw=new JsonPolicyWriter();
		String poString=jw.writePolicyToString(policy);
		
		System.out.println(poString);
		return poString;
	}
	
	public static Statement CreateStatement(Effect effect,String principalEffect, List<Principal> principals,String ationEffect,List<String> actions, String resourceEffect,List<String> resources,List<Condition> conditions) {
	    Statement s=new Statement(effect);
        if (principalEffect!=null&&principals!=null) {
            s.principalEffect=principalEffect;
            s.principals=principals;
        }
        s.ationEffect=ationEffect;
        s.resourceEffect=resourceEffect;
        s.actions=actions;
        s.resources=resources;
        s.conditions=conditions;
        return s;
    }
	
	public static String CreateMoreStatement(List<Statement> statements) {
	    AccessPolicy policy= new AccessPolicy();
        policy.id=String.valueOf(System.currentTimeMillis());
        policy.version="2012-10-17";
        policy.statements=statements;
        JsonPolicyWriter jw=new JsonPolicyWriter();
        String poString=jw.writePolicyToString(policy);
        System.out.println(poString);
        return poString;
    }
	
	
	public static Condition CreateCondition(String type,String conditionKey,List<String> values) {
		Condition con= new Condition() {

            @Override
            public Matcher getMatcher(String type) {
                // TODO Auto-generated method stub
                return null;
            }
		};
		
		con.type=type;
		con.conditionKey=conditionKey;
		con.values=values;
		return con;
	}
	
	public static JSONObject ParseErrorToJson(String xml) {
		
		try {
			StringReader sr = new StringReader(xml);
	        InputSource is = new InputSource(sr);
	        Document doc = (new SAXBuilder()).build(is);
	        Element root = doc.getRootElement();
	        
	        String code=root.getChild("Code").getValue();
	        String message=root.getChild("Message").getValue();
	        String resource=root.getChild("Resource").getValue();
	        String requestId=root.getChild("RequestId").getValue();
	        
	        JSONObject jObject= new JSONObject();
	        jObject.put("Code", code);
	        jObject.put("Message", message);
	        jObject.put("Resource", resource);
	        jObject.put("RequestId", requestId);
	        
	        return jObject;
	        
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null; 
	}
	
	public static Pair<Integer, String> invokeHttpsRequest(String body,String accessKey,String secretKey) {
		Pair<Integer, String> result=new Pair<Integer, String>();
		try {
			URL url = new URL(OOS_IAM_DOMAIN);
	        Map<String, String> headers = new HashMap<String, String>();
	        headers.put("Content-Type", "application/x-www-form-urlencoded");
	        
	        String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
	                url, "POST", "sts", regionName);
	        headers.put("Authorization", authorization);
	        
	        HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
	        OutputStream out = connection.getOutputStream();
	        out.write(body.getBytes());
	        out.flush();
	        int code = connection.getResponseCode();
	        String xml ="";
	        if (code==200) {
	        	xml = IOUtils.toString(connection.getInputStream());
			}else {
				xml = IOUtils.toString(connection.getErrorStream());
			}
	        result.first(code);
	        result.second(xml);;
	        System.out.println(xml);
	        out.close();        
	        if (connection != null) {
	            connection.disconnect();
	        }
			
		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		}
		
		return result;
	}
	
	public static Pair<Integer, String> invokeHttpsRequest2(String body,String accessKey,String secretKey,List<Pair<String, String>> ConditionHeaders) {
        Pair<Integer, String> result=new Pair<Integer, String>();
        try {
            URL url = new URL(OOS_IAM_DOMAIN);
            Map<String, String> headers = new HashMap<String, String>();
            headers.put("Content-Type", "application/x-www-form-urlencoded");
            
            String authorization = V4TestUtils.computeSignature(headers, null, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                    url, "POST", "sts", regionName);
            headers.put("Authorization", authorization);
            if (ConditionHeaders!=null&&ConditionHeaders.size()>0) {
                for (int i = 0; i < ConditionHeaders.size(); i++) {
                    headers.put(ConditionHeaders.get(i).first(), ConditionHeaders.get(i).second());
                }
            }

            HttpsURLConnection connection = HttpsRequestUtils.createConn(url, "POST", headers);
            OutputStream out = connection.getOutputStream();
            out.write(body.getBytes());
            out.flush();
            int code = connection.getResponseCode();
            String xml ="";
            if (code==200) {
                xml = IOUtils.toString(connection.getInputStream());
            }else {
                xml = IOUtils.toString(connection.getErrorStream());
            }
            result.first(code);
            result.second(xml);;
            System.out.println(xml);
            out.close();        
            if (connection != null) {
                connection.disconnect();
            }
            
        } catch (Exception e) {
            // TODO: handle exception
        }
        
        return result;
    }
	
	/*
	 * 如果清空iam-accountSummary表，同时清空iam-user，iam-group，iam-policy，iam-mfaDevice表
	 * 如果是iam-user，iam-group，iam-policy，iam-mfaDevice表中的一张，需要iam-accountSummary表中相关字段设置为0
	 * 如果非以上五张表直接清空
	 */
	public static void TrancateTable(String tableName) {
		HBaseAdmin hbaseAdmin = null;
        try {
        	if (tableName.contains("iam-accountSummary")) {
        		hbaseAdmin = new HBaseAdmin(GlobalHHZConfig.getConfig());
                hbaseAdmin.disableTable(iamUserTable);
                hbaseAdmin.truncateTable(TableName.valueOf(iamUserTable), true);
                hbaseAdmin.disableTable(iamGroupTable);
                hbaseAdmin.truncateTable(TableName.valueOf(iamGroupTable), true);
                hbaseAdmin.disableTable(iamPolicyTable);
                hbaseAdmin.truncateTable(TableName.valueOf(iamPolicyTable), true);
                hbaseAdmin.disableTable(iammfaDeviceTable);
                hbaseAdmin.truncateTable(TableName.valueOf(iammfaDeviceTable), true); 
			}

            if (tableName.contains("iam-user")) {
				UpdateAccountSummaryTable("users");
			}
            
            if (tableName.contains("iam-group")) {
            	UpdateAccountSummaryTable("groups");
			}
            
            if (tableName.contains("iam-policy")) {
            	UpdateAccountSummaryTable("policies");
			}
            
            if (tableName.contains("iam-mfaDevice")) {
            	UpdateAccountSummaryTable("mFADevices","mFADevicesInUse","accountMFAEnabled");
			}
            
            hbaseAdmin = new HBaseAdmin(GlobalHHZConfig.getConfig());
            hbaseAdmin.disableTable(tableName);
            hbaseAdmin.truncateTable(TableName.valueOf(tableName), true);


        } catch (Exception e) {
			// TODO: handle exception
		}
        finally {
            if (hbaseAdmin != null) {
                try {
					hbaseAdmin.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
            }
        }
	}
	
	private static void UpdateAccountSummaryTable(String...fileds ) {
		try {
			
			HConnection connection = HBaseConnectionManager.createConnection(GlobalHHZConfig.getConfig());
			HTableInterface table =connection.getTable(iamAccountSummaryTable);
			
			// 遍历iam-accountSummary表得到所有账户
			Scan scan = new Scan();
			ResultScanner scanner = table.getScanner(scan);
			List<String> list = new ArrayList<>();
            Iterator<Result> results = scanner.iterator();
            Result result = null;
            while(results.hasNext()) {
                result = results.next();
                String t = Bytes.toString(result.getRow());
                list.add(t);
            }
			System.out.println(list.size());
			// 所有账户的相关字段置0L
            for (String accountId : list) {
            	System.out.println("accountId="+accountId);
    			Put put = new Put(accountId.getBytes());
    			for (String s : fileds) {
    				put.add(Bytes.toBytes("i"), Bytes.toBytes(s), toBytes(0L));
    			}
    			table.put(put);
			}
			
		} catch (Exception e) {
			// TODO: handle exception
		}finally {
			
		}

	}
	
	public static void UpdateUserTable(String preFix,String...fileds ) {
        try {
            
            HConnection connection = HBaseConnectionManager.createConnection(GlobalHHZConfig.getConfig());
            HTableInterface table =connection.getTable(iamUserTable);
            
            // 遍历iam-user表得到所有账户
            Scan scan = new Scan();
            scan.setFilter(new PrefixFilter(preFix.getBytes()));
            
            ResultScanner scanner = table.getScanner(scan);
            List<String> list = new ArrayList<>();
            Iterator<Result> results = scanner.iterator();
            Result result = null;
            while(results.hasNext()) {
                result = results.next();
                String t = Bytes.toString(result.getRow());
                list.add(t);
            }
            System.out.println(list.size());
            
            Set<String> userRowSet = new HashSet<String>();  
           
            
            // 寻找用户
            for (int i = 0; i < list.size(); i++) {
                
                String[] ms=list.get(i).split("\\|");
                if (ms.length>=3) {
                    String userString=ms[1]+"|"+ms[2];
                    userRowSet.add(userString);
                }
            }
            // 删除所有找到的列
            for (int i = 0; i < list.size(); i++) {
                Delete del=new Delete(list.get(i).getBytes());
                table.delete(del);
            }
            
            
            // 把找到的用户policy列重置0
            Iterator<String> it = userRowSet.iterator();  
            while (it.hasNext()) {  
              String str = it.next();  
              System.out.println(str);  
              Put put = new Put(str.getBytes());
              for (String s : fileds) {
                  put.add(Bytes.toBytes("i"), Bytes.toBytes(s), toBytes(0L));
              }
              table.put(put);
            }  
            
        } catch (Exception e) {
            // TODO: handle exception
        }finally {
            
        }

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

}



