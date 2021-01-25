package cn.ctyun.oos.iam.accesscontroller.policy.condition;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.net.util.SubnetUtils;

import cn.ctyun.oos.iam.accesscontroller.policy.PolicyParseException;
import common.tuple.Pair;


/**
 * IP地址匹配条件
 * @author wangduo
 *
 */
public class IpAddressCondition extends Condition {

    private static final Log log = LogFactory.getLog(IpAddressCondition.class);
    
    // 符合IPV4格式的正则表达式
    private static String ipRegExp = "^(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|[1-9])\\."  
            +"(00?\\d|1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\."  
            +"(00?\\d|1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\."  
            +"(00?\\d|1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)$";
    
    // 符合CIDR格式的IPv4地址段表达式
    private static String cidrStrictRegExp = "^(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|[1-9])\\."  
                +"(00?\\d|1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\."  
                +"(00?\\d|1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\."  
                +"(00?\\d|1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)/(\\d|[1-2]\\d|3[0-2])$";
    
    public static enum IpAddressComparisonType {
        IpAddress((value, patterns) -> {
            return checkIP(value, patterns);
        }),
        NotIpAddress((value, patterns) -> {
            return !checkIP(value, patterns);
        });
        
        public Matcher matcher;
        
        IpAddressComparisonType(Matcher matcher) {
            this.matcher = matcher;
        }
    }

    public IpAddressCondition(String type, String key, List<String> values) throws PolicyParseException {
        super(type, key, values);
    }

    @Override
    public Matcher getMatcher(String type) {
        for (IpAddressComparisonType ipAddressType : IpAddressComparisonType.values()) {
            if (ipAddressType.toString().equals(type)) {
                return ipAddressType.matcher;
            }
        }
        return null;
    }
    
    /**
     * 校验IP是否与列表中的某个规则匹配
     * @param ip
     * @return
     */
    private static boolean checkIP(String ip, List<String> patterns) {
        Pair<List<String>,List<String>> sourceIps = getSourceIpSeparated(patterns);
        if (!ip.contains(":")) {
            // 请求ip为ipv4
            List<String> sourceIpv4 = sourceIps.first();
            for (int i = 0; i < sourceIpv4.size(); i++) {
                if (sourceIpv4.get(i).contains("/")) {
                    try {
                        SubnetUtils subnetUtils = new SubnetUtils((String) sourceIpv4.get(i));
                        subnetUtils.setInclusiveHostCount(true);
                        if (subnetUtils.getInfo().isInRange(ip))
                            return true;
                    } catch (IllegalArgumentException e) {
                        log.error("checkIP IllegalArgumentException. " + e.getMessage() + "ip=" + ip + ", sourceIp=" + sourceIpv4.get(i));
                    }
                } else {
                    if (isValidIPv4Addr(sourceIpv4.get(i))) {
                        if (ip.equals(sourceIpv4.get(i))) {
                            return true;
                        }
                    } else {
                        log.error("checkIP error. ip invalid. sourceIp:"+ sourceIpv4.get(i));
                    }
                }
            }
            return false;
        } else {
            // 请求ip为ipv6
            List<String> sourceIpv6 = sourceIps.second();
            for (int i = 0; i < sourceIpv6.size(); i++) {
                try {
                    if (isInIpv6Range(ip, sourceIpv6.get(i))) {
                        return true;
                    }
                } catch (UnknownHostException e) {
                    log.error("checkIP UnknownHostException. " + e.getMessage() + "ip=" + ip + ", sourceIp=" + sourceIpv6.get(i));
                }
            }
            return false;
        }
    }
    
    public static Pair<List<String>,List<String>> getSourceIpSeparated(List<String> patterns) {
        Pair<List<String>,List<String>> p = new Pair<List<String>,List<String>>();
        List<String> ipv4 = new ArrayList<String>();
        List<String> ipv6 = new ArrayList<String>();
        for (String sip : patterns) {
            if (!sip.contains(":")) {
                ipv4.add(sip);
            } else {
                ipv6.add(sip);
            }            
        }
        p.first(ipv4);
        p.second(ipv6);
        return p;       
    }
    
    /**
     * 判断是否为合法ipv4
     * @param ip
     * @return
     */
    public static boolean isValidIPv4Addr(String ip){
        return getPatternCompile(ipRegExp).matcher(ip).matches();
    }
    
    /**
     * 判断是否为合法ipv4 cidr
     * @param ip
     * @return
     */
    public static boolean isValidIPv4CidrAddr(String ip){
        return getPatternCompile(cidrStrictRegExp).matcher(ip).matches();
    }
    
    private static Pattern getPatternCompile(String strRegexp){
        return Pattern.compile(strRegexp);
    }
    
    /**
     * 判断ip(单个ip)是否属于sourceIp(ipv6或ipv6 cidr)范围内
     * @param ip
     * @param sourceIp
     * @return
     * @throws UnknownHostException
     */
    public static boolean isInIpv6Range(String ip, String sourceIp) throws UnknownHostException {
        if (sourceIp.contains("/")) {
            // souceIp为ipv6 cidr
            InetAddress address = InetAddress.getByName(ip);
            Pair<InetAddress, InetAddress> p = calculate(sourceIp);
            BigInteger start = new BigInteger(1, p.first().getAddress());
            BigInteger end = new BigInteger(1, p.second().getAddress());
            BigInteger target = new BigInteger(1, address.getAddress());
            int st = start.compareTo(target);
            int te = target.compareTo(end);
            return (st == -1 || st == 0) && (te == -1 || te == 0);
        } else {
            // souceIp为ipv6
            return twoIpv6IsSame(ip, sourceIp);
        }        
    }
    
    /**
     * 判断两个ipv6是否相等
     * @param ip1
     * @param ip2
     * @return
     * @throws UnknownHostException
     */
    public static boolean twoIpv6IsSame(String ip1, String ip2) throws UnknownHostException {
        InetAddress ipAddress = InetAddress.getByName(ip1);
        InetAddress sourceIpAddress = InetAddress.getByName(ip2);           
        if (ipAddress.getHostAddress().equals(sourceIpAddress.getHostAddress())) {
            return true;
        } else {
            return false;
        }
    }
    
    
    /**
     * 计算ipv6地址段的首末地址
     * @param cidr
     * @return
     * @throws UnknownHostException
     */
    public static Pair<InetAddress,InetAddress> calculate(String cidr) throws UnknownHostException {
        Pair<InetAddress,InetAddress> p = new Pair<InetAddress,InetAddress>();
        int prefixLength;
        if (cidr.contains("/")) {
            int index = cidr.indexOf("/");
            String addressPart = cidr.substring(0, index);
            String networkPart = cidr.substring(index + 1);
            InetAddress inetAddress = InetAddress.getByName(addressPart);
            prefixLength = Integer.parseInt(networkPart);
            ByteBuffer maskBuffer;
            int targetSize;
            if (inetAddress.getAddress().length == 4) {
                maskBuffer = ByteBuffer.allocate(4).putInt(-1);
                targetSize = 4;
            } else {
                maskBuffer = ByteBuffer.allocate(16).putLong(-1L).putLong(-1L);
                targetSize = 16;
            }
            BigInteger mask = (new BigInteger(1, maskBuffer.array())).not().shiftRight(prefixLength);
            ByteBuffer buffer = ByteBuffer.wrap(inetAddress.getAddress());
            BigInteger ipVal = new BigInteger(1, buffer.array());
            BigInteger startIp = ipVal.and(mask);
            BigInteger endIp = startIp.add(mask.not());
            byte[] startIpArr = toBytes(startIp.toByteArray(), targetSize);
            byte[] endIpArr = toBytes(endIp.toByteArray(), targetSize);
            InetAddress startAddress = InetAddress.getByAddress(startIpArr);
            InetAddress endAddress = InetAddress.getByAddress(endIpArr);
            p.first(startAddress);
            p.second(endAddress);
            return p;
        } else {
            InetAddress inetAddress1 = InetAddress.getByName(cidr);
            p.first(inetAddress1);
            p.second(inetAddress1);
            return p;
        }
    }
    
    private static byte[] toBytes(byte[] array, int targetSize) {
        int counter = 0;
        List<Byte> newArr = new ArrayList<Byte>();
        while (counter < targetSize && (array.length - 1 - counter >= 0)) {
            newArr.add(0, array[array.length - 1 - counter]);
            counter++;
        }
        int size = newArr.size();
        for (int i = 0; i < (targetSize - size); i++) {
            newArr.add(0, (byte) 0);
        }
        byte[] ret = new byte[newArr.size()];
        for (int i = 0; i < newArr.size(); i++) {
            ret[i] = newArr.get(i);
        }
        return ret;
    }

}
