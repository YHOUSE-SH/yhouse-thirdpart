
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;

public class SignUtil {
    private final static Logger logger = LoggerFactory.getLogger(SignUtil.class);

    /***
     *  默认签名key
     */
    public static final String SIGN = "sign";

    private SignUtil(){}

    /**
     * 加签
     * @param requests
     * @param secretKey
     * @return
     */
    public static String sign(final Map<String,String> requests, String secretKey){
        if(Objects.isNull(requests) || requests.isEmpty()){
            logger.info("sign==>encryption parameter map is null or empty");
            return StringUtils.EMPTY;
        }
        logger.debug("sign==>sort before:{}", toString(requests));
        Map<String,String> sortedMap = sort(requests);
        logger.debug("sign==>sort after:{}", toString(sortedMap));

        //拼接参数
        String joinedSendInfo = joinIfNotNullKey(sortedMap,secretKey);

        logger.debug("sign==>join string:{}",joinedSendInfo);

        return DigestUtils.md5Hex(joinedSendInfo).toUpperCase();
    }

    /**
     * 验签
     * verfiy
     * @param requests
     * @return
     */
    public static boolean verify(final Map<String,String> requests,String secretKey){
        if(Objects.isNull(requests) || requests.isEmpty()){
            logger.info("verify==>encryption parameter map is null or empty");
            return false;
        }
        if(!requests.containsKey(SIGN)){
            logger.info("verify==>encryption parameter map dont\'t contains key ['sign']");
            return false;
        }
        String sign = requests.get(SIGN);
        if(StringUtils.isBlank(sign)){
            logger.info("verify==>encrypted sign  is null or blank");
            return false;
        }
        requests.remove(SIGN);
        String getSign = sign(requests,secretKey);
        if(StringUtils.isBlank(getSign)){
            logger.info("verify==>encrypt parameter map failed");
            return false;
        }
        return sign.equals(getSign);
    }


    /**
     * 进行参数排序
     * @param requests
     * @return
     */
    private static Map<String,String> sort(Map<String,String> requests){
        if(Objects.isNull(requests) || requests.isEmpty()){
            return requests;
        }
        Map<String,String> sortedMap = new TreeMap<String, String>(String::compareTo);
        sortedMap.putAll(requests);
        return sortedMap;
    }

    /**
     * 拼接字符串
     */
    private static String joinIfNotNullKey(Map<String,String> map , String secretKey){
        String results  = StringUtils.EMPTY;
        if(Objects.isNull(map) || map.isEmpty() || StringUtils.isBlank(secretKey)){
            return results;
        }
        List<String> targets = map.entrySet()
                .stream()
                .filter(entry -> StringUtils.isNotBlank(entry.getKey()))
                .map(entry ->
                        new StringBuilder()
                            .append(entry.getKey())
                            .append("=")
                        .append(Objects.isNull(entry.getValue()) ? StringUtils.EMPTY : entry.getValue()).toString())
                .collect(Collectors.toList());
        results+= StringUtils.join(targets,"&");
        results+= secretKey;
        return results;
    }

    private static String toString(Map<String,String> map){
        if(Objects.isNull(map) || map.isEmpty()){
            return StringUtils.EMPTY;
        }
        List<String> strings = new ArrayList<String>();
        for (Map.Entry<String, String> entry : map.entrySet()) {
            strings.add(entry.getKey()+":"+(Objects.isNull(entry.getValue())?"":entry.getValue()));
        }
        return StringUtils.join(strings,StringUtils.EMPTY);
    }

    public static void main(String[] args) {
        Map<String,String> map = new HashMap<String,String>();
        map.put("uid","XP019371");
        map.put("partnerNo","PX0001");
        map.put("mobile",null);
        map.put("name","小一");
        map.put("timestamp","1560311049");
        String secretKey = "xp12031ne1321sa3234";
        String sign = SignUtil.sign(map,secretKey);
        System.out.println("sign:"+sign);
        map.put("sign",sign);
        boolean isVerified = SignUtil.verify(map,secretKey);
        System.out.println("isVerified:"+isVerified);
    }
}
