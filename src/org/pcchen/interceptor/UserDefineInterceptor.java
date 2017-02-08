package org.pcchen.interceptor;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.flume.Context;
import org.apache.flume.Event;
import org.apache.flume.interceptor.Interceptor;

import com.google.common.base.Charsets;

/**
 * File: UserDefineInterceptor.java 
 * Author:pcchen
 * Email：cpc_geek@163.com
 * Date: 2017年2月7日下午3:46:03
 * Description: 用户自定义实现flume的拦截器，对数据进行简单处理
 */

public class UserDefineInterceptor implements Interceptor{
	/** 指定字段的分隔符 */
	private  String fields_separator;
	/** 指定需要查出字段的索引 */
	private String indexs;
	/** 指定配置的索引字段的分隔符 */
	private String index_separator;
	/** 指定需要加密字段的索引 */
	private String encrypted_field_index;

	public UserDefineInterceptor() {
	}
	
	/**
	 * 对配置文件中的数据进行初始化
	 * @param fields_separator
	 * @param indexs
	 * @param index_separator
	 * @param encrypted_field_index
	 */
	public UserDefineInterceptor(String fields_separator, String indexs, 
			String index_separator, String encrypted_field_index) {
		String f = fields_separator.trim();
		String i = index_separator.trim();
		this.indexs = indexs;
		this.encrypted_field_index = encrypted_field_index;
		
		if(!"".equals(f)) {
			f = UnicodeToString(f);
		}
		this.fields_separator = f;
		if(!"".equals(i)) {
			i = UnicodeToString(i);
		}
		this.index_separator = i;
	}
	/*
	 * 
	 * \t 制表符 ('\u0009') \n 新行（换行）符 (' ') \r 回车符 (' ') \f 换页符 ('\u000C') \a 报警
	 * (bell) 符 ('\u0007') \e 转义符 ('\u001B') \cx  空格(\u0020)对应于 x 的控制符
	 * 
	 * @param str
	 * @return
	 * @data:2015-6-30
	 */
	private String UnicodeToString(String flag) {
		Pattern pattern = Pattern.compile("(\\\\u(\\p{XDigit}{4}))");
		Matcher matcher = pattern.matcher(flag);
		
		char ch;
		while(matcher.find()) {
			ch = (char) Integer.parseInt(matcher.group(2),16);
			flag = flag.replace(matcher.group(1),  ch + "");
		}
		return flag;
	}
	
	@Override
	public void initialize() {
	}

	@Override
	public Event intercept(Event event) {
		if(event == null) {
			return null;
		}
		try {
			String newLine = "";
			
			String line = new String(event.getBody(), Charsets.UTF_8);
			String[] fields_splits = line.split(fields_separator);
			//得到索引的数组
			String[] index_splits = indexs.split(index_separator);
			
			for(int i = 0; i < index_splits.length; i++) {
				int index = Integer.parseInt(index_splits[i]);
				//对加密字段进行加密
				if(!"".equals(encrypted_field_index) && encrypted_field_index.equals(index_splits[i])) {
					newLine += StringUtils.GetMD5Code(fields_splits[index]);
				} else {
					newLine += fields_splits[index];
				}
				
				if(i != index_splits.length-1) {
					newLine += fields_separator;
				}
			}
			event.setBody(newLine.getBytes(Charsets.UTF_8));
			return event;
		//此处注意catch的异常
		} catch (Exception e) {
			return event; 
		}
	}

	@Override
	public List<Event> intercept(List<Event> events) {
		List<Event> eventNewList = new ArrayList<Event>();
		for(Event event : events) {
			if(intercept(event) != null) {
				eventNewList.add(intercept(event));
			}
		}
		return eventNewList;
	}

	@Override
	public void close() {
	}
	
	/**
	 * 此类必须定义为static，因其外部类初始化时要加载七configure，兵器调build方法，构造外部类实例进行外部类初始化
	 * ClassName: Builder <br/> 
	 * date: 2017年2月8日 上午12:22:06 <br/> 
	 * 
	 * @author pcchen
	 * @version UserDefineInterceptor 
	 * @since JDK 1.8
	 */
	public static class Builder implements Interceptor.Builder {
		/** 指定字段的分隔符 */
		private String fields_separator;
		/** 指定需要查出字段的索引 */
		private String indexs;
		/** 指定配置的索引字段的分隔符 */
		private String index_separator;
		/** 指定需要加密字段的索引 */
		private String encrypted_field_index;
		@Override
		public void configure(Context context) {
			//下面四行是错误的
			fields_separator = context.getString(Constants.FIELD_SEPARATOR, Constants.DEFAULT_FIELD_SEPARATOR);
			indexs = context.getString(Constants.INDEXS, Constants.DEFAULT_INDEXS);
			index_separator = context.getString(Constants.INDEXS_SEPARATOR, Constants.DEFAULT_INDEXS_SEPARATOR);
			encrypted_field_index = context.getString(Constants.ENCRYPTED_FIELD_INDEX, Constants.DEFAULT_ENCRYPTED_FIELD_INDEX);
			
//			fields_separator = "\\u0009";
//			indexs = "0,1,3,5,6";
//			index_separator = "\\u002c";
//			encrypted_field_index = "0";
//			
//			fields_separator = context.getString(Constants.FIELD_SEPARATOR, Constants.DEFAULT_FIELD_SEPARATOR);
//			indexs = context.getString(Constants.INDEXS, Constants.DEFAULT_INDEXS);
//			index_separator = context.getString(Constants.INDEXS_SEPARATOR, Constants.DEFAULT_INDEXS_SEPARATOR);
//			encrypted_field_index= context.getString(Constants.ENCRYPTED_FIELD_INDEX, Constants.DEFAULT_ENCRYPTED_FIELD_INDEX);
		}
		@Override
		public Interceptor build() {
			return new UserDefineInterceptor(fields_separator, indexs, index_separator, encrypted_field_index);
		}
	}
	public static class Constants {
		/** The Constant FIELD_SEPARATOR. */
		public static final String FIELD_SEPARATOR = "fields_separator";

		/** The Constant DEFAULT_FIELD_SEPARATOR. */
		public static final String DEFAULT_FIELD_SEPARATOR =" ";
		
		/** The Constant INDEXS. */
		public static final String INDEXS = "indexs";

		/** The Constant DEFAULT_INDEXS. */
		public static final String DEFAULT_INDEXS = "0";

		/** The Constant INDEXS_SEPARATOR. */
		public static final String INDEXS_SEPARATOR = "indexs_separator";

		/** The Constant DEFAULT_INDEXS_SEPARATOR. */
		public static final String DEFAULT_INDEXS_SEPARATOR = ",";
		
		/** The Constant ENCRYPTED_FIELD_INDEX. */
		public static final String ENCRYPTED_FIELD_INDEX = "encrypted_field_index";

		/** The Constant DEFAUL_TENCRYPTED_FIELD_INDEX. */
		public static final String DEFAULT_ENCRYPTED_FIELD_INDEX = "";
		
		/** The Constant PROCESSTIME. */
		public static final String PROCESSTIME = "processTime";
		/** The Constant PROCESSTIME. */
		public static final String DEFAULT_PROCESSTIME = "a";
		
	}	
	/**
	 * 字符串md5加密
	 */
	public static class StringUtils {
		 private final static String[] strDigits = { "0", "1", "2", "3", "4", "5",
		            "6", "7", "8", "9", "a", "b", "c", "d", "e", "f" };
		// 返回形式为数字跟字符串
	    private static String byteToArrayString(byte bByte) {
	        int iRet = bByte;
	        // System.out.println("iRet="+iRet);
	        if (iRet < 0) {
	            iRet += 256;
	        }
	        int iD1 = iRet / 16;
	        int iD2 = iRet % 16;
	        return strDigits[iD1] + strDigits[iD2];
	    }
		// 转换字节数组为16进制字串
	    private static String byteToString(byte[] bByte) {
	        StringBuffer sBuffer = new StringBuffer();
	        for (int i = 0; i < bByte.length; i++) {
	            sBuffer.append(byteToArrayString(bByte[i]));
	        }
	        return sBuffer.toString();
	    }
		public static String GetMD5Code(String strObj) {
	        String resultString = null;
	        try {
	            resultString = new String(strObj);
	            MessageDigest md = MessageDigest.getInstance("MD5");
	            // md.digest() 该函数返回值为存放哈希值结果的byte数组
	            resultString = byteToString(md.digest(strObj.getBytes()));
	        } catch (NoSuchAlgorithmException ex) {
	            ex.printStackTrace();
	        }
	        return resultString;
	    }
	}
}
