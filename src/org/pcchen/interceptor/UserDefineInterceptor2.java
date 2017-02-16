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
 * File: UserDefineInterceptor2.java 
 * Author:pcchen
 * Email：cpc_geek@163.com
 * Date: 2017年2月15日下午2:56:23
 * Description: 
 */

public class UserDefineInterceptor2 implements Interceptor{
	private String fields_separator;
	private String indexs;
	private String index_separator;
	private String encrypted_field_index;
	
	public UserDefineInterceptor2() {
	}
	
	public UserDefineInterceptor2(String fields_separator, String indexs,
			String index_separator, String encrypted_field_index) {
//		this.fields_separator = fields_separator;
//		this.indexs = indexs;
//		this.index_separator = index_separator;
//		this.encrypted_field_index = encrypted_field_index;
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
	
	
	
	@Override
	public void close() {
	}

	@Override
	public void initialize() {
	}

	@Override
	public Event intercept(Event event) {
		if(event == null) {
			return event;
		}
		try {
			String line = new String(event.getBody(), Charsets.UTF_8);
			String[] line_fields = line.split(fields_separator);
			String[] index_split = indexs.split(index_separator);
			
			String new_line = "";
			for(int i = 0; i < index_split.length; i++) {
				String index = index_split[i];
				if(org.apache.commons.lang.StringUtils.isNotBlank(encrypted_field_index) && encrypted_field_index.equals(index)) {
					new_line += StringUtils.GetMD5Code(line_fields[Integer.parseInt(index)]);
				} else {
					new_line += line_fields[Integer.parseInt(index)];
				}
				if(i != index_split.length-1) {
					new_line += fields_separator;
				}
			}
//见了鬼了，此处把异常位置加错也会报错，异常要写在return之后
			event.setBody(new_line.getBytes(Charsets.UTF_8));
			return event;
		} catch(Exception e) {
			e.printStackTrace();
			return event;
		}
		/*if(event == null) {
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
		}*/
	}

	@Override
	public List<Event> intercept(List<Event> eventList) {
		if(eventList == null || eventList.size() == 0) {
			return eventList;
		}
		List<Event> eventNewList = new ArrayList<Event>();
		for(Event event : eventList) {
			eventNewList.add(intercept(event));
		}
		return eventNewList;
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
	
	/**
	 * 内部类用于实现对flume的配置文件中的参数读取，构造interceptor，并传递获取到的参数
	 * @author pcchen
	 *
	 */
	public static class Builder implements Interceptor.Builder {
		private String fields_separator;
		private String indexs;
		private String index_separator;
		private String encrypted_field_index;
		
		@Override
		public void configure(Context context) {
			this.fields_separator = context.getString(Constants.FIELD_SEPARATOR, Constants.DEFAULT_FIELD_SEPARATOR);
			this.indexs = context.getString(Constants.INDEXS, Constants.DEFAULT_INDEXS);
			this.index_separator = context.getString(Constants.INDEXS_SEPARATOR, Constants.DEFAULT_INDEXS);
			this.encrypted_field_index = context.getString(Constants.ENCRYPTED_FIELD_INDEX, Constants.DEFAULT_ENCRYPTED_FIELD_INDEX);
		}
		@Override
		public Interceptor build() {
			return new UserDefineInterceptor2(fields_separator, indexs, index_separator, encrypted_field_index);
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
