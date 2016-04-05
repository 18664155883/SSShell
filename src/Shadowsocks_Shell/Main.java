package Shadowsocks_Shell;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Properties;
import java.util.Set;

public class Main {
	private static HashMap<Integer, User> UsersInfoHashMap;
	private static HashSet<Integer> TempUserHashSet;
	private static HashSet<Integer> UserPortList = new HashSet<Integer>();
	private static HashMap<Integer, Long> UserBandwidthHashMap;
	private static int Node_Class;
	private static String Node_ID;
	private static String Node_IP;
	private static Float Node_Rate;
	private static long LastSumBandwidth = (long)0;
	private static String DB_Address;
	private static String DB_Name;
	private static String DB_Username;
	private static String DB_Password;
	private static int Version;
	private static boolean Node_Enable;

	public static void main(final String[] args){
		System.setProperty("user.timezone","GMT +08");
		
		try {
			FileInputStream input = new FileInputStream("ssshell.conf");
			Properties properties = new Properties();
			try {
				properties.load(input);
				Node_ID = properties.getProperty("nodeid");
				Node_IP = properties.getProperty("ip");
				DB_Address = properties.getProperty("db_address");
				DB_Name = properties.getProperty("db_name");
				DB_Username = properties.getProperty("db_username");
				DB_Password = properties.getProperty("db_password");
				Version = Integer.valueOf(properties.getProperty("version"));
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} catch (FileNotFoundException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		
		Exec("killall ss-server",false);
		Exec("rm -rf /tmp/ssshell/*.pid",false);
		
		File FolderFile=new File("/tmp/ssshell");
		if(!FolderFile.exists()&&!FolderFile.isDirectory())
		{
			FolderFile.mkdirs();
		}
		FolderFile=null;
		
		UsersInfoHashMap = new HashMap<Integer,User>();
		UserBandwidthHashMap = new HashMap<Integer,Long>();
		new Thread(){
			@Override
        	public void run()
			{
        		while(true)
        		{
        			try {
        				Log("info","Connecting to mysql....");
        				Connection MysqlConnection = null;
        				Class.forName("com.mysql.jdbc.Driver").newInstance();
        				MysqlConnection = DriverManager.getConnection("jdbc:mysql://"+DB_Address+"/"+DB_Name+"",DB_Username,DB_Password);
                        
                        Statement SelectNodeinfoStatement = MysqlConnection.createStatement();
                        
                        ResultSet SelectNodeResultSet = SelectNodeinfoStatement.executeQuery("SELECT * FROM ss_node where `id`='"+Node_ID+"'");
                        SelectNodeResultSet.first();
                        
                        if(Version == 2||Version == 3)
                        {
                        	Node_Rate = SelectNodeResultSet.getFloat("traffic_rate");
                        }
                        else
                        {
                        	Node_Rate = (float) 1.0;
                        }
                        
                        if(Version==3)
                        { 
                        	Node_Class=SelectNodeResultSet.getInt("node_class");
	                        Long node_bandwidth = Long.valueOf(String.valueOf(SelectNodeResultSet.getBigDecimal("node_bandwidth")));
	                        Long node_bandwidth_limit = Long.valueOf(String.valueOf(SelectNodeResultSet.getBigDecimal("node_bandwidth_limit")));
	                        if( node_bandwidth_limit == 0||( node_bandwidth_limit != 0 && node_bandwidth_limit > node_bandwidth ))
	                        {
	                        	Node_Enable = true;
	                        }
	                        else
	                        {
	                        	Node_Enable = false;
	                        }
                        }
                        else
                        {
                        	Node_Enable = true;
                        }
                        
                        SelectNodeinfoStatement = null;
                        SelectNodeResultSet = null;
                        
                        Statement SelectUserInfoStatement = MysqlConnection.createStatement();
                        
                        ResultSet SelectUserInfoResultSet = null;
                        if(Version==3)
                        {
                        	SelectUserInfoResultSet = SelectUserInfoStatement.executeQuery("SELECT * FROM user WHERE `class`>="+Node_Class+" AND `enable`=1 AND `expire_in`>"+String.valueOf(Integer.valueOf((int) (System.currentTimeMillis()/1000)))+" AND `transfer_enable`>`u`+`d`");
                        }
                        else
                        {
                        	SelectUserInfoResultSet = SelectUserInfoStatement.executeQuery("SELECT * FROM user WHERE `enable`=1 AND `transfer_enable`>`u`+`d`");
                        }
                        
                        TempUserHashSet = new HashSet<Integer>();
                        
                        if(Node_Enable == true)
                        {
                        	while (SelectUserInfoResultSet.next()) {
                            	TempUserHashSet.add(SelectUserInfoResultSet.getInt("id"));
                            	if(UsersInfoHashMap.containsKey(SelectUserInfoResultSet.getInt("id")))
                                {
                                	//存在时
                            		//监控端口变更和密码变更
                            		User SingleUser=UsersInfoHashMap.get(SelectUserInfoResultSet.getInt("id"));
                            		
                            		if(!SingleUser.getPasswd().equals(SelectUserInfoResultSet.getString("passwd"))||SingleUser.getPort()!=SelectUserInfoResultSet.getInt("port")||!SingleUser.getMethod().equals(SelectUserInfoResultSet.getString("method")))
                            		{
                            			DeleteUser(SelectUserInfoResultSet.getInt("id"));
                            			AddUser(SelectUserInfoResultSet.getString("user_name"),SelectUserInfoResultSet.getInt("port"),SelectUserInfoResultSet.getString("passwd"),SelectUserInfoResultSet.getInt("id"),SelectUserInfoResultSet.getString("method"));
                            		}
                                }
                                else
                                {
                                	//不存在时
                                	AddUser(SelectUserInfoResultSet.getString("user_name"),SelectUserInfoResultSet.getInt("port"),SelectUserInfoResultSet.getString("passwd"),SelectUserInfoResultSet.getInt("id"),SelectUserInfoResultSet.getString("method")); 	
                                }
                            }
                        }
                        else
                        {
                        	Set<Integer> UsersInfoMapKeySet = UsersInfoHashMap.keySet();
                        	Iterator<Integer> UserInfoKeySetIterator = UsersInfoMapKeySet.iterator();
                        	while(UserInfoKeySetIterator.hasNext())
                            {
                        		DeleteUser(UserInfoKeySetIterator.next());
                            }
                        }
                        
                        SelectUserInfoStatement = null;
                        SelectUserInfoResultSet = null;
                        
                        long ThisTimeSumBandwidth = 0;
                        
                        Log("info","Getting the OnlineUser.....");
                        String OnlineUserString = Exec("netstat -antp|grep "+Node_IP+":|awk -F ' ' '{print $4\"-\"$5}'|grep -v 0.0.0.0",true);
                		String[] OnlineUserStringArray = OnlineUserString.split("\n");
                		OnlineUserString = null;
                		
                		HashSet<String> ExistIpHashSet = new HashSet<String>();
                		int OnlineUserCount = 0;
                		
                		for(String OnlineUserSingle:OnlineUserStringArray)
                		{
                			String[] OnlineUserTempStringArray = OnlineUserSingle.split("-");
                			String[] OnlineUserPortArray = OnlineUserTempStringArray[0].split(":");
                			String OnlineUserPort = OnlineUserPortArray[1];
                			if(OnlineUserPort.equals(""))
                			{
                				OnlineUserPort=OnlineUserPortArray[4];
                			}
                			
                			String[] UserIPArray=OnlineUserTempStringArray[1].split(":");
                			String OnlineUserIP=UserIPArray[0];
                			if(OnlineUserIP.equals(""))
                			{
                				OnlineUserIP = UserIPArray[3];
                			}
                			
                			if(UserPortList.contains(Integer.valueOf(OnlineUserPort)))
                			{
                				if(!ExistIpHashSet.contains(OnlineUserIP))
                				{
                					OnlineUserCount++;
                					ExistIpHashSet.add(OnlineUserIP);
                				}
                			}
                		}
                		
                		OnlineUserStringArray = null;
                		ExistIpHashSet = null;
                		           		
                		String BandWidthString = Exec("iptables -n -v -L -t filter -x |awk -F' ' '{print $2\"-\"$10}'|grep spt",true);
                		String[] BandWidthArray = BandWidthString.split("\n");
                		BandWidthString = null;
                		
                		HashMap<Integer,Long> PortBandWidthHashMap = new HashMap<Integer,Long>();
                		
                		for(String BandWidthLine:BandWidthArray)
                		{
                			String[] BandWidthTemp = BandWidthLine.split("-");
                			String[] BandWidthPort = BandWidthTemp[1].split(":");
                			PortBandWidthHashMap.put(Integer.valueOf(BandWidthPort[1]), Long.valueOf(BandWidthTemp[0]));
                		}
                		
                		String PortString=Exec("netstat -antp|grep "+Node_IP+":|grep 0.0.0.0:*|awk -F' ' '{print $4}'|awk -F':' '{print $2}'",true);
                		String[] PortArray=PortString.split("\n");
                		HashSet<Integer> PortSet=new HashSet<Integer>();
                		for(String Port:PortArray)
                		{
                			PortSet.add(Integer.valueOf(Port));
                		}
                		
                		Set<Integer> UsersInfoSet = UsersInfoHashMap.keySet();
                        Iterator<Integer> UsersInfoIterator = UsersInfoSet.iterator();
                        HashSet<Integer> DeletedUserHashSet = new HashSet<Integer>();
                        while(UsersInfoIterator.hasNext())
                        {
                        	int CurrentUserId = UsersInfoIterator.next();
                        	if(PortBandWidthHashMap.containsKey(UsersInfoHashMap.get(CurrentUserId).getPort()))
                    		{
                    			if(PortBandWidthHashMap.get(UsersInfoHashMap.get(CurrentUserId).getPort())!=0)
                    			{
                    				if(UserBandwidthHashMap.containsKey(CurrentUserId))
                    				{
                    					long ThisTimeBandWidth = PortBandWidthHashMap.get(UsersInfoHashMap.get(CurrentUserId).getPort());
                    					ThisTimeSumBandwidth = ThisTimeSumBandwidth + ThisTimeBandWidth;
                    					if(ThisTimeBandWidth - UserBandwidthHashMap.get(CurrentUserId) > 0)
                    					{
                    						Log("info","Syncing the user traffic...."+CurrentUserId+" "+(ThisTimeBandWidth-UserBandwidthHashMap.get(CurrentUserId))*Node_Rate);
                    						
                    						Statement UpdateUserStatement = MysqlConnection.createStatement();
                    						UpdateUserStatement.executeUpdate("UPDATE `user` SET `d`=`d`+"+(ThisTimeBandWidth-UserBandwidthHashMap.get(CurrentUserId))*Node_Rate+",`t`='"+(System.currentTimeMillis()/1000)+"' WHERE `id`='"+UsersInfoHashMap.get(CurrentUserId).getId()+"'");
                    						UpdateUserStatement = null;
                    						
                    						if(Version == 2||Version == 3)
                    						{
	                    						Statement AddTrafficLogStatement = MysqlConnection.createStatement();
	                    						AddTrafficLogStatement.execute("INSERT INTO `user_traffic_log` (`id`, `user_id`, `u`, `d`, `Node_ID`, `rate`, `traffic`, `log_time`) VALUES (NULL, '"+CurrentUserId+"', '0', '"+(ThisTimeBandWidth-UserBandwidthHashMap.get(CurrentUserId))+"', '"+Node_ID+"', '"+Node_Rate+"', '"+TrafficShow((ThisTimeBandWidth-UserBandwidthHashMap.get(CurrentUserId)))+"', '"+Long.valueOf(System.currentTimeMillis()/1000)+"'); ");
	                    						AddTrafficLogStatement = null;
                    						}
                    						
                    						UserBandwidthHashMap.put(CurrentUserId, ThisTimeBandWidth);
                    					}
                    				}
                    			}
                    		}
                        	else
                        	{
                        		Exec("iptables -A OUTPUT -s "+Node_IP+" -p tcp --sport "+UsersInfoHashMap.get(CurrentUserId).getPort(),false);
                        	}
                        	
                        	if(!PortSet.contains(UsersInfoHashMap.get(CurrentUserId).getPort()))
                        	{
                        		Exec("ss-server -c /tmp/ssshell/"+CurrentUserId+".conf -f /tmp/ssshell/"+CurrentUserId+".pid -u -s "+Node_IP,false);
                        	}
                    		
                        	if(!TempUserHashSet.contains(CurrentUserId))
                        	{
                        		DeletedUserHashSet.add(CurrentUserId);
                        	}
                        }
                        
                        PortSet = null;
                        PortBandWidthHashMap = null;
                        
                        if(Version == 3)
                        {
	                        Statement UpdateNodeStatement = MysqlConnection.createStatement();
	                        UpdateNodeStatement.executeUpdate("UPDATE `ss_node` SET `node_heartbeat`='"+Long.valueOf(System.currentTimeMillis()/1000)+"',`node_bandwidth`=`node_bandwidth`+'"+(ThisTimeSumBandwidth-LastSumBandwidth)+"' WHERE `id` = "+Node_ID+"; ");
							LastSumBandwidth = ThisTimeSumBandwidth;
							UpdateNodeStatement = null;
                        }
						if(Version == 2 || Version == 3)
						{
	                        Statement AddNodeOnlineLogStatement = MysqlConnection.createStatement();
	                        AddNodeOnlineLogStatement.execute("INSERT INTO `ss_node_online_log` (`id`, `Node_ID`, `online_user`, `log_time`) VALUES (NULL, '"+Node_ID+"', '"+OnlineUserCount+"', '"+Long.valueOf(System.currentTimeMillis()/1000)+"'); ");
	                        AddNodeOnlineLogStatement = null;
						}
                        
                    	Iterator<Integer> DeletedUserIterator = DeletedUserHashSet.iterator();
                    	while(DeletedUserIterator.hasNext())
                    	{
                    		DeleteUser(DeletedUserIterator.next());
                    	}
                        
                        
                        try {
                        	MysqlConnection.close();
						} catch (SQLException e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						}
                        MysqlConnection = null;
        			} catch(Exception e) {
        				System.err.println("Exception: " + e.getMessage()+e.getStackTrace().toString()+e.getLocalizedMessage()+e.getCause());
        			}
        			
        			Log("info","Sleeping...");
        			try {
						sleep(60000);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
        		}
        	}
        }.start();
	}

	
	public static String Exec(String cmd,Boolean NeedReturn) {
        try {
            String[] cmdA = { "/bin/sh", "-c", cmd };
            if(NeedReturn==false)
            {
            	Runtime.getRuntime().exec(cmdA);
            	return null;
            }
            Process process = Runtime.getRuntime().exec(cmdA);
            LineNumberReader br = new LineNumberReader(new InputStreamReader(
                    process.getInputStream()));
            StringBuffer sb = new StringBuffer();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
            }
            return sb.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
	
	public static void Log(String LogLevel,String LogContent)
	{
		SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");//设置日期格式
		System.out.println("["+LogLevel+"]["+df.format(new Date())+"]"+LogContent);
	}
	
	public static String TrafficShow(Long Traffic)
	{
		if(Traffic<1024)
		{
			return String.valueOf(Traffic)+"B";
		}
		
		if(Traffic<1024*1024)
		{
			return String.valueOf(Traffic/1024)+"KB";
		}
		
		if(Traffic<1024*1024*1024)
		{
			return String.valueOf(Traffic/1024/1024)+"MB";
		}
		
		
		return String.valueOf(Traffic/1024/1024/1024)+"GB";
		
	}
	
	public static void DeleteUser(int UserId)
	{
		try{
			Log("info","Deleting User..."+UserId);
			File PidFile=new File("/tmp/ssshell/"+UsersInfoHashMap.get(UserId).getId()+".pid");
			if(PidFile.exists())
			{
				FileInputStream PidFileInputStream = new FileInputStream("/tmp/ssshell/"+UsersInfoHashMap.get(UserId).getId()+".pid");
				InputStreamReader PidFileInputStreamReader = new InputStreamReader(PidFileInputStream,"UTF-8");
				BufferedReader PidFileInputBufferedReader = new BufferedReader(PidFileInputStreamReader);
				String line = null;
				while((line=PidFileInputBufferedReader.readLine())!=null){
					Exec("kill "+line,false);
				}
				PidFileInputBufferedReader.close();
				PidFile.delete();
			}
			
			Exec("rm -f /tmp/ssshell/"+UserId+".conf",false);
		
			String BandWidthString=Exec("iptables -L --line-number -n|grep \"spt:"+UsersInfoHashMap.get(UserId).getPort()+"\"|awk -F' ' '{print $1}'",false);
			String[] BandWidthArray=BandWidthString.split("\n");
			
    		for(int i = 0;i < BandWidthArray.length; i++)
    		{
    			Exec("iptables -D OUTPUT -s "+Node_IP+" -p tcp --sport "+UsersInfoHashMap.get(UserId).getPort(),false);
    		}
		
    		UserPortList.remove(UsersInfoHashMap.get(UserId).getPort());
			UsersInfoHashMap.remove(UserId);
			UserBandwidthHashMap.remove(UserId);
			
		}catch(Exception e) {
			System.err.println("Exception: " + e.getMessage());
		}
	}

	public static void AddUser(String UserName,int Port,String Passwd,int Id,String Method)
	{
		Log("info","Adding User..."+UserName);
		
		Exec("rm -f /tmp/ssshell/"+Id+".conf",false);
		
		User newUser = new User(Port,Passwd,Id,Method);
		
		UsersInfoHashMap.put(Id, newUser);
		UserBandwidthHashMap.put(Id, (long) 0);
		
		String BandWidthString = Exec("iptables -L --line-number -n|grep \"spt:"+UsersInfoHashMap.get(Id).getPort()+"\"|awk -F' ' '{print $1}'",true);
		String[] BandWidthArray = BandWidthString.split("\n");
		
		for(int i = 0;i < BandWidthArray.length; i++)
		{
			Exec("iptables -D OUTPUT -s "+Node_IP+" -p tcp --sport "+UsersInfoHashMap.get(Id).getPort(),false);
		}
		
		try {
	         BufferedWriter out = new BufferedWriter(new FileWriter("/tmp/ssshell/"+Id+".conf"));
	         out.write("{\"server\":\""+Node_IP+"\",\"server_port\":"+Port+",\"local_port\":1080,\"password\":\""+Passwd+"\",\"timeout\":60,\"method\":\""+Method+"\"}");
	         out.close();
		} catch (IOException e) {
		}
		
		Exec("chown 600 /tmp/ssshell/"+Id+".conf",false);
		
		Exec("ss-server -c /tmp/ssshell/"+Id+".conf -f /tmp/ssshell/"+Id+".pid -u -s "+Node_IP,false);
		Exec("iptables -A OUTPUT -s "+Node_IP+" -p tcp --sport "+Port,false);
		
		UserPortList.add(Port);
		
		while(true)
		{
			BandWidthString = Exec("iptables -L --line-number -n|grep \"spt:"+Port+"\"",true);
			BandWidthArray = BandWidthString.split("\n");
			if(!BandWidthString.contains("spt")||BandWidthArray.length!=1)
			{
	    		for(int i = 0;i < BandWidthArray.length; i++)
	    		{
	    			Exec("iptables -D OUTPUT -s "+Node_IP+" -p tcp --sport "+Port,false);
	    		}
	    		
	    		Exec("iptables -A OUTPUT -s "+Node_IP+" -p tcp --sport "+Port,false);
			}
			else
			{
				break;
			}
		}	
	}
}
