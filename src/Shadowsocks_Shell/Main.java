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
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;  
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;  

public class Main {
	private static HashMap<Integer, User> UsersInfoHashMap;
	private static HashSet<Integer> TempUserHashSet;
	private static HashSet<Integer> UserPortList = new HashSet<Integer>();
	private static HashMap<Integer, Long> UserBandwidthHashMap;
	private static HashMap<Integer,Long> PortBandWidthHashMap = new HashMap<Integer,Long>();
	private static HashMap<Integer,Long> PortOnlineHashMap = new HashMap<Integer,Long>();
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
	private static String Node_Nic;
	protected static int Node_SpeedLimit;

	public static void main(final String[] args){
		System.setProperty("user.timezone","GMT +08");
		
		try {
			FileInputStream input = new FileInputStream("ssshell.conf");
			Properties properties = new Properties();
			try {
				properties.load(input);
				Node_ID = properties.getProperty("nodeid");
				Node_IP = properties.getProperty("ip");
				Node_Nic = properties.getProperty("nic");
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
		
		ResetSpeedLimit();
		PrepareSpeedLimit();
		
		File FolderFile=new File("/tmp/ssshell");
		if(!FolderFile.exists()&&!FolderFile.isDirectory())
		{
			FolderFile.mkdirs();
		}
		FolderFile=null;
		
		UsersInfoHashMap = new HashMap<Integer,User>();
		UserBandwidthHashMap = new HashMap<Integer,Long>();
		
		
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs  
        StringBuilder errbuf = new StringBuilder(); // For any error msgs  
		
        int r = Pcap.findAllDevs(alldevs, errbuf);  
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {  
            System.err.printf("Can't read list of devices, error is %s", errbuf  
                .toString());  
            return;  
        }  
  
        int i = 0;
        int any = 0;
        
        for (PcapIf device : alldevs) {  
            if(device.getName().equals("any"))
            {
            	any = i;
            }
            i++;
        }  
  
        if(any == 0)
        {
        	any = i;
        }
        
        PcapIf device = alldevs.get(any); // We know we have atleast 1 device  
  
        int snaplen = 64 * 1024;           // Capture all packets, no trucation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 10 * 1000;           // 10 seconds in millis  
        Pcap pcap =  
            Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);  
  
        if (pcap == null) {  
            System.err.printf("Error while opening device for capture: "  
                + errbuf.toString());  
            return;  
        }  
        
      
  
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {  
  
            public void nextPacket(PcapPacket packet, String user) { 
            	
            	Boolean Out = false;
            	String IP = "";
            	
            	if(packet.hasHeader(new Ip4()))
                {
                    Ip4 ip = packet.getHeader(new Ip4());                    
                    IP = getIpAddress(ip.source());
                    if(IP.equals(Node_IP))
                    {
                    	Out = true;
                    }
                    IP = getIpAddress(ip.destination());
                    if(!IP.equals(Node_IP))
                    {
                    	return;
                    }
                }

                if(packet.hasHeader(new Tcp()))
                {
                    Tcp tcp = packet.getHeader(new Tcp());
                    if(Out == true)
                    {
                    	if(UserPortList.contains(tcp.source()))
                    	{
                    		PortBandWidthHashMap.put(tcp.source(),PortBandWidthHashMap.get(tcp.source())+packet.getTotalSize());
                    		PortOnlineHashMap.put(tcp.source(), Long.valueOf(System.currentTimeMillis()/1000));
                    	}
                    }
                    else
                    {
                    	if(UserPortList.contains(tcp.destination()))
                    	{
                    		PortBandWidthHashMap.put(tcp.destination(),PortBandWidthHashMap.get(tcp.destination())+packet.getTotalSize());
                    		PortOnlineHashMap.put(tcp.destination(), Long.valueOf(System.currentTimeMillis()/1000));
                    	}
                    }
                    return;
                }

                if(packet.hasHeader(new Udp()))
                {
                    Udp udp = packet.getHeader(new Udp());
                    udp.source();
                    udp.destination();
                    if(Out == true)
                    {
                    	if(UserPortList.contains(udp.source()))
                    	{
                    		PortBandWidthHashMap.put(udp.source(),PortBandWidthHashMap.get(udp.source())+packet.getTotalSize());
                    		PortOnlineHashMap.put(udp.source(), Long.valueOf(System.currentTimeMillis()/1000));
                    	}
                    }
                    else
                    {
                    	if(UserPortList.contains(udp.destination()))
                    	{
                    		PortBandWidthHashMap.put(udp.destination(),PortBandWidthHashMap.get(udp.destination())+packet.getTotalSize());
                    		PortOnlineHashMap.put(udp.destination(), Long.valueOf(System.currentTimeMillis()/1000));
                    	}
                    }
                    return;
                }
                
            }  
        };  
  
        
        
        new Thread(){
        	@Override
        	public void run()
        	{
        		while(true)
                {
                	pcap.loop(1000, jpacketHandler, "jNetPcap rocks!");  
                }
        	}
        }.start();
		
		
		
		
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
                        	Node_SpeedLimit=SelectNodeResultSet.getInt("node_speedlimit");
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
                        	Node_SpeedLimit = 0;
                        	Node_Enable = true;
                        }
                        
                        SelectNodeinfoStatement = null;
                        SelectNodeResultSet = null;
                        
                        Statement SelectUserInfoStatement = MysqlConnection.createStatement();
                        
                        ResultSet SelectUserInfoResultSet = null;
                        if(Version==3)
                        {
                        	SelectUserInfoResultSet = SelectUserInfoStatement.executeQuery("SELECT * FROM user WHERE `class`>="+Node_Class+" AND `enable`=1 AND `expire_in`>"+TimeStamp2Date(String.valueOf(Long.valueOf((long) (System.currentTimeMillis()/1000))), "yyyy-MM-dd HH:mm:ss")+" AND `transfer_enable`>`u`+`d`");
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
                            		
                            		int SingleUserSpeedLimit = 0;
                            		
                            		if(Version == 3)
                            		{
                            		
	                            		if(SelectUserInfoResultSet.getInt("node_speedlimit")>Node_SpeedLimit)
	                            		{
	                            			SingleUserSpeedLimit = SelectUserInfoResultSet.getInt("node_speedlimit");
	                            		}
	                            		else
	                            		{
	                            			SingleUserSpeedLimit = Node_SpeedLimit;
	                            		}
	                            		
                            		}
                            		
                            		if(!SingleUser.getPasswd().equals(SelectUserInfoResultSet.getString("passwd"))||SingleUser.getPort()!=SelectUserInfoResultSet.getInt("port")||!SingleUser.getMethod().equals(SelectUserInfoResultSet.getString("method"))||SingleUser.getSpeedLimit()!=SingleUserSpeedLimit)
                            		{
                            			DeleteUser(SelectUserInfoResultSet.getInt("id"));
                            			AddUser(SelectUserInfoResultSet.getString("user_name"),SelectUserInfoResultSet.getInt("port"),SelectUserInfoResultSet.getString("passwd"),SelectUserInfoResultSet.getInt("id"),SelectUserInfoResultSet.getString("method"),SingleUserSpeedLimit);
                            		}
                                }
                                else
                                {
                                	//不存在时
                                	int SingleUserSpeedLimit = 0;
                            		
                                	if(Version == 3)
                            		{
                            		
	                            		if(SelectUserInfoResultSet.getInt("node_speedlimit")>Node_SpeedLimit)
	                            		{
	                            			SingleUserSpeedLimit = SelectUserInfoResultSet.getInt("node_speedlimit");
	                            		}
	                            		else
	                            		{
	                            			SingleUserSpeedLimit = Node_SpeedLimit;
	                            		}
	                            		
                            		}
                            		
                                	AddUser(SelectUserInfoResultSet.getString("user_name"),SelectUserInfoResultSet.getInt("port"),SelectUserInfoResultSet.getString("passwd"),SelectUserInfoResultSet.getInt("id"),SelectUserInfoResultSet.getString("method"),SingleUserSpeedLimit); 	
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
                		
                		int OnlineUserCount = 0;
                		
                		Set<Integer> PortSet = PortOnlineHashMap.keySet();
                		Iterator<Integer> PortSetItertor = PortSet.iterator();
                		
                		HashSet<Integer> DeletePortSet = new HashSet<Integer>();
                		
                		while(PortSetItertor.hasNext())
                		{
                			int Port = PortSetItertor.next();
                			if(PortOnlineHashMap.get(Port) > Long.valueOf(System.currentTimeMillis()/1000) - 300)
                			{
                				OnlineUserCount++;
                			}
                			else
                			{
                				DeletePortSet.add(Port);
                			}
                		}
                		
                		PortSetItertor = null;
                		PortSet = null;
                		
                		Iterator<Integer> DeletePortIterator = DeletePortSet.iterator();
                		
                		while(DeletePortIterator.hasNext())
                		{
                			PortOnlineHashMap.remove(DeletePortIterator.next());
                		}
                		
                		DeletePortIterator = null;
                		DeletePortSet = null;
                		
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
                        	
                        	if(!TempUserHashSet.contains(CurrentUserId))
                        	{
                        		DeletedUserHashSet.add(CurrentUserId);
                        	}
                        }
                        
                        
                        
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
						
						if(Version == 2 || Version == 3)
						{
	                        Statement AddNodeOnlineLogStatement = MysqlConnection.createStatement();
	                        AddNodeOnlineLogStatement.execute("INSERT INTO `ss_node_info` (`id`, `node_id`, `uptime`, `load`, `log_time`) VALUES (NULL, '"+Node_ID+"', '"+GetUptime()+"', '"+GetLoad()+"', '"+String.valueOf(Long.valueOf(System.currentTimeMillis()/1000))+"'); ");
	                        AddNodeOnlineLogStatement = null;
	                    }
                        
                    	Iterator<Integer> DeletedUserIterator = DeletedUserHashSet.iterator();
                    	while(DeletedUserIterator.hasNext())
                    	{
                    		DeleteUser(DeletedUserIterator.next());
                    	}
                    	
                    	DeletedUserIterator = null;
                    	DeletedUserHashSet = null;
                        
                        
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
	
	public static void ForkChild(String cmd)
	{
		Process childProcess;
		try {
			childProcess = new ProcessBuilder(cmd).start();
			Thread closeChildThread = new Thread() {
			    public void run() {
			        childProcess.destroy();
			    }
			};
			Runtime.getRuntime().addShutdownHook(closeChildThread); 
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public static void PrepareSpeedLimit()
	{
		Exec("tc qdisc add dev "+Node_Nic+" handle 8964: root htb",true);
	}
	
	public static void AddSpeedLimit(String Port,String Speed)
	{
		Exec("tc class add dev "+Node_Nic+" parent 8964: classid 8964:"+Port+" htb rate "+Speed+"mbps",true);
		Exec("tc filter add dev "+Node_Nic+" protocol ip prio 1 u32 match ip dport "+Port+" 0xffff flowid 1:"+Port,true);
	}
	
	public static void DeleteSpeedLimit(String Port)
	{
		String ReturnString = Exec("tc filter list dev "+Node_Nic+" |grep \"flowid 1:"+Port+"\"|awk '{print $10}'",true);
		String[] ReturnArray = ReturnString.split("\n");
		for(String Id:ReturnArray)
		{
			Exec("tc filter delete dev "+Node_Nic+" parent 1: protocol ip prio 1 handle "+Id+" u32",true);
		}
	}

	public static void ResetSpeedLimit()
	{
		Exec("tc qdisc del dev "+Node_Nic+" root",true);
	}
	
	public static String GetUptime()
	{
		String ReturnString = Exec("cat /proc/uptime | awk '{ print $1 }'",true);
		String[] ReturnArray = ReturnString.split("\n");
		return ReturnArray[0];
	}
	
	public static String GetLoad()
	{
		String ReturnString = Exec("cat /proc/loadavg | awk '{ print $1\" \"$2\" \"$3 }'",true);
		String[] ReturnArray = ReturnString.split("\n");
		return ReturnArray[0];
	}
	
	public static void Log(String LogLevel,String LogContent)
	{
		SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
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
	
	public static boolean DeleteFile(String fileName){     
	    File file = new File(fileName);     
	    if(file.isFile() && file.exists()){     
	        file.delete();     
	        return true;     
	    }else{     
	    	return false;     
	    }     
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
			
			DeleteFile("/tmp/ssshell/"+UserId+".conf");
		
    		UserPortList.remove(UsersInfoHashMap.get(UserId).getPort());
    		PortBandWidthHashMap.remove(UsersInfoHashMap.get(UserId).getPort());
    		
    		if(UsersInfoHashMap.get(UserId).getSpeedLimit() != 0)
    		{
    			DeleteSpeedLimit(String.valueOf(UsersInfoHashMap.get(UserId).getPort()));
    		}
    		
			UsersInfoHashMap.remove(UserId);
			UserBandwidthHashMap.remove(UserId);
			
			
		}catch(Exception e) {
			System.err.println("Exception: " + e.getMessage());
		}
	}
	
	public static void AddUser(String UserName,int Port,String Passwd,int Id,String Method,int SpeedLimit)
	{
		Log("info","Adding User..."+UserName);
		
		DeleteFile("/tmp/ssshell/"+Id+".conf");
		
		User newUser = new User(Port,Passwd,Id,Method,SpeedLimit);
		
		UsersInfoHashMap.put(Id, newUser);
		UserBandwidthHashMap.put(Id, (long) 0);
		PortBandWidthHashMap.put(Port, (long) 0);
		
		try {
	         BufferedWriter FileOutPutWriter = new BufferedWriter(new FileWriter("/tmp/ssshell/"+Id+".conf"));
	         FileOutPutWriter.write("{\"server\":\""+Node_IP+"\",\"server_port\":"+Port+",\"local_port\":1080,\"password\":\""+Passwd+"\",\"timeout\":60,\"method\":\""+Method+"\"}");
	         FileOutPutWriter.close();
		} catch (IOException e) {
			System.err.println("Exception: " + e.getMessage()+e.getStackTrace().toString()+e.getLocalizedMessage()+e.getCause());
		}
		
		Exec("chmod 600 /tmp/ssshell/"+Id+".conf",false);
		
		Exec("ss-server -c /tmp/ssshell/"+Id+".conf -f /tmp/ssshell/"+Id+".pid -u -s "+Node_IP,true);

		UserPortList.add(Port);
		
		if(SpeedLimit != 0)
		{
			AddSpeedLimit(String.valueOf(Port),String.valueOf(SpeedLimit));
		}
		
	}
	
	public static String getIpAddress(byte[] rawBytes) {
        int i = 4;
        String ipAddress = "";
        for (byte raw : rawBytes)
        {
            ipAddress += (raw & 0xFF);
            if (--i > 0)
            {
                ipAddress += ".";
            }
        }

        return ipAddress;
    }
	
	
	public static String TimeStamp2Date(String timestampString, String formats){ 
	  Long timestamp = Long.parseLong(timestampString)*1000; 
	  String date = new java.text.SimpleDateFormat(formats).format(new java.util.Date(timestamp)); 
	  return date; 
	}
}
