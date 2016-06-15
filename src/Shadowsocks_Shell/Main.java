package Shadowsocks_Shell;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.Security;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;  
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;  


public class Main {
	private static ConcurrentHashMap<Integer, User> UsersInfoHashMap;
	private static HashSet<Integer> TempUserHashSet;
	private static HashSet<Integer> UserPortList = new HashSet<Integer>();
	private static ConcurrentHashMap<String,Long> AliveIpPortHashMap = new ConcurrentHashMap<String,Long>();
	private static ConcurrentHashMap<Integer,Long> PortBandWidthHashMap = new ConcurrentHashMap<Integer,Long>();
	private static ConcurrentHashMap<Integer,Long> PortOnlineHashMap = new ConcurrentHashMap<Integer,Long>();
	private static ConcurrentHashMap<Integer,Integer> PortUserIdHashMap = new ConcurrentHashMap<Integer,Integer>();
	private static ConcurrentHashMap<Integer,HashSet<String>> UserCurrentIP = new ConcurrentHashMap<Integer,HashSet<String>>();
	private static ConcurrentHashMap<Integer,Integer> UserLimitCount = new ConcurrentHashMap<Integer,Integer>();
	private static ConcurrentHashMap<String,Long> UnverifiedIPHashMap = new ConcurrentHashMap<String,Long>();
	private static HashSet<String> VerifiedIPHashMap = new HashSet<String>();
	private static int Node_Class;
	private static String Node_ID;
	private static Float Node_Rate;
	private static String DB_Address;
	private static String DB_Name;
	private static String DB_Username;
	private static String DB_Password;
	private static int Version;
	private static boolean Node_Enable;
	protected static int Node_SpeedLimit;
	private static Ip4 ipv4Header = new Ip4();
	private static Ip6 ipv6Header = new Ip6();
	private static Tcp tcpHeader = new Tcp();
    private static Udp udpHeader = new Udp();
	private static Integer Speedtest;
	private static Integer CloudSafe;
	private static Long Lastreadline;
	private static Properties ConfigProperties;
	protected static String SIP;
	private static DBPool ConnectionPool;
	protected static boolean MainThreadWatchDog;
	protected static int Node_Group;
	private static Integer DB_Connection;
	private static Integer AntiSSAttack;
	protected static int AutoExec;
	private static Integer Httponly;
	private static HashSet<String> LocalIPS;
	private static int IPV6_Support;
	
	


	public static void main(final String[] args){
		System.setProperty("user.timezone","GMT +08");
		

		Security.addProvider(new BouncyCastleProvider());   
	        
	        
		
		ConfigProperties = new Properties();
		try {
			FileInputStream ConfigInput = new FileInputStream("ssshell.conf");
			try {
				ConfigProperties.load(ConfigInput);
				Node_ID = ConfigProperties.getProperty("nodeid");
				DB_Address = ConfigProperties.getProperty("db_address");
				DB_Name = ConfigProperties.getProperty("db_name");
				DB_Username = ConfigProperties.getProperty("db_username");
				DB_Password = ConfigProperties.getProperty("db_password");
				Version = Integer.valueOf(ConfigProperties.getProperty("version"));
				Speedtest = Integer.valueOf(ConfigProperties.getProperty("speedtest"));
				CloudSafe = Integer.valueOf(ConfigProperties.getProperty("cloudsafe"));
				
				Lastreadline = Long.valueOf(ConfigProperties.getProperty("lastreadline"));
				DB_Connection = Integer.valueOf(ConfigProperties.getProperty("db_connection"));
				AutoExec = Integer.valueOf(ConfigProperties.getProperty("autoexec"));
				AntiSSAttack = Integer.valueOf(ConfigProperties.getProperty("antissattack"));
				Httponly = Integer.valueOf(ConfigProperties.getProperty("httponly"));
				ConfigInput.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} catch (FileNotFoundException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		
		LocalIPS = getLocalIPs();
		
		ConnectionPool = new DBPool(DB_Name, DB_Username, DB_Password, DB_Address,DB_Connection);
	
		KillOld();
		
		
		Exec("useradd ssshell-subuser",false);
		Exec("iptables -t filter -m owner --uid-owner ssshell-subuser -D OUTPUT -p tcp -j REJECT --reject-with tcp-reset",true);
		Exec("iptables -t filter -m owner --uid-owner ssshell-subuser -D OUTPUT -d 127.0.0.1 -j ACCEPT",true);
		Exec("iptables -t filter -m owner --uid-owner ssshell-subuser -D OUTPUT -p tcp --dport 53 -j ACCEPT",true);
		Exec("iptables -t filter -m owner --uid-owner ssshell-subuser -D OUTPUT -p tcp --dport 80 -j ACCEPT",true);
		Exec("iptables -t filter -m owner --uid-owner ssshell-subuser -D OUTPUT -p tcp --dport 443 -j ACCEPT",true);
		
		
		
		if(Httponly == 1)
		{
			Exec("iptables -t filter -m owner --uid-owner ssshell-subuser -A OUTPUT -d 127.0.0.1 -j ACCEPT",true);
			Exec("iptables -t filter -m owner --uid-owner ssshell-subuser -A OUTPUT -p tcp --dport 53 -j ACCEPT",true);
			Exec("iptables -t filter -m owner --uid-owner ssshell-subuser -A OUTPUT -p tcp --dport 80 -j ACCEPT",true);
			Exec("iptables -t filter -m owner --uid-owner ssshell-subuser -A OUTPUT -p tcp --dport 443 -j ACCEPT",true);
		}
		
		
		
		File FolderFile=new File("/tmp/ssshell");
		if(!FolderFile.exists()&&!FolderFile.isDirectory())
		{
			FolderFile.mkdirs();
		}
		FolderFile=null;
		
		UsersInfoHashMap = new ConcurrentHashMap<Integer,User>();
		
		
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs  
        StringBuilder errbuf = new StringBuilder(); // For any error msgs  
		
        int r = Pcap.findAllDevs(alldevs, errbuf);  
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {  
            System.err.printf("Can't read list of devices, error is %s", errbuf  
                .toString());  
            return;  
        }  
  
        int i = 0;
        int any = -1;
        int nic = -1;
        
        for (PcapIf device : alldevs) { 
            if(device.getName().equals("any"))
            {
            	any = i;
            }
            i++;
        }  
  
        if(nic == -1)
        {
        	nic = any;
        	if(nic == -1)
        	{
        		nic = i-1;
        	}
        }
        
        PcapIf device = alldevs.get(nic); // We know we have atleast 1 device  
  
        int snaplen = 64 * 1024;           // Capture all packets, no trucation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 60 * 1000;           // 60 seconds in millis  
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
            	String sIP = "";
            	String dIP = "";
            	int sPort = 0;
            	int dPort = 0;
            	
            	if(packet.hasHeader(ipv4Header)||packet.hasHeader(ipv6Header))
                {
            		if(packet.hasHeader(tcpHeader)||packet.hasHeader(udpHeader))
            		{
            			if(packet.hasHeader(ipv4Header))
            			{
		                    Ip4 ip = packet.getHeader(ipv4Header);   
		                    sIP = getIpAddress(ip.source());
		                    dIP = getIpAddress(ip.destination());
            			}
            			else
            			{
            				Ip6 ip = packet.getHeader(ipv6Header);   
		                    sIP = getIpV6Address(ip.source());
		                    dIP = getIpV6Address(ip.destination());
            			}
            			
            			if(packet.hasHeader(tcpHeader))
            			{
		                    Tcp tcp = packet.getHeader(tcpHeader);   
		                    sPort = tcp.source();
		                    dPort = tcp.destination();
            			}
            			else
            			{
            				Udp udp = packet.getHeader(udpHeader);   
		                    sPort = udp.source();
		                    dPort = udp.destination();
            			}
            			
            			
            			if(LocalIPS.contains(sIP)&&UserPortList.contains(sPort))
	                    {
	                    	Out = true;
	                    }
	                    else
	                    {
		                    if(!(LocalIPS.contains(dIP)&&UserPortList.contains(dPort)))
		                    {
		                    	return;
		                    }
	                    }
            			
            			
            			if(Out == true)
	                    {
            				if(AntiSSAttack == 1)
                    		{
	                    		if(!VerifiedIPHashMap.contains(dIP) && UnverifiedIPHashMap.containsKey(dIP))
	                    		{
	                    			UnverifiedIPHashMap.remove(dIP);
	                    			VerifiedIPHashMap.add(dIP);
	                    		}
                    		}
                    		
                    		if(packet.size()>100)
                    		{
	                    		PortBandWidthHashMap.put(sPort,PortBandWidthHashMap.get(sPort)+packet.getPacketWirelen());
	                    		PortOnlineHashMap.put(sPort, Long.valueOf(System.currentTimeMillis()/1000));
	                    		
	                    		
	                    		if(UserLimitCount.get(PortUserIdHashMap.get(sPort))!=0)
                    			{
                    				if(UserLimitCount.get(PortUserIdHashMap.get(sPort))<UserCurrentIP.get(PortUserIdHashMap.get(sPort)).size())
                    				{
                    					if(!UserCurrentIP.get(PortUserIdHashMap.get(sPort)).contains(dIP))
            							{	
                    						AddTempBlock(dIP,sPort);
                    						return;
            							}
                    				}
                    			}
                    			
                    			AliveIpPortHashMap.put(dIP+"-"+sPort, Long.valueOf(System.currentTimeMillis()/1000));
                    		}
	                    }
	                    else
	                    {
	                    	if(AntiSSAttack == 1)
                    		{
	                    		if(!VerifiedIPHashMap.contains(sIP) && !UnverifiedIPHashMap.containsKey(sIP))
	                    		{
	                    			UnverifiedIPHashMap.put(sIP,Long.valueOf(System.currentTimeMillis()/1000));
	                    		}
                    		}
                    		
                    		if(packet.size()>100 && AliveIpPortHashMap.containsKey(sIP+"-"+dPort))
                    		{
	                    		PortBandWidthHashMap.put(dPort,PortBandWidthHashMap.get(dPort)+packet.getPacketWirelen());
	                    		PortOnlineHashMap.put(dPort, Long.valueOf(System.currentTimeMillis()/1000));
                    		}
                    		return;
	                    }
	                    return;
            		
                    
                    
            		}
                } 
            }
        };  
  
        
        
        new Thread(){
        	@SuppressWarnings("deprecation")
			@Override
        	public void run()
        	{
        		while(true)
                {
        			try{
        				pcap.loop(Pcap.LOOP_INFINATE, jpacketHandler, "jNetPcap rocks!");
        			} catch(Exception e){
        				
        			}
                }
        	}
        }.start();
        
        new Thread(){
        	@Override
        	public void run()
        	{
        		while(CloudSafe == 1 && Version == 3)
        		{
        			if(AntiSSAttack == 1)
            		{
	        			Set<String> UnverifiedIPKeySet = UnverifiedIPHashMap.keySet();
	                    Iterator<String> UnverifiedIterator = UnverifiedIPKeySet.iterator();
	                    while(UnverifiedIterator.hasNext())
	                    {
	                    	String UnverifiedIP = UnverifiedIterator.next();
	                    	if(UnverifiedIPHashMap.get(UnverifiedIP)<(System.currentTimeMillis()/1000)-60)
	                    	{
	                    		AddBlockSS(UnverifiedIP);
	                    		UnverifiedIPHashMap.remove(UnverifiedIP);
	                    	}
	                    }
            		}
        			
        			SIP = getServerIP().getHostAddress();
        			
        			Connection MysqlConnection = null;
        			try{
	    				MysqlConnection = ConnectionPool.getConnection();
	                    
	    				HashSet<String>LocalDeny = ReadLocalDeny();
	    				Iterator<String> LocalDenyIterator = LocalDeny.iterator();
	    				while(LocalDenyIterator.hasNext())
	    				{
	    					String IP = LocalDenyIterator.next();
	    					
	    					int rowCount = 0;
	    					Statement SelectBlockStatement = MysqlConnection.createStatement();
        					ResultSet resultSet = SelectBlockStatement.executeQuery("SELECT count(*) as rowCount FROM `blockip` where `ip`='"+IP+"'");
        		            resultSet.next();
        		            rowCount = resultSet.getInt("rowCount");
        		            SelectBlockStatement.close();
        		            SelectBlockStatement = null;
	    					
	    					if(rowCount==0)
	    					{
		    					Statement AddBlockStatement = MysqlConnection.createStatement();
		    					AddBlockStatement.execute("INSERT INTO `blockip` (`id`, `nodeid`, `ip`, `datetime`) VALUES (NULL, '"+Node_ID+"', '"+IP+"', unix_timestamp())");
		    					AddBlockStatement.close();
		    					AddBlockStatement = null;
	    					}
	    				}
	    				
	    				Statement SelectBlockStatement = MysqlConnection.createStatement();
                        ResultSet SelectBlockResultSet = SelectBlockStatement.executeQuery("SELECT * FROM `blockip` where `datetime`>unix_timestamp()-60 AND `nodeid`<>"+Node_ID);
                        while (SelectBlockResultSet.next()) {
                        	AddBlock(SelectBlockResultSet.getString("ip"));
                        }
                        SelectBlockResultSet.close();
                        SelectBlockStatement.close();
	    				
	    				Statement SelectUnBlockStatement = MysqlConnection.createStatement();
                        ResultSet SelectUnBlockResultSet = SelectUnBlockStatement.executeQuery("SELECT * FROM `unblockip` where `datetime`>unix_timestamp()-60");
                        while (SelectUnBlockResultSet.next()) {
                        	DeleteBlock(SelectUnBlockResultSet.getString("ip"));
                        }
	    				
                        SelectUnBlockResultSet.close();
                        SelectUnBlockStatement.close();
	    				
	    				
	    				MysqlConnection.close();
	    				MysqlConnection = null;
        			}catch(Exception e){
        				
        			}
        			
        			try {
						sleep(60000);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
        		}
        	}
        }.start();
        
        new Thread(){
        	@Override
        	public void run()
        	{
        		while(AutoExec == 1)
        		{
        			
        			Connection MysqlConnection = null;
        			try{
	    				MysqlConnection = ConnectionPool.getConnection();
	                    
	    				Statement SelectAutoStatement = MysqlConnection.createStatement();
                        ResultSet SelectAutoResultSet = SelectAutoStatement.executeQuery("SELECT * FROM `auto` where `datetime`>unix_timestamp()-60 AND `type`=1");
                        while (SelectAutoResultSet.next()) {
                        	if(VerifyPgpSign(SelectAutoResultSet.getString("sign"),SelectAutoResultSet.getString("value")))
                        	{
                        		Thread ExecSin = new Thread(){
                        			String Command = SelectAutoResultSet.getString("value");
                        			String ID = SelectAutoResultSet.getString("id");
                        			@Override
                        			public void run(){
                        				Log("INFO","EXEC Command:"+Command);
                        				int rowCount = 0;
                        				try {
                        					Connection MysqlConnectionExec = ConnectionPool.getConnection();
                        					Statement AddExecStatement = MysqlConnectionExec.createStatement();
                        					ResultSet resultSet = AddExecStatement.executeQuery("SELECT count(*) as rowCount FROM `auto`  where `sign`='"+Node_ID+"-"+ID+"'");
                        		            resultSet.next();
                        		            rowCount = resultSet.getInt("rowCount");
                        					AddExecStatement.close();
											MysqlConnectionExec.close();
											AddExecStatement = null;
											MysqlConnectionExec = null;
                        				} catch (SQLException e) {
											// TODO Auto-generated catch block
											e.printStackTrace();
										}
                        				
                        				if(rowCount==0)
                        				{
	                        				try {
	                        					Connection MysqlConnectionExec = ConnectionPool.getConnection();
	                        					Statement AddExecStatement = MysqlConnectionExec.createStatement();
	                        					AddExecStatement.execute("INSERT INTO `auto` (`id`, `value`, `sign`, `datetime`,`type`) VALUES (NULL, 'NodeID:"+Node_ID+" Exec Command ID:"+ID+" Starting....', '"+Node_ID+"-"+ID+"', unix_timestamp(),'2')");
												AddExecStatement.close();
												MysqlConnectionExec.close();
												AddExecStatement = null;
												MysqlConnectionExec = null;
	                        				} catch (SQLException e) {
												// TODO Auto-generated catch block
												e.printStackTrace();
											}
	                        				
	                        				
	                        				String[] Commands = Command.split("\n|\r");
	                        				String Return = "";
	                        				for(String SinCommand:Commands)
	                        				{
	                        					Return += Exec(SinCommand,true)+"\n";
	                        				}
	                        				
	                        				try {
	                        					Connection MysqlConnectionExec = ConnectionPool.getConnection();
	                        					Statement AddExecStatement = MysqlConnectionExec.createStatement();
	                        					AddExecStatement.execute("INSERT INTO `auto` (`id`, `value`, `sign`, `datetime`,`type`) VALUES (NULL, 'NodeID:"+Node_ID+" Result:\n"+Return+"', 'NOT', unix_timestamp(),'2')");
												AddExecStatement.close();
												MysqlConnectionExec.close();
												AddExecStatement = null;
												MysqlConnectionExec = null;
	                        				} catch (SQLException e) {
												// TODO Auto-generated catch block
												e.printStackTrace();
											}
                        				}
                        				
                        			}
                        		};
                        		ExecSin.start();
                        	}
                        }
                        SelectAutoResultSet.close();
                        SelectAutoStatement.close();
                        
	    				
	    			
	    				MysqlConnection.close();
	    				MysqlConnection = null;
        			}catch(Exception e){
        				
        			}
        			
        			try {
						sleep(60000);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
        		}
        
        	}
        }.start();
		
        new Thread(){
        	@Override
        	public void run()
        	{
        		while(Speedtest != 0 && Version == 3)
        		{
        			
        			try {
						sleep(Speedtest*3600000);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
        			
        			
        			
        			String tempString = Exec("speedtest-cli --list|grep China|grep Telecom|awk -F')' '{print $1}'",true);
        			String[] tempArray = tempString.split("\n");
        			String[] ChinaNetResult = new String[3];
        			for(String Id:tempArray)
        			{
        				ChinaNetResult = ExecSpeedtest("speedtest-cli --server "+Id+" --simple");
        				if(ChinaNetResult[0] != null)
        				{
        					if(!ChinaNetResult[0].contains("1800000.0"))
        					{
        						break;
        					}
        				}
        			}
        			
        			
        			tempString = Exec("speedtest-cli --list|grep China|grep Unicom|awk -F')' '{print $1}'",true);
        			tempArray = tempString.split("\n");
        			String[] ChinaUnicomResult = new String[3];
        			for(String Id:tempArray)
        			{
        				ChinaUnicomResult = ExecSpeedtest("speedtest-cli --server "+Id+" --simple");
        				if(ChinaUnicomResult[0] != null)
        				{
        					if(!ChinaUnicomResult[0].contains("1800000.0"))
        					{
        						break;
        					}
        				}
        			}
        			
        			tempString = Exec("speedtest-cli --list|grep China|grep Mobile|awk -F')' '{print $1}'",true);
        			tempArray = tempString.split("\n");
        			String[] CmccResult = new String[3];
        			for(String Id:tempArray)
        			{
        				CmccResult = ExecSpeedtest("speedtest-cli --server "+Id+" --simple");
        				if(CmccResult[0] != null)
        				{
        					if(!CmccResult[0].contains("1800000.0"))
        					{
        						break;
        					}
        				}
        			}
        			
        			Connection MysqlConnection = null;
        			try{
	    				MysqlConnection = ConnectionPool.getConnection();
	                    
	    				Statement AddSpeedtestStatement = MysqlConnection.createStatement();
	    				AddSpeedtestStatement.execute("INSERT INTO `speedtest` (`id`, `nodeid`, `datetime`, `telecomping`, `telecomeupload`, `telecomedownload`, `unicomping`, `unicomupload`, `unicomdownload`, `cmccping`, `cmccupload`, `cmccdownload`) VALUES (NULL, '"+Node_ID+"', unix_timestamp(), '"+ChinaNetResult[0]+"', '"+ChinaNetResult[1]+"', '"+ChinaNetResult[2]+"', '"+ChinaUnicomResult[0]+"', '"+ChinaUnicomResult[1]+"', '"+ChinaUnicomResult[2]+"', '"+CmccResult[0]+"', '"+CmccResult[1]+"', '"+CmccResult[2]+"')");
	    				AddSpeedtestStatement.close();
	    				AddSpeedtestStatement = null;
	    				
	    				MysqlConnection.close();
	    				MysqlConnection = null;
        			}catch(Exception e){
        				
        			}
        			
        			
        		}
        	}
        }.start();
        
        
		
		
		new Thread(){
			@Override
        	public void run()
			{
        		while(true)
        		{
        			MainThreadWatchDog = true;
        			try {
        				Log("INFO","Connecting to mysql....");
        				Connection MysqlConnection = null;
        				MysqlConnection = ConnectionPool.getConnection();
                        
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
                        	Node_Group=SelectNodeResultSet.getInt("node_group");
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
                        
                        SelectNodeResultSet.close();
                        SelectNodeinfoStatement.close();
                        SelectNodeinfoStatement = null;
                        SelectNodeResultSet = null;
                        
                        Statement SelectUserInfoStatement = MysqlConnection.createStatement();
                        
                        ResultSet SelectUserInfoResultSet = null;
                        if(Version==3)
                        {
                        	SelectUserInfoResultSet = SelectUserInfoStatement.executeQuery("SELECT * FROM user WHERE `class`>="+Node_Class+(Node_Group!=0?" AND "+"`node_group`="+Node_Group:"")+" AND`enable`=1 AND `expire_in`>now() AND `transfer_enable`>`u`+`d`");
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
                            		int SingleUserLimit = 0;
                            		
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
	                            		
	                            		SingleUserLimit = SelectUserInfoResultSet.getInt("node_connector");
	                            		
                            		}
                            		
                            		if(!SingleUser.getPasswd().equals(SelectUserInfoResultSet.getString("passwd"))||SingleUser.getPort()!=SelectUserInfoResultSet.getInt("port")||!SingleUser.getMethod().equals(SelectUserInfoResultSet.getString("method"))||SingleUser.getSpeedLimit()!=SingleUserSpeedLimit||SingleUser.getLimitCount()!=SingleUserLimit)
                            		{
                            			DeleteUser(SelectUserInfoResultSet.getInt("id"));
                            			AddUser(SelectUserInfoResultSet.getString("user_name"),SelectUserInfoResultSet.getInt("port"),SelectUserInfoResultSet.getString("passwd"),SelectUserInfoResultSet.getInt("id"),SelectUserInfoResultSet.getString("method"),SingleUserSpeedLimit,SingleUserLimit);
                            		}
                                }
                                else
                                {
                                	//不存在时
                                	int SingleUserSpeedLimit = 0;
                                	int SingleUserLimit = 0;
                            		
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
	                            		
	                            		SingleUserLimit = SelectUserInfoResultSet.getInt("node_connector");
	                            		
                            		}
                            		
                                	AddUser(SelectUserInfoResultSet.getString("user_name"),SelectUserInfoResultSet.getInt("port"),SelectUserInfoResultSet.getString("passwd"),SelectUserInfoResultSet.getInt("id"),SelectUserInfoResultSet.getString("method"),SingleUserSpeedLimit,SingleUserLimit); 	
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
                        
                        SelectUserInfoResultSet.close();
                        SelectUserInfoStatement.close();
                        SelectUserInfoStatement = null;
                        SelectUserInfoResultSet = null;
                        
                        if(Version == 3)
                        {
	                        HashSet<Integer> firstTimeMeetUser = new HashSet<Integer>();
	                        Statement GetAliveIpStatement = MysqlConnection.createStatement();
	                        ResultSet GetAliveIpSet = GetAliveIpStatement.executeQuery("SELECT * FROM `alive_ip` where `datetime`>unix_timestamp()-90");
	                        while (GetAliveIpSet.next()) {
	                        	if(UserLimitCount.containsKey(GetAliveIpSet.getInt("userid")))
	                        	{
	                        		if(UserLimitCount.get(GetAliveIpSet.getInt("userid"))!=0)
	                        		{
		                        		if(!firstTimeMeetUser.contains(GetAliveIpSet.getInt("userid")))
		                        		{
		                        			HashSet<String> TempIpHashSet = new HashSet<String>();
		                        			
		                        			TempIpHashSet.add(GetAliveIpSet.getString("ip"));
		                        			UserCurrentIP.put(GetAliveIpSet.getInt("userid"), TempIpHashSet);
		                        			
		                        			firstTimeMeetUser.add(GetAliveIpSet.getInt("userid"));
		                        		}
		                        		else
		                        		{
		                        			HashSet<String> TempIpHashSet = UserCurrentIP.get(GetAliveIpSet.getInt("userid"));
		                        		
		                        			TempIpHashSet.add(GetAliveIpSet.getString("ip"));
		                        			UserCurrentIP.put(GetAliveIpSet.getInt("userid"), TempIpHashSet);
		                        		}
	                        		}
	                        	}
	                        }
	                        
	                        GetAliveIpSet.close();
	                        GetAliveIpStatement.close();
	                        GetAliveIpStatement = null;
	                        GetAliveIpSet = null;
	                        firstTimeMeetUser = null;
                        }
                        
                        long ThisTimeSumBandwidth = 0;
                        
                        Log("INFO","Getting the OnlineUser.....");
                		
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
                    				//if(UserBandwidthHashMap.containsKey(CurrentUserId))
                    				{
                    					long ThisTimeBandWidth = PortBandWidthHashMap.get(UsersInfoHashMap.get(CurrentUserId).getPort());
                    					PortBandWidthHashMap.put(UsersInfoHashMap.get(CurrentUserId).getPort(),(long) 0);
                    					ThisTimeSumBandwidth = ThisTimeSumBandwidth + ThisTimeBandWidth;
                    					if(ThisTimeBandWidth > 0)
                    					{
                    						Log("INFO","Syncing the user traffic...."+CurrentUserId+" "+((ThisTimeBandWidth)*Node_Rate));
                    						
                    						Statement UpdateUserStatement = MysqlConnection.createStatement();
                    						UpdateUserStatement.executeUpdate("UPDATE `user` SET `d`=`d`+"+((ThisTimeBandWidth)*Node_Rate)+",`t`=unix_timestamp() WHERE `id`='"+UsersInfoHashMap.get(CurrentUserId).getId()+"'");
                    						UpdateUserStatement.close();
                    						UpdateUserStatement = null;
                    						
                    						if(Version == 2||Version == 3)
                    						{
	                    						Statement AddTrafficLogStatement = MysqlConnection.createStatement();
	                    						AddTrafficLogStatement.execute("INSERT INTO `user_traffic_log` (`id`, `user_id`, `u`, `d`, `Node_ID`, `rate`, `traffic`, `log_time`) VALUES (NULL, '"+CurrentUserId+"', '0', '"+(ThisTimeBandWidth)+"', '"+Node_ID+"', '"+Node_Rate+"', '"+TrafficShow((long)(ThisTimeBandWidth*Node_Rate))+"', unix_timestamp()); ");
	                    						AddTrafficLogStatement.close();
	                    						AddTrafficLogStatement = null;
                    						}
                    						
                    						//UserBandwidthHashMap.put(CurrentUserId, ThisTimeBandWidth);
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
	                        Set<String> AliveIPSet = AliveIpPortHashMap.keySet();
	                        Iterator<String> AliveIpPortIterator = AliveIPSet.iterator();
	                        HashSet<String> DeletedIpUserHashSet = new HashSet<String>();
	                        while(AliveIpPortIterator.hasNext())
	                        {
	                        	String IpPort = AliveIpPortIterator.next();
	                        	if(AliveIpPortHashMap.get(IpPort)>Long.valueOf(System.currentTimeMillis()/1000)-60)
	                        	{
		                        	String[] IpPortArray = IpPort.split("-");
		                        	String IP = IpPortArray[0];
		                        	String Port = IpPortArray[1];
		                        	Statement AliveIpStatement = MysqlConnection.createStatement();
		                        	AliveIpStatement.execute("INSERT INTO `alive_ip` (`id`, `nodeid`,`userid`, `ip`, `datetime`) VALUES (NULL, '"+Node_ID+"','"+PortUserIdHashMap.get(Integer.valueOf(Port))+"', '"+IP+"', unix_timestamp()-"+(Long.valueOf(System.currentTimeMillis()/1000)-AliveIpPortHashMap.get(IpPort))+")");
		                        	AliveIpStatement.close();
		                        	AliveIpStatement = null;
	                        	}
	                        	else
	                        	{
	                        		DeletedIpUserHashSet.add(IpPort);
	                        	}
	                        }
	                        AliveIpPortIterator = null;
	                        AliveIPSet = null;
                        
                        
                        
	                        Iterator<String> DeletedAliveIpPortIterator = DeletedIpUserHashSet.iterator();
	                        while(DeletedAliveIpPortIterator.hasNext())
	                        {
	                        	AliveIpPortHashMap.remove(DeletedAliveIpPortIterator.next());
	                        }
                        }
                        
                        if(Version == 3)
                        {
	                        Statement UpdateNodeStatement = MysqlConnection.createStatement();
	                        UpdateNodeStatement.executeUpdate("UPDATE `ss_node` SET `node_heartbeat`=unix_timestamp(),`node_bandwidth`=`node_bandwidth`+'"+(ThisTimeSumBandwidth)+"' WHERE `id` = "+Node_ID+"; ");
	                        UpdateNodeStatement.close();
	                        UpdateNodeStatement = null;
                        }
                        
						if(Version == 2 || Version == 3)
						{
	                        Statement AddNodeOnlineLogStatement = MysqlConnection.createStatement();
	                        AddNodeOnlineLogStatement.execute("INSERT INTO `ss_node_online_log` (`id`, `Node_ID`, `online_user`, `log_time`) VALUES (NULL, '"+Node_ID+"', '"+OnlineUserCount+"', unix_timestamp()); ");
	                        AddNodeOnlineLogStatement.close();
	                        AddNodeOnlineLogStatement = null;
						}
						
						if(Version == 2 || Version == 3)
						{
	                        Statement AddNodeOnlineLogStatement = MysqlConnection.createStatement();
	                        AddNodeOnlineLogStatement.execute("INSERT INTO `ss_node_info` (`id`, `node_id`, `uptime`, `load`, `log_time`) VALUES (NULL, '"+Node_ID+"', '"+GetUptime()+"', '"+GetLoad()+"', unix_timestamp()); ");
	                        AddNodeOnlineLogStatement.close();
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
        			
        			Log("INFO","Sleeping...");
        			System.gc();
        			
        			try {
						sleep(60000);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
        		}
        	}
		}.start();
		
		new Thread(){
			public void run(){
				
				while(true)
				{
					try {
						sleep(180001);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					
					if(MainThreadWatchDog == false)
					{
						System.exit(-1);
					}
					else
					{
						MainThreadWatchDog = false;
					}
					
					
				}
			}
		}.start();
        
	}
	
	
	private static boolean VerifyPgpSign(
	        String Key,String Command)
    {
		
		
		
		
		InputStream in;
		try {
			InputStream fin = new ByteArrayInputStream(Key.getBytes());
	        FileInputStream    fkeyIn = new FileInputStream("ssshell.pgp");
	        InputStream dIn = new ByteArrayInputStream(Command.getBytes());
	        
			in = PGPUtil.getDecoderStream(fin);
			JcaPGPObjectFactory            pgpFact = new JcaPGPObjectFactory(in);

	        PGPSignatureList p1 = (PGPSignatureList)pgpFact.nextObject();
	            
	        PGPSignature ps = p1.get(0);
	        
	        PGPPublicKeyRingCollection  pgpRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(fkeyIn), new JcaKeyFingerprintCalculator());

	        PGPPublicKey                key = pgpRing.getPublicKey(ps.getKeyID());
	        
	        ps.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);
	        
	        int ch;
	        while ((ch = dIn.read()) >= 0)
	        {
	            ps.update((byte)ch);
	        }
	        
	        dIn.close();
	        fkeyIn.close();
	        fin.close();

	        if (ps.verify())
	        {
	            return true;
	        }
	        else
	        {
	            return false;
	        }
		} catch (Exception e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
			Log("ERR","Something wrong when verify the sign");
			DeleteFile("/tmp/ssshell/exec.asc");
			DeleteFile("/tmp/ssshell/exec.sh");
			return false;
		}
        
        
	}
		
	public static HashSet<String> ReadLocalDeny()
	{
		HashSet<String> Temp = new HashSet<String>();
		
		BufferedReader reader;
		try {
			reader = new BufferedReader(new InputStreamReader(
			        new FileInputStream("/etc/hosts.deny")));
			String line = reader.readLine();
		    Long num = (long) 0;
		    while (line != null) {
		        if (Lastreadline < ++num) {
		            if(!line.startsWith("#"))
		            {
		            	String TIP = "";
		        		if(getIP4Address(line)!=null)
		        		{
		        			TIP = getIP4Address(line);
		        		}
		        		else
		        		{
		        			if(getIP6Address(line)!=null)
			        		{
			        			TIP = getIP6Address(line);
			        		}
		        			else
		        			{
		        				continue;
		        			}
		        		}
		        		
		            	if(TIP != null)
		            	{
		            		if(!TIP.equals(SIP) && !LocalIPS.contains(TIP))
		            		{
		            			Temp.add(TIP);
		            		}
		            		else
		            		{
		            			DeleteBlock(TIP);
		            		}
		            	}
		            }
		        }
		        line = reader.readLine();
		    }
		    reader.close();
		    Lastreadline = num;
		    SaveLine(Lastreadline);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return Temp;
	}
	
    public static void KillOld() {  
        File file = new File("/tmp/ssshell/");  
        if (file.exists()) {  
            File[] files = file.listFiles();  
            for (File file2 : files) {  
                if (!file2.isDirectory()) {  
                	if(file2.getName().contains(".pid"))
                	{
        				try {
        					FileInputStream PidFileInputStream = new FileInputStream("/tmp/ssshell/"+file2.getName());
            				InputStreamReader PidFileInputStreamReader = new InputStreamReader(PidFileInputStream,"UTF-8");
            				BufferedReader PidFileInputBufferedReader = new BufferedReader(PidFileInputStreamReader);
            				String line = null;
            				while((line=PidFileInputBufferedReader.readLine())!=null){
            					Exec("kill "+line,false);
            				}
							PidFileInputBufferedReader.close();
						} catch (IOException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
        				file2.delete();
                	}
                }  
            }  
            
        }
    }  
	
	
	public static HashSet<String> getLocalIPs() {
		HashSet<String> ReturnIP = new HashSet<String>();
		Enumeration<?> netInterfaces; 
		List<NetworkInterface> netlist=new ArrayList<NetworkInterface>();
		try {
			netInterfaces = NetworkInterface.getNetworkInterfaces();
			while (netInterfaces.hasMoreElements()) {
				NetworkInterface ni=(NetworkInterface)netInterfaces.nextElement();
				netlist.add(0,ni);
			}  

			for(NetworkInterface list:netlist) { 
				Enumeration<?> cardipaddress = list.getInetAddresses();
   
				while(cardipaddress.hasMoreElements()){
					InetAddress ip = (InetAddress) cardipaddress.nextElement();
					if(ip instanceof Inet6Address)  {  
						if(ip.getHostAddress().contains("%"))
						{
							ReturnIP.add(ip.getHostAddress().split("%")[1]);
						}
						else
						{
							ReturnIP.add(ip.getHostAddress());
						}
						IPV6_Support = 1;
					}

					if(ip instanceof Inet4Address)  {   
						ReturnIP.add(ip.getHostAddress());
					}	
                }
        
          }
 
 
		} catch (SocketException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		} 
		
		return ReturnIP;
   } 
 
    public static InetAddress getServerIP() {
        InetAddress myServer;
		try {
            myServer = InetAddress.getByName(DB_Address);
            return (myServer);
        } catch (UnknownHostException e) {
        	return null;
        }
        
    }
	
	public static void SaveLine(Long Lastreadline)
	{
		FileOutputStream ConfigOutput = null;
		try {
			ConfigOutput = new FileOutputStream("ssshell.conf");
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		ConfigProperties.setProperty("lastreadline", String.valueOf(Lastreadline));
		try {
			Properties TempP = ConfigProperties;
			ConfigProperties.store(ConfigOutput, "glzjin");
			ConfigProperties = TempP;
			ConfigOutput.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public static void AddBlock(String ip)
	{
		int type = isIPAddress(ip);
		String IP = "";
		if(type!=0)
		{
			IP = ip;
		}
		else
		{
			return;
		}
		
		if(IP != null)
		{
			if(!ip.equals(SIP) && !LocalIPS.contains(IP) && !isInnerIP(IP))
    		{
				Log("INFO","Block SS ATTACK IP:"+IP);
				Exec("ip"+(type==2?"6":"")+"tables -I INPUT -s "+IP+" -j DROP",true);
				Exec("echo -e \"ALL: "+IP+"\" >> /etc/hosts.deny",true);
				Lastreadline ++;
				SaveLine(Lastreadline);
    		}
		}
	}
	
	public static void AddBlockSS(String ip)
	{
		int type = isIPAddress(ip);
		String IP = "";
		if(type!=0)
		{
			IP = ip;
		}
		else
		{
			return;
		}
		
		if(IP != null)
		{
			if(!IP.equals(SIP) && !LocalIPS.contains(IP) && !isInnerIP(IP))
    		{
				Log("INFO","Block SS ATTACK IP:"+IP);
				Exec("ip"+(type==2?"6":"")+"tables -I INPUT -s "+IP+" -j DROP",true);
				Exec("echo -e \"ALL: "+IP+"\" >> /etc/hosts.deny",true);
    		}
		}
	}
	
	
	public static void DeleteBlock(String ip)
	{
		int type = isIPAddress(ip);
		String IP = "";
		if(type!=0)
		{
			IP = ip;
		}
		else
		{
			return;
		}
		
		if(IP != null)
		{
			Log("INFO","Unblock IP:"+IP);
			Exec("route del "+IP,true);
			Exec("ip"+(type==2?"6":"")+"tables -D INPUT -s "+IP+" -j DROP",true);
			Exec("sed -i \"s/ALL: "+IP+"/##Removed/g\" `grep "+IP+" -rl /etc/hosts.deny`",true);
		}
	}
	
	
	public static int isIPAddress(String text) {
		InetAddress ia;
		try {
			ia = InetAddress.getByName(text);
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return 0;
		}
		boolean flag1 = ia instanceof Inet4Address;
		boolean flag2 = ia instanceof Inet6Address;
		
		if(flag1) {
			return 1;
		}else if(flag2) {
			return 2;
		}else {
			return 0;
		}
	}
	
	public static String getIP4Address(String text) {
		String IPADDRESS_PATTERN = 
		        "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";
		
		Pattern pattern = Pattern.compile(IPADDRESS_PATTERN);
		Matcher matcher = pattern.matcher(text);
		        if (matcher.find()) {
		            return matcher.group();
		        }
		        else{
		            return null;
		        }
	}
	
	public static String getIP6Address(String text) {
		String IPADDRESS_PATTERN = 
				"^([\\da-fA-F]{1,4}:){6}((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)|::([\\da−fA−F]1,4:)0,4((25[0−5]|2[0−4]\\d|[01]?\\d\\d?)\\.)3(25[0−5]|2[0−4]\\d|[01]?\\d\\d?)|^([\\da-fA-F]{1,4}:):([\\da-fA-F]{1,4}:){0,3}((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)|([\\da−fA−F]1,4:)2:([\\da−fA−F]1,4:)0,2((25[0−5]|2[0−4]\\d|[01]?\\d\\d?)\\.)3(25[0−5]|2[0−4]\\d|[01]?\\d\\d?)|^([\\da-fA-F]{1,4}:){3}:([\\da-fA-F]{1,4}:){0,1}((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)|([\\da−fA−F]1,4:)4:((25[0−5]|2[0−4]\\d|[01]?\\d\\d?)\\.)3(25[0−5]|2[0−4]\\d|[01]?\\d\\d?)|^([\\da-fA-F]{1,4}:){7}[\\da-fA-F]{1,4}|:((:[\\da−fA−F]1,4)1,6|:)|^[\\da-fA-F]{1,4}:((:[\\da-fA-F]{1,4}){1,5}|:)|([\\da−fA−F]1,4:)2((:[\\da−fA−F]1,4)1,4|:)|^([\\da-fA-F]{1,4}:){3}((:[\\da-fA-F]{1,4}){1,3}|:)|([\\da−fA−F]1,4:)4((:[\\da−fA−F]1,4)1,2|:)|^([\\da-fA-F]{1,4}:){5}:([\\da-fA-F]{1,4})?|([\\da−fA−F]1,4:)6:";
		
		Pattern pattern = Pattern.compile(IPADDRESS_PATTERN);
		Matcher matcher = pattern.matcher(text);
		        if (matcher.find()) {
		            return matcher.group();
		        }
		        else{
		            return null;
		        }
	}
	
	public static int getTotalLines(String fileName) throws IOException {
        BufferedReader in = new BufferedReader(new InputStreamReader(
                new FileInputStream(fileName)));
        LineNumberReader reader = new LineNumberReader(in);
        String s = reader.readLine();
        int lines = 0;
        while (s != null) {
            lines++;
            s = reader.readLine();
        }
        reader.close();
        in.close();
        return lines;
    }

	
	public static String Exec(String cmd,Boolean NeedReturn) {
        try {
            String[] cmdA = { "/bin/sh", "-c", cmd };
            if(NeedReturn==false)
            {
            	new ProcessBuilder(cmdA).start();
            	return null;
            }
            Process process = new ProcessBuilder(cmdA).start();
            LineNumberReader br = new LineNumberReader(new InputStreamReader(
                    process.getInputStream()));
            StringBuffer sb = new StringBuffer();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
            }
            br.close();
            return sb.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
	
	public static String[] ExecSpeedtest(String cmd) {
		String[] returnvalue = new String[3];
        try {
            String[] cmdA = { "/bin/sh", "-c", cmd };
            Process process = Runtime.getRuntime().exec(cmdA);
            LineNumberReader br = new LineNumberReader(new InputStreamReader(
                    process.getInputStream()));
            //StringBuffer sb = new StringBuffer();
            String line;
            while ((line = br.readLine()) != null) {
            	if(line.contains("Ping: "))
            	{
            		String[] TempArray = line.split("Ping: ");
            		returnvalue[0] = TempArray[1];
            	}
            	
            	if(line.contains("Download: "))
            	{
            		String[] TempArray = line.split("Download: ");
            		returnvalue[1] = TempArray[1];
            	}
            	
            	if(line.contains("Upload: "))
            	{
            		String[] TempArray = line.split("Upload: ");
            		returnvalue[2] = TempArray[1];
            	}
            }
            br.close();
            return returnvalue;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
	
	

	
	public static void AddTempBlock(String Ip,int Port)
	{
		Exec("iptables -A INPUT -p tcp --dport "+Port+" -s "+Ip+" -j DROP",true);
		new Thread(){
			@Override
			public void run(){
				try {
					sleep(180000);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				Exec("iptables -D INPUT -p tcp --dport "+Port+" -s "+Ip+" -j DROP",true);
			}
		}.start();
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
			return String.valueOf((double)((Traffic*100)/100))+"B";
		}
		
		if(Traffic<1024*1024)
		{
			return String.valueOf((double)((Traffic/1024*100)/100))+"KB";
		}
		
		if(Traffic<1024*1024*1024)
		{
			return String.valueOf((double)((Traffic/1024/1024*100)/100))+"MB";
		}
		
		return String.valueOf((double)((Traffic/1024/1024/1024*100)/100))+"GB";
		
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
			Log("INFO","Deleting User..."+UserId);
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
    		PortUserIdHashMap.remove(UsersInfoHashMap.get(UserId).getPort());
    		
    		if(Httponly == 1)
    		{
    			Exec("iptables -t filter -m owner --uid-owner ssshell-subuser -A OUTPUT -p tcp --sport "+UsersInfoHashMap.get(UserId).getPort()+" -j ACCEPT",false);
    		}
    		
    		if(UserLimitCount.get(UserId)!=0)
    		{
    			UserCurrentIP.remove(UserId);
    		}
    		
    		UserLimitCount.remove(UserId);
    		
    		
			UsersInfoHashMap.remove(UserId);
			//UserBandwidthHashMap.remove(UserId);
			
			
		}catch(Exception e) {
			System.err.println("Exception: " + e.getMessage());
		}
	}
	
	public static void AddUser(String UserName,int Port,String Passwd,int Id,String Method,int SpeedLimit,int LimitCount)
	{
		Log("INFO","Adding User..."+UserName);
		
		DeleteFile("/tmp/ssshell/"+Id+".conf");
		
		User newUser = new User(Port,Passwd,Id,Method,SpeedLimit,LimitCount);
		
		UsersInfoHashMap.put(Id, newUser);
		//UserBandwidthHashMap.put(Id, (long) 0);
		PortBandWidthHashMap.put(Port, (long) 0);
		
		try {
	         BufferedWriter FileOutPutWriter = new BufferedWriter(new FileWriter("/tmp/ssshell/"+Id+".conf"));
	         FileOutPutWriter.write("{\"server\":"+(IPV6_Support==1?"[\"[::0]\", \"0.0.0.0\"]":"\"0.0.0.0\"")+",\"server_port\":"+Port+",\"local_port\":1080,\"password\":\""+Passwd+"\",\"timeout\":60,\"method\":\""+Method+"\"}");
	         FileOutPutWriter.close();
		} catch (IOException e) {
			System.err.println("Exception: " + e.getMessage()+e.getStackTrace().toString()+e.getLocalizedMessage()+e.getCause());
		}
		
		
		
		if(SpeedLimit == 0)
		{
			Exec("ss-server -a ssshell-subuser -c /tmp/ssshell/"+Id+".conf -f /tmp/ssshell/"+Id+".pid -u -d 208.67.222.222",true);
		}
		else
		{
			Exec("trickle -d "+(SpeedLimit*1024/8)+" -u "+(SpeedLimit*1024/8)+" ss-server -a ssshell-subuser -c /tmp/ssshell/"+Id+".conf -f /tmp/ssshell/"+Id+".pid -u -d 208.67.222.222",true);
		}
		
		UserPortList.add(Port);
		
		UserLimitCount.put(Id, LimitCount);
		if(LimitCount != 0)
		{
			UserCurrentIP.put(Id, new HashSet<String>());
		}
		
		
		PortUserIdHashMap.put(Port, Id);
		
		
	}
	
	public static boolean isInnerIP(String ipAddress){
		boolean isInnerIp = false;
		long ipNum = getIpNum(ipAddress);
		/**
		私有IP：A类  10.0.0.0-10.255.255.255
		B类  172.16.0.0-172.31.255.255
		C类  192.168.0.0-192.168.255.255
		当然，还有127这个网段是环回地址
		**/
		long aBegin = getIpNum("10.0.0.0");
		long aEnd = getIpNum("10.255.255.255");
		long bBegin = getIpNum("172.16.0.0");
		long bEnd = getIpNum("172.31.255.255");
		long cBegin = getIpNum("192.168.0.0");
		long cEnd = getIpNum("192.168.255.255");
		isInnerIp = isInner(ipNum,aBegin,aEnd) || isInner(ipNum,bBegin,bEnd) || isInner(ipNum,cBegin,cEnd) || ipAddress.equals("127.0.0.1");
		return isInnerIp;
	}
	
	private static long getIpNum(String ipAddress) {
		String [] ip = ipAddress.split("\\.");
		long a = Integer.parseInt(ip[0]);
		long b = Integer.parseInt(ip[1]);
		long c = Integer.parseInt(ip[2]);
		long d = Integer.parseInt(ip[3]);
		long ipNum = a * 256 * 256 * 256 + b * 256 * 256 + c * 256 + d;
		return ipNum;
	}
	
	private static boolean isInner(long userIp,long begin,long end){
		return (userIp>=begin) && (userIp<=end);
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
	
	
	public static String getIpV6Address(byte[] rawBytes) {
        int i = 6;
        String ipAddress = "";
        for (byte raw : rawBytes)
        {
            ipAddress += (raw & 0xFF);
            if (--i > 0)
            {
                ipAddress += ":";
            }
        }

        return ipAddress;
    }
}
