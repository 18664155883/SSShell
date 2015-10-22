package Shadowsocks_Shell;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

public class Main {
	private static HashMap<String, User> usersinfo;
	private static HashSet<String> tempuserlist;
	private static HashMap<String, Long> userbandwidth;
	private static HashMap<String, Integer> connector;
	private static int node_class;
	private static String node_id;
	private static int node_speedlimit;
	private static String ip;
	private static long lastsumbandwidth=(long)0;
	private static int zeroport=65535;
	
	public static String exec(String cmd) {
        try {
            String[] cmdA = { "/bin/sh", "-c", cmd };
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

	public static void main(final String[] args){
		System.setProperty("user.timezone","GMT +08");
		ip=args[4];
		node_id=args[5];
		Runtime run = Runtime.getRuntime();
		try {
			run.exec("killall ss-server");
			run.exec("rm -rf ./ssshell/*.pid");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		File dict=new File("./ssshell");
		if(!dict.exists()&&!dict.isDirectory())
		{
			dict.mkdirs();
		}
		usersinfo=new HashMap<String,User>();
		userbandwidth=new HashMap<String,Long>();
		new Thread(){
			@Override
        	public void run(){
        		while(true)
        		{
        			try {
        				System.out.println("Connecting...");
        				Connection con = null;
        				Class.forName("com.mysql.jdbc.Driver").newInstance();
                        con = DriverManager.getConnection("jdbc:mysql://"+args[0]+"/"+args[1]+"",args[2], args[3]);
                        Statement st = con.createStatement();
                        ResultSet rs = st.executeQuery("SELECT * FROM user");
                        Statement st2 = con.createStatement();
                        ResultSet rs2 = st2.executeQuery("SELECT * FROM node where `id`='"+node_id+"'");
                        rs2.first();
                        node_class=rs2.getInt("node_class");
                        Long node_bandwidth = Long.valueOf(String.valueOf(rs2.getBigDecimal("node_bandwidth")));
                        Long node_bandwidth_limit = Long.valueOf(String.valueOf(rs2.getBigDecimal("node_bandwidth_limit")));
                        tempuserlist=new HashSet<String>();
                        HashSet<String> deleteduserlist = new HashSet<String>();
                        if(node_bandwidth_limit==0||(node_bandwidth_limit!=0&&node_bandwidth_limit<node_bandwidth))
                        {
                        	while (rs.next()) {
                            	tempuserlist.add(rs.getString("user_name"));
                            	if(usersinfo.containsKey(rs.getString("user_name")))
                                {
                                	//存在时
                                	if(rs.getBigDecimal("transfer_enable").longValue()<(rs.getBigDecimal("u").longValue()+rs.getBigDecimal("d").longValue()))
                                	{
                                		deleteuser(rs.getString("user_name"));
                                	}
                                	else
                                	{
                                		//监控端口变更和密码变更
                                		User cur=usersinfo.get(rs.getString("user_name"));
                                		if(!cur.getPasswd().equals(rs.getString("passwd"))||cur.getPort()!=rs.getInt("port"))
                                		{
                                			deleteuser(rs.getString("user_name"));
                                    		adduser(rs.getString("user_name"),rs.getInt("port"),rs.getString("passwd"),rs.getInt("uid"));
                                    		if(rs.getInt("port")<zeroport)
                                    		{
                                    			zeroport=rs.getInt("port");
                                    		}
                                		}
                                		else
                                		{
                                			String nodeclass_s=rs.getString("node_clas");
                                        	String[] u_nodeclass=nodeclass_s.split("|");
                                			if(node_class!=0&&(!isinarray(u_nodeclass,String.valueOf(node_class))))
                                			{
                                				deleteuser(rs.getString("user_name"));
                                			}
                                		}
                                	}
                                }
                                else
                                {
                                	//不存在时
                                	String nodeclass_s=rs.getString("node_clas");
                                	String[] u_nodeclass=nodeclass_s.split("|");
                                	if(rs.getBigDecimal("transfer_enable").longValue()>(rs.getBigDecimal("u").longValue()+rs.getBigDecimal("d").longValue())&&(node_class==0||(isinarray(u_nodeclass,String.valueOf(node_class)))))
                                	{
                                		adduser(rs.getString("user_name"),rs.getInt("port"),rs.getString("passwd"),rs.getInt("uid"));
                                		if(rs.getInt("port")<zeroport)
                                		{
                                			zeroport=rs.getInt("port");
                                		}
                                	}
                                }
                            }
                        }
                        else
                        {
                        	Set<String> usersset = usersinfo.keySet();
                        	Iterator<String> usersit = usersset.iterator();
                        	while(usersit.hasNext())
                            {
                        		String tempuser=usersit.next();
                        		deleteuser(tempuser);
                            }
                        }
                        
                        Set<String> usersset = usersinfo.keySet();
                        Iterator<String> usersit = usersset.iterator();
                        long sumbandwidth=0;
                        //iptables -n -v -L -t filter -x |awk -F' ' '{print $2"-"$10}'
                        String back=exec("iptables -n -v -L -t filter -x |awk -F' ' '{print $2\"-\"$10}'");
                		String[] array=back.split("\n");
                		//netstat -antp|grep 103.192.176.252|awk -F ' ' '{print $4"-"$5}'
                		String back2=exec("netstat -antp|grep "+ip+":|awk -F ' ' '{print $4\"-\"$5}'");
                		String[] array2=back2.split("\n");
                		
                		HashMap<String,Integer> pconnector=new HashMap<String,Integer>();
                		
                		for(int a=0;a<array2.length;a++)
                		{
                			String[] exps=array2[a].split("-");
                			String[] ports=exps[0].split(":");
                			String port=ports[1];
                			if(Integer.valueOf(port)>zeroport)
                			{
                				if(pconnector.containsKey(port))
                				{
                					pconnector.put(port, pconnector.get(port)+1);
                				}
                				else
                				{
                					pconnector.put(port, 1);
                				}
                			}
                		}
                		
                		HashMap<String,Long> portbandwidth=new HashMap<String,Long>();
                		for(int a=0;a<array.length;a++)
                		{
                			String[] temps=array[a].split("-");
                			String[] port=temps[2].split(":");
                			portbandwidth.put(port[1], Long.valueOf(temps[0]));
                		}
                		
                		HashSet<String> connector_list=new HashSet<String>();
                        while(usersit.hasNext())
                        {
                        	String tempuser=usersit.next();
                    		if(portbandwidth.containsKey(tempuser))
                    		{
                    			if(portbandwidth.get(tempuser)!=0)
                    			{
                    				if(userbandwidth.containsKey(tempuser))
                    				{
                    					//long bandwidth = -1;
                    					long bandwidth=Long.valueOf(array[0]);
                    					sumbandwidth=sumbandwidth+bandwidth;
                    					//System.out.println("bw:"+bandwidth+"|"+userbandwidth.get(tempuser));
                    					if(bandwidth-userbandwidth.get(tempuser)>0)
                    					{
                    						//System.out.println("EXC:UPDATE `user` SET `u`=`u`+"+(bandwidth-userbandwidth.get(tempuser))+",`t`='"+(System.currentTimeMillis()/1000)+"' WHERE `uid`='"+usersinfo.get(tempuser).getId()+"'");
                    						
                    						Statement st1 = con.createStatement();
                    						st1.executeUpdate("UPDATE `user` SET `node_connector`='"+pconnector.get(usersinfo.get(tempuser).getPort())+"',`u`=`u`+"+(bandwidth-userbandwidth.get(tempuser))+",`t`='"+(System.currentTimeMillis()/1000)+"',`node_speed`=if('"+Long.valueOf(System.currentTimeMillis()/1000)+"'-`node_period`>10,'"+((bandwidth-userbandwidth.get(tempuser))/1024)+"',`node_speed`+'"+((bandwidth-userbandwidth.get(tempuser))/1024)+"'),`node_period`=if('"+Long.valueOf(System.currentTimeMillis()/1000)+"'-`node_period`>10,'"+Long.valueOf(System.currentTimeMillis()/1000)+"',`node_period`) WHERE `uid`='"+usersinfo.get(tempuser).getId()+"'");
                    						userbandwidth.put(tempuser, bandwidth);
                    					}
                    				}
                    			}
                    		}
                    		
                        	if(!tempuserlist.contains(tempuser))
                        	{
                        		deleteduserlist.add(tempuser);
                        	}
                        }
                        
                        Statement st3 = con.createStatement();
						st3.executeUpdate("UPDATE `ss_node` SET `node_connector`='"+connector_list.size()+"',`node_heartbeat`='"+Long.valueOf(System.currentTimeMillis()/1000)+"',`node_speed_sum` = '"+Long.valueOf((sumbandwidth-lastsumbandwidth)/10)+"',`node_bandwidth`=`node_bandwidth`+'"+(sumbandwidth-lastsumbandwidth)+"' WHERE `id` = "+node_id+"; ");
                        lastsumbandwidth=sumbandwidth;
                        
                        {
                        	Iterator<String> duit = deleteduserlist.iterator();
                        	while(duit.hasNext())
                        	{
                        		deleteuser(duit.next());
                        		System.out.println("deleted3");
                        	}
                        }
                        
                        System.out.println("Sleeping");
                        con.close();
        			} catch(Exception e) {
        				System.err.println("Exception: " + e.getMessage()+e.getStackTrace().toString());
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
	}

	public static boolean isinarray(String[] array,String match)
	{
		for(int a=0;a<array.length;a++)
		{
			if(array[a].equals(match))
			{
				return true;
			}
		}
		return false;
	}

	public static void deleteuser(String username)
	{
		try{
			System.out.println("DELETE:"+username);
			File pidfile=new File("./ssshell/"+usersinfo.get(username).getId()+".pid");
			if(pidfile.exists())
			{
				FileInputStream fi=new FileInputStream("./ssshell/"+usersinfo.get(username).getId()+".pid");
				InputStreamReader ir=new InputStreamReader(fi,"UTF-8");
				BufferedReader in=new BufferedReader(ir);
				String line=null;
				while((line=in.readLine())!=null){
					Runtime run = Runtime.getRuntime();
		    		run.exec("kill "+line);
				}
				in.close();
				pidfile.delete();
			}
			String back=exec("iptables -L --line-number -n|grep \"spt:"+usersinfo.get(username).getPort()+"\"|awk -F' ' '{print $1}'");
    		String[] array=back.split("\n");
    		for(int i=0;i<array.length;i++)
    		{
    			exec("iptables -D OUTPUT "+array[i]);
    		}
			usersinfo.remove(username);
			userbandwidth.remove(username);
		}catch(Exception e) {
			//System.err.println("Exception: " + e.getMessage());
		}
	}

	public static void adduser(String username,int port,String passwd,int id)
	{
		System.out.println("ADD:"+username);
		User newUser=new User(port, passwd,id);
		usersinfo.put(username, newUser);
		userbandwidth.put(username, (long) 0);
		String back=exec("iptables -L --line-number -n|grep \"spt:"+usersinfo.get(username).getPort()+"\"|awk -F' ' '{print $1}'");
		String[] array=back.split("\n");
		for(int i=0;i<array.length;i++)
		{
			exec("iptables -D OUTPUT "+array[i]);
		}
		Runtime run = Runtime.getRuntime();
		try {
			run.exec("/usr/local/bin/ss-server -p "+port+" -k "+passwd+" -m aes-256-cfb -f ./ssshell/"+id+".pid -u -s "+ip);
			run.exec("iptables -I OUTPUT -s "+ip+" -p tcp --sport "+port);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}


}
