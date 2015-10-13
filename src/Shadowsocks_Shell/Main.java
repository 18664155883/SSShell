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
	private static String ip;
	
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
                        tempuserlist=new HashSet<String>();
                        HashSet<String> deleteduserlist = new HashSet<String>();
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
                            		}
                            	}
                            }
                            else
                            {
                            	//不存在时
                            	if(rs.getBigDecimal("transfer_enable").longValue()>(rs.getBigDecimal("u").longValue()+rs.getBigDecimal("d").longValue()))
                            	{
                            		adduser(rs.getString("user_name"),rs.getInt("port"),rs.getString("passwd"),rs.getInt("uid"));
                            	}
                            }
                        }
                        
                        Set<String> usersset = usersinfo.keySet();
                        Iterator<String> usersit = usersset.iterator();
                        while(usersit.hasNext())
                        {
                        	String tempuser=usersit.next();
                        	String back=exec("iptables -n -v -L -t filter -x |grep -i 'spt:"+usersinfo.get(tempuser).getPort()+"' -m 1|awk -F' ' '{print $2}'");
                    		String[] array=back.split("\n");
                    		if(array!=null)
                    		{
                    			if(!array[0].equals("0"))
                    			{
                    				if(userbandwidth.containsKey(tempuser))
                    				{
                    					//long bandwidth = -1;
                    					long bandwidth=Long.valueOf(array[0]);
                    					
                    					System.out.println("bw:"+bandwidth+"|"+userbandwidth.get(tempuser));
                    					if(bandwidth-userbandwidth.get(tempuser)>0)
                    					{
                    						System.out.println("EXC:UPDATE `user` SET `u`=`u`+"+(bandwidth-userbandwidth.get(tempuser))+",`t`='"+(System.currentTimeMillis()/1000)+"' WHERE `uid`='"+usersinfo.get(tempuser).getId()+"'");
                    						Statement st1 = con.createStatement();
                    						st1.executeUpdate("UPDATE `user` SET `u`=`u`+"+(bandwidth-userbandwidth.get(tempuser))+",`t`='"+(System.currentTimeMillis()/1000)+"' WHERE `uid`='"+usersinfo.get(tempuser).getId()+"'");
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
