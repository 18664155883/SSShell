package Shadowsocks_Shell;

public class User {
	private int Port;
	private String Passwd;
	private int id;
	private int connector;
	private String Method;
	private int SpeedLimit;
	private int LimitCount;
	

	
	public User(int Port,String Passwd,int id,String method,int SpeedLimit,int LimitCount){
		this.Port = Port;
		this.Passwd = Passwd;
		this.id = id;
		this.connector = 0;
		this.Method = method;
		this.SpeedLimit = SpeedLimit;
		this.LimitCount = LimitCount;
	}
	
	public void setPort(int Port){
		this.Port=Port;
	}
	
	public int getPort(){
		return this.Port;
	}
	
	public int getSpeedLimit(){
		return this.SpeedLimit;
	}
	
	public String getMethod(){
		return this.Method;
	}
	
	public int getLimitCount(){
		return this.LimitCount;
	}
	
	public void setConnector(int connector){
		this.connector=connector;
	}
	
	public int getConnector(){
		return this.connector;
	}
	
	public void setPasswd(String Passwd){
		this.Passwd=Passwd;
	}
	
	public String getPasswd(){
		return this.Passwd;
	}
	
	public void setId(int id){
		this.id=id;
	}
	
	public int getId(){
		return this.id;
	}
}
