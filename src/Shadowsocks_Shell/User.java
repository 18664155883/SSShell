package Shadowsocks_Shell;

public class User {
	private int Port;
	private String Passwd;
	private int id;
	private int connector;
	
	public User(int Port,String Passwd,int id){
		this.Port=Port;
		this.Passwd=Passwd;
		this.id=id;
		this.connector=0;
	}
	
	public void setPort(int Port){
		this.Port=Port;
	}
	
	public int getPort(){
		return this.Port;
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
