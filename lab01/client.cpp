#include<iostream>
#include<Winsock2.h>
#include <ctime>
#include<cstring>
#pragma comment(lib,"ws2_32.lib")
using namespace std;
//接收和发送消息的字符数组
char send_buf[1024];
char recv_buf[1024];
bool quit=0;	//表示连接是否失效
bool talk=1;	//表示本客户端能否发送信息
void init() {
	//初始化套接字库	
	WSADATA wsadata;	
	int err;
    WORD w_version = MAKEWORD(2,2);//版本号
	err = WSAStartup(w_version,&wsadata);
	if (err != 0) {
		cout << "初始化套接字库失败" << endl;
	}
	else {
		cout << "初始化套接字库成功" << endl;
	}
}

//打印时间信息，要求在连接和关闭、接收到的信息后都进行打印
void print_time(){
	time_t time1;
	tm *p;
	time(&time1);
	p=localtime(&time1);
	printf("---%d月%d日 %02d:%02d:%02d\n",1+p->tm_mon,p->tm_mday,p->tm_hour,p->tm_min,p->tm_sec);
}

//接受信息
DWORD WINAPI cli_recv(LPVOID lparam){
	SOCKET client=*(SOCKET*)lparam;
	while(1){
		if(quit)break;
		int n=recv(client,recv_buf,1024,0);
		if(n>0){
			cout<<recv_buf<<endl;
			print_time();
			if(strcmp(recv_buf,"您已被管理员禁言!")==0)talk=0;
			if(strcmp(recv_buf,"您已被管理员解除禁言!")==0)talk=1;
		}
		else{
			quit=1;
		}
	}
	return 0;
}

int main() {
	init();
	SOCKET client=socket(AF_INET,SOCK_STREAM,0);
	SOCKADDR_IN server_addr;
	//填充地址信息
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	server_addr.sin_port = htons(1234);
	int t=connect(client,(SOCKADDR*)&server_addr,sizeof(SOCKADDR_IN));
	if(t!=0)cout<<"连接出现错误！"<<endl;
	//新建一个线程能够接收信息，在主线程中发送信息
	HANDLE th;
	th=CreateThread(NULL,0,cli_recv,(LPVOID)&client,0,0);
	while(1){
		if(quit)break;
		cin.getline(send_buf,1024);
		if(send_buf[0]!=0){
			if(strcmp(send_buf,"end_chat")==0){
				cout<<"与服务器连接已断开"<<endl;
				print_time();
				quit=1;
				break;
			}
			if(talk){
				print_time();
				send(client,send_buf,1024,0);
			}
		}
	}
	//通信结束后的处理
	CloseHandle(th);
	closesocket(client);
	WSACleanup();
	return 0;
}
