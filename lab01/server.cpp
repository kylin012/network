#include<iostream>
#include<Winsock2.h>
#include <ctime>
#include<cstring>
#pragma comment(lib,"ws2_32.lib")
using namespace std;
char send_buf[1024];//接收和发送消息的字符数组
char recv_buf[1024];
const int MAX_NUM=22;  //最多容纳20个客户端，加上1个服务端和1个防溢出的末尾元素
SOCKET sockets[MAX_NUM];	//客户端+服务端套接字和地址，服务端为0号
SOCKADDR_IN addrs[MAX_NUM];	
WSAEVENT events[MAX_NUM];	//对应所有客户端和服务端的事件
int client_num=0;	//当前客户端数量
bool quit=0;	//表示连接是否失效
bool talk[MAX_NUM];	//对应所有客户端是否被禁言的标识符

void init() {
	//初始化套接字库
	WORD w_req = MAKEWORD(2,2);
	WSADATA wsadata;
	int err;
	err = WSAStartup(w_req,&wsadata);
	if (err != 0) 
		cout << "初始化套接字库失败！" << endl;
	else 
		cout << "初始化套接字库成功！" << endl;
}

//打印时间信息，要求在连接和关闭、接收到的信息后都进行打印
void print_time(){
	time_t time1;
	tm *p;
	time(&time1);
	p=localtime(&time1);
	printf("---%d月%d日 %02d:%02d:%02d\n",1+p->tm_mon,p->tm_mday,p->tm_hour,p->tm_min,p->tm_sec);
}

//接受并转发信息
DWORD WINAPI serv_recv(LPVOID lparam){
	SOCKET servSock = *(SOCKET*)lparam;
	while (1) {
		if(quit)break;
		for (int i = 0; i < client_num+1; i++){
			//查看某个事件
			int id = WSAWaitForMultipleEvents(1, &events[i], false, 10, false);
			if (id==0){
				//将发生的具体事件存到ntevent中	
				WSANETWORKEVENTS ntevent;	
				WSAEnumNetworkEvents(sockets[i], events[i], &ntevent);
				//如果是接收事件，说明有新客户端加入
				if (ntevent.lNetworkEvents&FD_ACCEPT){
					if (client_num+1<MAX_NUM){
						client_num++;
						//设置新客户端的各信息
						int len = sizeof(SOCKADDR_IN);
						SOCKET newcli = accept(servSock, (SOCKADDR*)&addrs[client_num], &len);
						sockets[client_num] = newcli;
						//为新客户端绑定关闭、读（接收信息）、写（发送信息）事件
						WSAEVENT cli_event = WSACreateEvent();
						WSAEventSelect(sockets[client_num], cli_event, FD_CLOSE | FD_READ | FD_WRITE);
						events[client_num] = cli_event;
						cout <<"第" << client_num<< "号用户已加入聊天"<< endl;
						print_time();
						//向所有客户端发送消息
						sprintf(send_buf,"管理员：第%d号用户加入聊天",client_num);
						for (int j = i; j <=client_num; j++)
							send(sockets[j], send_buf, 1024,0);
					}
				}
				//如果是关闭事件
				else if (ntevent.lNetworkEvents & FD_CLOSE){
					client_num--;
					//关闭客户端对应资源
					closesocket(sockets[i]);
					WSACloseEvent(events[i]);
					cout <<"第" <<i<< "号用户已退出聊天，当前还剩"<<client_num<<"人"<< endl;
					print_time();
					//调整各客户端的下标顺序
					for (int j = i; j <= client_num; j++){
						sockets[j] = sockets[j + 1];
						events[j] = events[j + 1];
						addrs[j] = addrs[j + 1];
						talk[j]=talk[j+1];
					}
					//向所有客户端发送消息
					sprintf(send_buf,"管理员：第%d号用户退出聊天，其后的用户编号前移。包括您在内还有%d人",i,client_num);
					for (int j = 1; j <=client_num; j++)
						send(sockets[j], send_buf, 1024, 0);
				}
				//如果是读事件，说明接收到消息
				else if (ntevent.lNetworkEvents & FD_READ){
					char temp[1024]; //临时的接收数组
					for (int j = 1; j <= client_num; j++){
						int nrecv = recv(sockets[j], temp, 1024, 0);//nrecv是接收到的字节数
						if (nrecv > 0){	
							sprintf(send_buf,"%d号：%s",j,temp);
							cout << send_buf << endl;
							print_time();
							//转发给其他客户端
							for (int k = 1; k <= client_num; k++)
								if(k!=j)
									send(sockets[k], send_buf, 1024,0);
						}
					}
				}
			}
		}
	}
	return 0;
}

//服务端发送信息
DWORD WINAPI serv_send(LPVOID lparam){
	SOCKET servSock = *(SOCKET*)lparam;
	while (1){
		if(quit)break;
		char temp[1024];
		int tar=0;
		cin.getline(temp, 1024);
		// 服务器主动退出
		if(strcmp(temp,"end_chat")==0){
			cout<<"服务器下线"<<endl;
			strcpy(temp,"我方已主动断开连接");
			quit=1;
			}
		// #nt禁言指令，禁言某个客户端
		else if(temp[0]=='#'&&temp[1]=='n'&&temp[2]=='t'){
			int i=3;
			while(temp[i]!='\0'){
				tar=tar*10+temp[i]-48;
				i++;
			}
			if(tar<=client_num&&!talk[tar]){
				cout<<"已将"<<tar<<"号用户禁言"<<endl;
				talk[tar]=1;
				}
			else if(tar<=client_num&&talk[tar]){
				cout<<"该用户已处于禁言状态，请勿重复禁言"<<endl;
				tar=0;
			}
			else {
				cout<<"指令无效，不存在该用户"<<endl;
				tar=0;
				}
			print_time();
			if(tar!=0){
				sprintf(send_buf,"管理员：已将%d号用户禁言，注意维护聊天环境",tar);
				for (int j =1 ; j <= client_num; j++){
					if(j!=tar)
						send(sockets[j], send_buf, 1024, 0);
					else 
						send(sockets[j],"您已被管理员禁言!",1024,0);	
				}
			}
			continue;
		}
		// #ct解禁指令，解除禁言某个客户端
		else if(temp[0]=='#'&&temp[1]=='c'&&temp[2]=='t'){
			int i=3;
			while(temp[i]!='\0'){
				tar=tar*10+temp[i]-48;
				i++;
			}
			if(tar<=client_num&&talk[tar]){
				cout<<"已将"<<tar<<"号用户解除禁言"<<endl;
				talk[tar]=0;
				}
			else if(tar<=client_num&&!talk[tar]){
				cout<<"该用户未被禁言，无需解除禁言"<<endl;
				tar=0;
			}
			else {
				cout<<"指令无效，不存在该用户"<<endl;
				tar=0;
				}
			print_time();
			if(tar!=0){
				sprintf(send_buf,"管理员：已将%d号用户解除禁言，注意维护聊天环境",tar);
				for (int j =1 ; j <= client_num; j++){
					if(j!=tar)
						send(sockets[j], send_buf, 1024, 0);
					else 
						send(sockets[j],"您已被管理员解除禁言!",1024,0);	
				}
			}
			continue;
		}
		print_time();
		sprintf(send_buf, "管理员：%s",temp);
		for (int j =1 ; j <= client_num; j++)
			send(sockets[j], send_buf, 1024, 0);
	}
	return 0;
}
int main() {
	init();
	SOCKET serv=socket(AF_INET,SOCK_STREAM,0);
	//填充服务端套接字地址信息
	SOCKADDR_IN serv_addr;
	serv_addr.sin_family=AF_INET;
	serv_addr.sin_addr.S_un.S_addr=inet_addr("127.0.0.1");
	serv_addr.sin_port=htons(1234);
	//绑定套接字和地址
	bind(serv,(SOCKADDR*)&serv_addr,sizeof(SOCKADDR_IN));
	//为服务端绑定事件对象，监听其他事件
	WSAEVENT serv_event = WSACreateEvent();
	WSAEventSelect(serv, serv_event, FD_ALL_EVENTS); 
	sockets[0] = serv;
	events[0] = serv_event;
	//监听客户端连接请求
	listen(serv, 20);
	cout << "群聊已开启，本聊天室最多容纳"<<MAX_NUM-2<<"个用户" << endl;
	//多线程，在主线程之外创建一个用于接收和转发信息的进程、一个自身发送消息的进程
	HANDLE th[2];
	th[0]=CreateThread(NULL, 0, serv_recv, (LPVOID)&serv, 0, 0);
	th[1]=CreateThread(NULL, 0, serv_send, (LPVOID)&serv, 0, 0);
	WaitForMultipleObjects(2, th, TRUE, INFINITE);
	CloseHandle(th[0]);
	CloseHandle(th[1]);
	WSACleanup();
	return 0;
}
