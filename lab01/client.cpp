#include<iostream>
#include<Winsock2.h>
#include <ctime>
#include<cstring>
#pragma comment(lib,"ws2_32.lib")
using namespace std;
//���պͷ�����Ϣ���ַ�����
char send_buf[1024];
char recv_buf[1024];
bool quit=0;	//��ʾ�����Ƿ�ʧЧ
bool talk=1;	//��ʾ���ͻ����ܷ�����Ϣ
void init() {
	//��ʼ���׽��ֿ�	
	WSADATA wsadata;	
	int err;
    WORD w_version = MAKEWORD(2,2);//�汾��
	err = WSAStartup(w_version,&wsadata);
	if (err != 0) {
		cout << "��ʼ���׽��ֿ�ʧ��" << endl;
	}
	else {
		cout << "��ʼ���׽��ֿ�ɹ�" << endl;
	}
}

//��ӡʱ����Ϣ��Ҫ�������Ӻ͹رա����յ�����Ϣ�󶼽��д�ӡ
void print_time(){
	time_t time1;
	tm *p;
	time(&time1);
	p=localtime(&time1);
	printf("---%d��%d�� %02d:%02d:%02d\n",1+p->tm_mon,p->tm_mday,p->tm_hour,p->tm_min,p->tm_sec);
}

//������Ϣ
DWORD WINAPI cli_recv(LPVOID lparam){
	SOCKET client=*(SOCKET*)lparam;
	while(1){
		if(quit)break;
		int n=recv(client,recv_buf,1024,0);
		if(n>0){
			cout<<recv_buf<<endl;
			print_time();
			if(strcmp(recv_buf,"���ѱ�����Ա����!")==0)talk=0;
			if(strcmp(recv_buf,"���ѱ�����Ա�������!")==0)talk=1;
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
	//����ַ��Ϣ
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	server_addr.sin_port = htons(1234);
	int t=connect(client,(SOCKADDR*)&server_addr,sizeof(SOCKADDR_IN));
	if(t!=0)cout<<"���ӳ��ִ���"<<endl;
	//�½�һ���߳��ܹ�������Ϣ�������߳��з�����Ϣ
	HANDLE th;
	th=CreateThread(NULL,0,cli_recv,(LPVOID)&client,0,0);
	while(1){
		if(quit)break;
		cin.getline(send_buf,1024);
		if(send_buf[0]!=0){
			if(strcmp(send_buf,"end_chat")==0){
				cout<<"������������ѶϿ�"<<endl;
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
	//ͨ�Ž�����Ĵ���
	CloseHandle(th);
	closesocket(client);
	WSACleanup();
	return 0;
}
