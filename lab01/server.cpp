#include<iostream>
#include<Winsock2.h>
#include <ctime>
#include<cstring>
#pragma comment(lib,"ws2_32.lib")
using namespace std;
char send_buf[1024];//���պͷ�����Ϣ���ַ�����
char recv_buf[1024];
const int MAX_NUM=22;  //�������20���ͻ��ˣ�����1������˺�1���������ĩβԪ��
SOCKET sockets[MAX_NUM];	//�ͻ���+������׽��ֺ͵�ַ�������Ϊ0��
SOCKADDR_IN addrs[MAX_NUM];	
WSAEVENT events[MAX_NUM];	//��Ӧ���пͻ��˺ͷ���˵��¼�
int client_num=0;	//��ǰ�ͻ�������
bool quit=0;	//��ʾ�����Ƿ�ʧЧ
bool talk[MAX_NUM];	//��Ӧ���пͻ����Ƿ񱻽��Եı�ʶ��

void init() {
	//��ʼ���׽��ֿ�
	WORD w_req = MAKEWORD(2,2);
	WSADATA wsadata;
	int err;
	err = WSAStartup(w_req,&wsadata);
	if (err != 0) 
		cout << "��ʼ���׽��ֿ�ʧ�ܣ�" << endl;
	else 
		cout << "��ʼ���׽��ֿ�ɹ���" << endl;
}

//��ӡʱ����Ϣ��Ҫ�������Ӻ͹رա����յ�����Ϣ�󶼽��д�ӡ
void print_time(){
	time_t time1;
	tm *p;
	time(&time1);
	p=localtime(&time1);
	printf("---%d��%d�� %02d:%02d:%02d\n",1+p->tm_mon,p->tm_mday,p->tm_hour,p->tm_min,p->tm_sec);
}

//���ܲ�ת����Ϣ
DWORD WINAPI serv_recv(LPVOID lparam){
	SOCKET servSock = *(SOCKET*)lparam;
	while (1) {
		if(quit)break;
		for (int i = 0; i < client_num+1; i++){
			//�鿴ĳ���¼�
			int id = WSAWaitForMultipleEvents(1, &events[i], false, 10, false);
			if (id==0){
				//�������ľ����¼��浽ntevent��	
				WSANETWORKEVENTS ntevent;	
				WSAEnumNetworkEvents(sockets[i], events[i], &ntevent);
				//����ǽ����¼���˵�����¿ͻ��˼���
				if (ntevent.lNetworkEvents&FD_ACCEPT){
					if (client_num+1<MAX_NUM){
						client_num++;
						//�����¿ͻ��˵ĸ���Ϣ
						int len = sizeof(SOCKADDR_IN);
						SOCKET newcli = accept(servSock, (SOCKADDR*)&addrs[client_num], &len);
						sockets[client_num] = newcli;
						//Ϊ�¿ͻ��˰󶨹رա�����������Ϣ����д��������Ϣ���¼�
						WSAEVENT cli_event = WSACreateEvent();
						WSAEventSelect(sockets[client_num], cli_event, FD_CLOSE | FD_READ | FD_WRITE);
						events[client_num] = cli_event;
						cout <<"��" << client_num<< "���û��Ѽ�������"<< endl;
						print_time();
						//�����пͻ��˷�����Ϣ
						sprintf(send_buf,"����Ա����%d���û���������",client_num);
						for (int j = i; j <=client_num; j++)
							send(sockets[j], send_buf, 1024,0);
					}
				}
				//����ǹر��¼�
				else if (ntevent.lNetworkEvents & FD_CLOSE){
					client_num--;
					//�رտͻ��˶�Ӧ��Դ
					closesocket(sockets[i]);
					WSACloseEvent(events[i]);
					cout <<"��" <<i<< "���û����˳����죬��ǰ��ʣ"<<client_num<<"��"<< endl;
					print_time();
					//�������ͻ��˵��±�˳��
					for (int j = i; j <= client_num; j++){
						sockets[j] = sockets[j + 1];
						events[j] = events[j + 1];
						addrs[j] = addrs[j + 1];
						talk[j]=talk[j+1];
					}
					//�����пͻ��˷�����Ϣ
					sprintf(send_buf,"����Ա����%d���û��˳����죬�����û����ǰ�ơ����������ڻ���%d��",i,client_num);
					for (int j = 1; j <=client_num; j++)
						send(sockets[j], send_buf, 1024, 0);
				}
				//����Ƕ��¼���˵�����յ���Ϣ
				else if (ntevent.lNetworkEvents & FD_READ){
					char temp[1024]; //��ʱ�Ľ�������
					for (int j = 1; j <= client_num; j++){
						int nrecv = recv(sockets[j], temp, 1024, 0);//nrecv�ǽ��յ����ֽ���
						if (nrecv > 0){	
							sprintf(send_buf,"%d�ţ�%s",j,temp);
							cout << send_buf << endl;
							print_time();
							//ת���������ͻ���
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

//����˷�����Ϣ
DWORD WINAPI serv_send(LPVOID lparam){
	SOCKET servSock = *(SOCKET*)lparam;
	while (1){
		if(quit)break;
		char temp[1024];
		int tar=0;
		cin.getline(temp, 1024);
		// �����������˳�
		if(strcmp(temp,"end_chat")==0){
			cout<<"����������"<<endl;
			strcpy(temp,"�ҷ��������Ͽ�����");
			quit=1;
			}
		// #nt����ָ�����ĳ���ͻ���
		else if(temp[0]=='#'&&temp[1]=='n'&&temp[2]=='t'){
			int i=3;
			while(temp[i]!='\0'){
				tar=tar*10+temp[i]-48;
				i++;
			}
			if(tar<=client_num&&!talk[tar]){
				cout<<"�ѽ�"<<tar<<"���û�����"<<endl;
				talk[tar]=1;
				}
			else if(tar<=client_num&&talk[tar]){
				cout<<"���û��Ѵ��ڽ���״̬�������ظ�����"<<endl;
				tar=0;
			}
			else {
				cout<<"ָ����Ч�������ڸ��û�"<<endl;
				tar=0;
				}
			print_time();
			if(tar!=0){
				sprintf(send_buf,"����Ա���ѽ�%d���û����ԣ�ע��ά�����컷��",tar);
				for (int j =1 ; j <= client_num; j++){
					if(j!=tar)
						send(sockets[j], send_buf, 1024, 0);
					else 
						send(sockets[j],"���ѱ�����Ա����!",1024,0);	
				}
			}
			continue;
		}
		// #ct���ָ��������ĳ���ͻ���
		else if(temp[0]=='#'&&temp[1]=='c'&&temp[2]=='t'){
			int i=3;
			while(temp[i]!='\0'){
				tar=tar*10+temp[i]-48;
				i++;
			}
			if(tar<=client_num&&talk[tar]){
				cout<<"�ѽ�"<<tar<<"���û��������"<<endl;
				talk[tar]=0;
				}
			else if(tar<=client_num&&!talk[tar]){
				cout<<"���û�δ�����ԣ�����������"<<endl;
				tar=0;
			}
			else {
				cout<<"ָ����Ч�������ڸ��û�"<<endl;
				tar=0;
				}
			print_time();
			if(tar!=0){
				sprintf(send_buf,"����Ա���ѽ�%d���û�������ԣ�ע��ά�����컷��",tar);
				for (int j =1 ; j <= client_num; j++){
					if(j!=tar)
						send(sockets[j], send_buf, 1024, 0);
					else 
						send(sockets[j],"���ѱ�����Ա�������!",1024,0);	
				}
			}
			continue;
		}
		print_time();
		sprintf(send_buf, "����Ա��%s",temp);
		for (int j =1 ; j <= client_num; j++)
			send(sockets[j], send_buf, 1024, 0);
	}
	return 0;
}
int main() {
	init();
	SOCKET serv=socket(AF_INET,SOCK_STREAM,0);
	//��������׽��ֵ�ַ��Ϣ
	SOCKADDR_IN serv_addr;
	serv_addr.sin_family=AF_INET;
	serv_addr.sin_addr.S_un.S_addr=inet_addr("127.0.0.1");
	serv_addr.sin_port=htons(1234);
	//���׽��ֺ͵�ַ
	bind(serv,(SOCKADDR*)&serv_addr,sizeof(SOCKADDR_IN));
	//Ϊ����˰��¼����󣬼��������¼�
	WSAEVENT serv_event = WSACreateEvent();
	WSAEventSelect(serv, serv_event, FD_ALL_EVENTS); 
	sockets[0] = serv;
	events[0] = serv_event;
	//�����ͻ�����������
	listen(serv, 20);
	cout << "Ⱥ���ѿ��������������������"<<MAX_NUM-2<<"���û�" << endl;
	//���̣߳������߳�֮�ⴴ��һ�����ڽ��պ�ת����Ϣ�Ľ��̡�һ����������Ϣ�Ľ���
	HANDLE th[2];
	th[0]=CreateThread(NULL, 0, serv_recv, (LPVOID)&serv, 0, 0);
	th[1]=CreateThread(NULL, 0, serv_send, (LPVOID)&serv, 0, 0);
	WaitForMultipleObjects(2, th, TRUE, INFINITE);
	CloseHandle(th[0]);
	CloseHandle(th[1]);
	WSACleanup();
	return 0;
}
