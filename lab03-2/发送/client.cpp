// 客户端即为发送端
#include<iostream>
#include<Winsock2.h>
#include<cstring>
#include<fstream>
#include<direct.h>  
#include<stdio.h> 
#include<vector>
#include<io.h>
#include<time.h>
#include<thread>
#pragma comment(lib, "ws2_32.lib")
using namespace std;

// 定义报文长度、源和目标的地址与端口等
#define BUF_SIZE 8192
#define SERVER_ID 127<<24+1  //表示127.0.0.1
#define CLIENT_ID 127<<24+1
#define SERVER_PORT 8080
#define CLIENT_PORT 8081
#define PATH_LEN 30
#define WINDOW_SIZE 8

// 定义报文结构
struct group{
    USHORT flags;   //标志位
    UINT s_ip;    //源地址
    UINT d_ip;    //目标地址
    USHORT s_port;  //源端口
    USHORT d_port;  //目标端口
    USHORT seq;     //序号
    USHORT f_length;    //报文内容长度
    USHORT checksum;    //校验和，以上共计2*6+4*2=20字节
    char buf[BUF_SIZE];     //报文内容
};

// 定义全局变量
char send_buf[sizeof(group)];
char recv_buf[sizeof(group)];
char* send_ALL[WINDOW_SIZE];   //发送缓冲区
char file_name[PATH_LEN];
char file_path[200];
// 以下三个边界单调递增，实现单调队列的功能
USHORT id;  //发送边界
USHORT left_edge; //左边界
#define right_edge left_edge+WINDOW_SIZE //右边界
clock_t time_st;
bool clock_on = 0;
bool close_conn = 0;
int file_end = -1;
SOCKET client;
sockaddr_in saddr;
sockaddr_in caddr;

//初始化套接字库
void init() {
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

//检测所有的文件
bool getFiles(string path, vector<string>& files)
{
	//文件句柄
	long hFile = 0;
	//文件信息
	struct _finddata_t fileinfo;
	string p;
	if ((hFile = _findfirst(p.assign(path).append("\\*").c_str(), &fileinfo)) != -1)
	{
		do
		{
			files.push_back(p.assign(path).append("\\").append(fileinfo.name));
		} while (_findnext(hFile, &fileinfo) == 0);
		_findclose(hFile);
	}
	return 1;
}

// 输出报文日志
void getlog(group g,int a)
{
	if (a == 0){
		cout << "send"
			<< "\tseq " << g.seq
			<< "\tSYN " << (g.flags&0b1)
			<< "\tACK " << ((g.flags&0b10)>>1)
			<< "\tFIN " << ((g.flags&0b100)>>2)
			<< "\tchecksum " << g.checksum
            << "\tlength " << g.f_length
			<< endl;
	}
	if (a == 1){
		cout << "recv"
			<< "\tseq " << g.seq
			<< "\tSYN " << (g.flags&0b1)
			<< "\tACK " << ((g.flags&0b10)>>1)
			<< "\tFIN " << ((g.flags&0b100)>>2)
			<< "\tchecksum " << g.checksum
			<< endl;
	}
}

// 计算校验和并填入
void set_checksum(group *g){
    unsigned int sum = 0;
    // sum累加上报文结构中的所有数值
    sum+=g->flags;
    // 若超过16位的表示范围则把超出的部分截掉，在末尾加1
    if(sum>=0x10000){
        sum-=0x10000;
        sum+=1;
    }
    sum+=g->s_ip>>16;
    if(sum>=0x10000){
        sum-=0x10000;
        sum+=1;
    }
    sum+=(g->s_ip<<16)>>16;
    if(sum>=0x10000){
        sum-=0x10000;
        sum+=1;
    }
    sum+=g->d_ip>>16;
    if(sum>=0x10000){
        sum-=0x10000;
        sum+=1;
    }
    sum+=(g->d_ip<<16)>>16;
    if(sum>=0x10000){
        sum-=0x10000;
        sum+=1;
    }
    sum+=g->s_port;
    if(sum>=0x10000){
        sum-=0x10000;
        sum+=1;
    }
    sum+=g->d_port;
    if(sum>=0x10000){
        sum-=0x10000;
        sum+=1;
    }
    sum+=g->seq;
    if(sum>=0x10000){
        sum-=0x10000;
        sum+=1;
    }
    sum+=g->f_length;
    if(sum>=0x10000){
        sum-=0x10000;
        sum+=1;
    }
    // 数据通过char存储，由于以2字节为单位取数据，所以取的char元素个数为2的倍数
    for(int i=0;i<g->f_length;i+=2){
        // 第一个字节左移8位(乘256)再与第二个字节拼接
        sum+=g->buf[i]*256+g->buf[i+1];
        if(sum>=0x10000){
            sum-=0x10000;
            sum+=1;
        }
    }
    // 取反，得到校验和，结果放入g的校验和中
    g->checksum = ~(USHORT)sum;
}

// 设置报文内容
group set_group(char *buf,int len,bool SYN=0,bool ACK=0,bool FIN=0){
    group g;
    memset(&g,0,sizeof(group));
    if(SYN) g.flags+=0b1;
    if(ACK) g.flags+=0b10;
    if(FIN) g.flags+=0b100;
    g.s_ip = CLIENT_ID;
    g.d_ip = SERVER_ID;
    g.s_port = CLIENT_PORT;
    g.d_port = SERVER_PORT;
    g.seq = id;
    g.f_length = len;
    memcpy(g.buf,buf,len);
    set_checksum(&g);
    return g;
}

// SYN连接报文
group SYN_UDP(){
    char str[]="";
    group g = set_group(str,0,1,0,0);
    return g;
}
// ACK接收报文
group ACK_UDP(){
    char str[]="";
    group g = set_group(str,0,0,1,0);
    return g;
}

// FIN结束报文
group FIN_UDP(){
    char str[]="";
    group g = set_group(str,0,0,0,1);
    return g;
}

// 实现group类与char类型的相互转换
void group_to_char(group& g,char* str)
{
	memset(str,0,sizeof(group));
	memcpy(str,&g,sizeof(group));
}

void char_to_group(char* str, group &g)
{
	memset(&g,0,sizeof(group));
	memcpy(&g, str, sizeof(group));
}

//握手
bool shake(SOCKET& client, sockaddr_in& saddr){
    // 设置超时时间
    int timeout = 100;
    //设置套接字属性
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    group g = SYN_UDP();
    group_to_char(g,send_buf);
    int addr_len = sizeof(saddr);
    // 最大尝试连接次数
    int shake_times=30;
    while(1){
        // 发送SYN报文
        sendto(client,send_buf,sizeof(group),0,(sockaddr*)&saddr,addr_len);
        getlog(g,0);
        shake_times--;
        if(!shake_times){
            cout<< "连接失败！"<<endl;
            return 0;
        }
        // 接收传回的报文
        int rec = recvfrom(client,recv_buf,sizeof(group),0,(sockaddr*)&saddr,&addr_len);
        // 如果接收失败或接收超时，重新发送SYN报文
        if(rec<0){
            continue;
        }
        char_to_group(recv_buf,g);
        getlog(g,1);
        // 如果接收到ACK报文，且序号为0，建立连接成功
        if(g.flags ==2&&g.seq==id+1){
            id++;
            left_edge = id;
            break;
        }
    }
    cout << "连接成功！"<<endl;
    return 1;
}

// 挥手
bool wave(SOCKET& client, sockaddr_in& saddr){
    close_conn = 1;
    // 设置断连超时时间
    int timeout = 100;
    //设置套接字属性
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    group g = FIN_UDP();
    group_to_char(g,send_buf);
    int addr_len = sizeof(saddr);
    while(1){
        // 发送FIN报文
        sendto(client,send_buf,sizeof(group),0,(sockaddr*)&saddr,addr_len);
        getlog(g,0);
        // 接收传回的报文
        int rec = recvfrom(client,recv_buf,sizeof(group),0,(sockaddr*)&saddr,&addr_len);
        // 如果接收失败或接收超时，重新发送FIN报文
        if(rec<0){
            sendto(client, send_buf, sizeof(group), 0, (sockaddr*)&saddr, sizeof(saddr));
            continue;
        }
        char_to_group(recv_buf,g);
        getlog(g,1);
        // 如果接收到ACK报文，且序号与记录的序号相同，则成功断开连接
        if(g.flags==2&&g.seq==id+1){
            break;
        }
    }
    cout << "成功断开连接！"<<endl;
    return 1;
}

// 计时器，判断是否在一段时间内未接收到正确的ACK信号
void outtime(){
    while(1){
        if(close_conn)
            break;
        // 计时器未开启
        if(!clock_on)
            continue;
        // 一直未能接收到正确的ACK信号，已超时
        if((double)(clock()-time_st)>100){
            // 重新发送所有已发送未确认的数据
            for(int i = left_edge;i<=id;i++){
                sendto(client, send_ALL[i%WINDOW_SIZE], sizeof(group), 0, (sockaddr*)&saddr, sizeof(saddr));
                }
            time_st = clock();
        }
    }
}

// 判断要发送的信息是否在窗口范围内
void asend(){
    // 判断要发送的信息是否在窗口范围内
    while(1){
        if(id>=left_edge && id<right_edge)
            break;
    }
    id+=1;
    memset(send_ALL[id%WINDOW_SIZE], 0, sizeof(group));
	memcpy(send_ALL[id%WINDOW_SIZE], send_buf, sizeof(group)); //存入缓冲区
    sendto(client,send_buf,sizeof(group),0,(sockaddr*)&saddr, sizeof(saddr));
    group sg;
    char_to_group(send_buf,sg);
    getlog(sg,0);
    if(id == left_edge+1){
        time_st=clock();
        clock_on=1;
    }
    
}

// 发送信息
void send0(){
    while(1){
        int op;
        cout<<"输入1进行文件传输，输入2断开连接：";
        cin>>op;
        // 挥手退出
        if(op == 2){
            close_conn=1;
            clock_on = 0;
            wave(client,saddr);
            return;
        }
        // 线传输文件名
        cout<<"请输入文件名（无需完整路径）：";
        cin>>file_name;
        cout<<"---------------------正在传输文件---------------------"<<endl;
         // 记录传输开始时间、传输字节数
        int t_st = clock();    
        int bytesum=0,byteleft=0;
        FILE* fp;
        fp = fopen(file_name,"rb");
        // 首先传输文件名
        group name = set_group(file_name,sizeof(file_name));
        group_to_char(name,send_buf);
        asend();
        byteleft+=30;
        // 再传输文件内容
        int len;
        while(len = fread(send_buf,1,BUF_SIZE,fp)){
            group sg = set_group(send_buf,len);
            group_to_char(sg,send_buf);
            asend();
            if(len==BUF_SIZE)
                bytesum+=1;
            else
                byteleft+=len;
        }
        // 发送文件传输结束的信号
        char end[] = "end";
		group sg = set_group(end, 3);
		group_to_char(sg, send_buf);
        asend();
        byteleft+=3;
        cout<<"---------------------文件传输结束---------------------"<<endl;
        int t_ed = clock();
        cout<<"传输"<<bytesum*BUF_SIZE+byteleft<<"字节，"
            <<"耗时"<<t_ed-t_st<<"毫秒，"
            <<"吞吐率为"<<(bytesum*BUF_SIZE+byteleft)*8.0/(t_ed-t_st)*1000<<"bps"<<endl;
        fclose(fp);
    }
}

// 接收信息
void recv0(){
    int length = sizeof(saddr);
    while(1){
        if(close_conn)
            return;
        int ret = recvfrom(client, recv_buf, sizeof(group), 0, (sockaddr*)&saddr, &length);
        if(ret<=0)continue;
        group rg;
        char_to_group(recv_buf,rg);
        if(ret>0 && rg.flags==2){
            // 表示到第rg.seq-1个都已被确认,左边界移动
            int temp_edge = rg.seq;
            // 如果左边界和发送边界重合，说明所有已发送的数据都已确认，关闭计时器
            if(temp_edge==id){
                clock_on = 0;
                }
            left_edge = temp_edge;
        }
        else 
            continue;
    }
}

int main(){
    init();
    // 设置套接字与地址信息
    client = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    caddr.sin_family = AF_INET;
	caddr.sin_port = htons(CLIENT_PORT);
	caddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
    saddr.sin_family = AF_INET;
	saddr.sin_port = htons(SERVER_PORT);
	saddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
    // 绑定套接字与地址
    bind(client,(sockaddr*)&caddr,sizeof(sockaddr_in));
    // 握手连接
    if(!shake(client,saddr)){
        return 0;
    }  
    // 展示当前文件夹下的文件
    getcwd(file_path,200);
    vector<string> files;
    getFiles(file_path, files);
    int size = files.size();
    cout<<"当前文件夹下可传输的文件："<<endl;
    for (int i = 2;i < size;i++){
        cout<<files[i].c_str()<<endl;
    }
    // 缓冲区初始化
    for (int i = 0; i < WINDOW_SIZE; i++)
		send_ALL[i] = new char[sizeof(group)];
    // 多线程———发送+接收+超时
    thread tsend,trecv,touttime;
    tsend = thread(send0);
    trecv = thread(recv0);
    touttime = thread(outtime);
    tsend.join();
    trecv.join();
    touttime.join();

    closesocket(client);
    WSACleanup();
    return 0;
}