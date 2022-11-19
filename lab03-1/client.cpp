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
#pragma comment(lib, "ws2_32.lib")
using namespace std;

// 定义报文长度、源和目标的地址与端口等
#define BUF_SIZE 2048
#define SERVER_ID 127<<24+1  //表示127.0.0.1
#define CLIENT_ID 127<<24+1
#define SERVER_PORT 8080
#define CLIENT_PORT 8081
#define PATH_LEN 30

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

char send_buf[sizeof(group)];
char recv_buf[sizeof(group)];
char file_name[PATH_LEN];
char file_path[200];
USHORT id;  //序号

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
    // 设置连接超时时间
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
            break;
        }
    }
    cout << "连接成功！"<<endl;
    return 1;
}

// 挥手
bool wave(SOCKET& client, sockaddr_in& saddr){
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
            continue;
        }
        char_to_group(recv_buf,g);
        getlog(g,1);
        // 如果接收到ACK报文，且序号与记录的序号相同，则成功断开连接
        if(g.flags==2&&g.seq==id+1){
            id++;
            break;
        }
    }
    cout << "成功断开连接！"<<endl;
    return 1;
}


int main(){
    init();
    // 建立客户端套接字
    SOCKET client;
    client = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int timeout = 100;
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    // 填充地址信息
    sockaddr_in caddr;
    sockaddr_in saddr;
    int addr_len = sizeof(sockaddr_in);
    caddr.sin_family = AF_INET;
    caddr.sin_port = htons(CLIENT_PORT);
    caddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
    saddr.sin_family = AF_INET;
	saddr.sin_port = htons(SERVER_PORT);
	saddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
    // 绑定客户端套接字与地址
    bind(client,(sockaddr*)&caddr,addr_len);
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
    // 发送文件
    while(1){
        int op;
        cout<<"输入1进行文件传输，输入2断开连接：";
        cin>>op;
        // 挥手退出
        if(op == 2){
            wave(client,saddr);
            return 0;
        }
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
        byteleft+=30;
        group_to_char(name,send_buf);
        // 发送与接收报文
        while (1){
            sendto(client, send_buf, sizeof(group), 0, (sockaddr*)&saddr, sizeof(saddr));
            getlog(name,0);
            // 如果接收失败或接收超时，重新发送报文
            int rec = recvfrom(client,recv_buf,sizeof(group),0,(sockaddr*)&saddr, &addr_len);
            if (rec < 0)
                continue;
            // 接收到的
            group rg;
            char_to_group(recv_buf,rg);
            getlog(rg,1);
            // 如果接收到ACK报文，且序号与记录的序号相同，则说明传输成功
            if(rg.flags==2&&rg.seq==id+1){
                id++;
                break;
            }
        }
        // 接下来传输文件内的实际内容
        int len;
        // 只要文件未读完就一直循环，一次最多读2048字节的内容
        while(len = fread(send_buf,1,BUF_SIZE,fp)){
            if (len==BUF_SIZE)
                bytesum+=1;
            else
                byteleft+=len;
            // 转化为报文的形式再发送
			group sg = set_group(send_buf, len);
			group_to_char(sg, send_buf);
            while (1){
                sendto(client, send_buf, sizeof(group), 0, (sockaddr*)&saddr, sizeof(saddr));
                getlog(sg,0);
                // 如果接收失败或接收超时，重新发送报文
                int rec = recvfrom(client,recv_buf,sizeof(group),0,(sockaddr*)&saddr, &addr_len);
                if (rec < 0)
                    continue;
                // 接收到的
                group rg;
                char_to_group(recv_buf,rg);
                getlog(rg,1);
                // 如果接收到ACK报文，且序号与记录的序号相同，则说明传输成功
                if(rg.flags==2&&rg.seq==id+1){
                    id++;
                    break;
                }
            }
        }
        // 发送标志文件传输结束的报文
        char end_sym[] = "end";
        byteleft+=3;
        group sg = set_group(end_sym,3);
        group_to_char(sg,send_buf);
        while(1){
            sendto(client, send_buf, sizeof(group), 0, (sockaddr*)&saddr, sizeof(saddr));
            getlog(sg,0);
            // 如果接收失败或接收超时，重新发送报文
            int rec = recvfrom(client,recv_buf,sizeof(group),0,(sockaddr*)&saddr, &addr_len);
            if (rec < 0)
                continue;
            // 接收到的
            group rg;
            char_to_group(recv_buf,rg);
            getlog(rg,1);
            // 如果接收到ACK报文，且序号与记录的序号相同，则说明传输成功
            if(rg.flags==2&&rg.seq==id+1){
                id++;
                break;
            }
        }
        int t_ed = clock();
        cout<<"---------------------文件传输结束---------------------"<<endl;
        cout<<"传输"<<bytesum*BUF_SIZE+byteleft<<"字节，"
            <<"耗时"<<t_ed-t_st<<"毫秒，"
            <<"吞吐率为"<<(bytesum*BUF_SIZE+byteleft)*8.0/(t_ed-t_st)*1000<<"bps"<<endl;
        cout<<endl;
        fclose(fp);
    }

    closesocket(client);
    WSACleanup();
    return 0;
}