#include<iostream>
#include<Winsock2.h>
#pragma comment(lib, "ws2_32.lib")
using namespace std;

// 定义报文长度、源和目标的地址与端口等
#define BUF_SIZE 2048
#define SERVER_ID 127<<24+1  //表示127.0.0.1
#define CLIENT_ID 127<<24+1
#define SERVER_PORT 7998
#define CLIENT_PORT 7999
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
			<< endl;
	}
	if (a == 1){
		cout << "recv"
			<< "\tseq " << g.seq
			<< "\tSYN " << (g.flags&0b1)
			<< "\tACK " << ((g.flags&0b10)>>1)
			<< "\tFIN " << ((g.flags&0b100)>>2)
			<< "\tchecksum " << g.checksum
            << "\tlength" << g.f_length
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

// 验证校验和
bool ver_checksum(group *g){
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
    sum = (USHORT)sum;
    USHORT checksum = g->checksum;
    if((checksum+sum)==0xffff){
        return 1;
    }
    else{
        cout<<"校验和出错"<<endl;
        return 0;
    }
}

// 设置报文内容
group set_group(char *buf,int len,bool SYN=0,bool ACK=0,bool FIN=0){
    group g;
    memset(&g,0,sizeof(group));
    if(SYN) g.flags+=0b1;
    if(ACK) g.flags+=0b10;
    if(FIN) g.flags+=0b100;
    g.s_ip = SERVER_ID;
    g.d_ip = CLIENT_ID;
    g.s_port = SERVER_PORT;
    g.d_port = CLIENT_PORT;
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
bool shake(SOCKET& server, sockaddr_in& caddr){
    int addr_len = sizeof(caddr);
    while(1){
        int rec = recvfrom(server, recv_buf, sizeof(group), 0, (sockaddr*)&caddr, &addr_len);
        group rg;
        char_to_group(recv_buf,rg);
        getlog(rg,1);
        // 接收到SYN报文，则返回ACK报文
        if(rg.flags==1){
            id = rg.seq+1;
            group sg = ACK_UDP();
            group_to_char(sg,send_buf);
            sendto(server, send_buf, sizeof(group), 0, (sockaddr*)&caddr, sizeof(caddr));
            getlog(sg,0);
            break;
        }
    }
    cout << "连接成功！"<<endl;
    return 1;
}

// 挥手，当接收到client传来的FIN报文时触发
bool wave(SOCKET& server, sockaddr_in& caddr){
    group sg = ACK_UDP();
    group_to_char(sg,send_buf);
    sendto(server, send_buf, sizeof(group), 0, (sockaddr*)&caddr, sizeof(caddr));
    getlog(sg,0);
    cout << "成功断开连接！"<<endl;
    return 1;
}

int main(){
    init();
    // 创建服务端套接字
    SOCKET server = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    //填充地址信息
    sockaddr_in saddr,caddr;
    int addr_len = sizeof(sockaddr_in);
    saddr.sin_family = AF_INET;
	saddr.sin_port = htons(SERVER_PORT);
	saddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
    caddr.sin_family = AF_INET;
	caddr.sin_port = htons(CLIENT_PORT);
	caddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
    // 绑定服务端套接字与地址
    bind(server,(sockaddr*)&saddr,addr_len);
    cout<<"等待客户端连接"<<endl;
    shake(server,caddr);
    // 接收文件
    while(1){
        cout<<"---------------------等待接收文件---------------------"<<endl;
        // 首先接收文件名/接收断开连接的FIN报文
        group name;
        while(int rec = recvfrom(server, recv_buf, sizeof(group), 0, (sockaddr*)&caddr, &addr_len)){
            char_to_group(recv_buf,name);
            cout<<"接收文件："<<name.buf<<endl;
            getlog(name,1);
            // 校验和不对或序号不对，不更新序号id，发送上次发送的ACK报文，等待发送端重新发送数据
            if(!ver_checksum(&name)||name.seq!=id){
                group sg = ACK_UDP();
                group_to_char(sg,send_buf);
                sendto(server, send_buf, sizeof(group), 0, (sockaddr*)&caddr, sizeof(caddr));
                getlog(sg,0);
                continue;
            }
            // 若传输正常，先判断是否要退出，若不退出则更新序号id后再发送ACK报文
            id = name.seq+1;
            if(name.flags==4){
                wave(server,caddr);
                return 0;    
            }
            group sg = ACK_UDP();
            group_to_char(sg,send_buf);
            sendto(server, send_buf, sizeof(group), 0, (sockaddr*)&caddr, sizeof(caddr));
            getlog(sg,0);
            break;
        }
        // 再接收文件实际的内容
        FILE *fp;
        fopen_s(&fp,name.buf,"wb");
        int len;
        // 只要文件未传输完就一直循环，一次最多读2048字节的内容
        while(len=recvfrom(server, recv_buf, sizeof(group), 0, (sockaddr*)&caddr, &addr_len)){
            group rg;
            char_to_group(recv_buf,rg);
            getlog(rg,1);
            // 校验和不对或序号不对，不更新序号id，发送上次发送的ACK报文，等待发送端重新发送数据
            if(!ver_checksum(&rg)||rg.seq!=id){
                group sg = ACK_UDP();
                group_to_char(sg,send_buf);
                sendto(server, send_buf, sizeof(group), 0, (sockaddr*)&caddr, sizeof(caddr));
                getlog(sg,0);
                continue;
            }
            // 传输正确，更新id后发送新的ACK报文
            id = rg.seq+1;
            group sg = ACK_UDP();
            group_to_char(sg,send_buf);
            sendto(server, send_buf, sizeof(group), 0, (sockaddr*)&caddr, sizeof(caddr));
            getlog(sg,0);
            // 文件传输完毕，则退出
            if (!strcmp(rg.buf, "end")) 
				break;
            // 否则写入文件
            int ret = fwrite(rg.buf,1,rg.f_length,fp);
            if(ret<rg.f_length){
                cout<<"写入文件失败！"<<endl;
                return 0;
            }
        }
        cout<<"---------------------文件接收结束---------------------"<<endl;
        cout<<endl;
        fclose(fp);
    }
    closesocket(server);
    WSACleanup();
    return 0;
}