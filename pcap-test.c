#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h> //ntohs, struct in_addr 사용


struct ethernet_hdr
{
    uint8_t  dst[6];/* destination ethernet address */
    uint8_t  src[6];/* source ethernet address */
    uint16_t protocol;                 /* protocol */
};

struct ipv4_hdr
{
    //리틀 엔디안 환경에서는 하위 비트부터 채워져 version과 ihl 순서 반대로
    uint8_t ihl : 4, version : 4;       
    uint8_t tos;       /* type of service */
    uint16_t tot_len;         /* total length */
    uint16_t id;          /* identification */
    uint16_t offset;
    uint8_t ttl;          /* time to live */
    uint8_t protocol;            /* protocol */
    uint16_t hdr_checksum;         /* checksum */
    uint32_t src_add; /* source address */
    uint32_t dst_add; /* dest address */
};

struct tcp_hdr
{
    uint16_t src_port;       /* source port */
    uint16_t dst_port;       /* destination port */
    uint32_t seq_num;          /* sequence number */
    uint32_t ack_num;          /* acknowledgement number */
	//리틀 엔디안 환경에서는 하위 비트부터 채워져 data_offset과 reserved 순서 반대로
    uint8_t reserved : 4, data_offset : 4;        /* data offset */
    uint8_t  flags;       /* control flags */
    uint16_t window;         /* window */
    uint16_t checksum;         /* checksum */
    uint16_t urgent_p;         /* urgent pointer */
};

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

//전역변수 구조체 param의 선언과 param.dev를 NULL로 초기화 
Param param = {
        .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    //인자로 하나의 네트워크 인터페이스가 주어져야 함
    if (argc != 2) {
        usage();
        return false;
    }
    //param->dev(문자열)에 네트워크 인터페이스 넣음
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    //인자 개수가 정상적이지 않으면 종료
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    //pcap_open_live(인터페이스, 캡쳐할 바이트 수
    //, 1:모든 패킷/0:내 컴퓨터 패킷
    //, 패킷읽기 타임아웃(ms)
    //, 에러 메시지를 담을 버퍼)
    //반환값은 성공->핸들, 실패->NULL
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    //패킷을 읽기 위한 핸들 반환이 실패하면 종료
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        /*
        struct pcap_pkthdr {
            struct timeval ts;  // 패킷 캡처 시간
            bpf_u_int32 caplen; // 실제로 캡처한 길이 (이걸 사용해야 함)
            bpf_u_int32 len;    // 원래 패킷 길이
        };
        */
        struct pcap_pkthdr* header; //패킷 메타 정보
        const uint8_t* packet;       //패킷의 시작주소?
        struct ethernet_hdr* ethernet;
        struct ipv4_hdr* ip;
        struct tcp_hdr* tcp;
        uint16_t data_len = 0;
	uint8_t ip_header_len = 0;
	uint8_t tcp_header_len = 0; 
	uint32_t src_ip, dst_ip;

        /*
        int pcap_next_ex(
            pcap_t *p,                          //패킷 핸들
            struct pcap_pkthdr **pkt_header,    //
            const u_char **pkt_data);
        */
        //header에 다음 패킷의 메타데이터가 들어감
        //packet에 다음 패킷의 시작 주소가 들어감
        int res = pcap_next_ex(pcap, &header, &packet);
        //res == 1: 정상수신
        //res == 0: 타임아웃
        //res == -1: 에러
        //res == -2: eof
        if (res == 0) continue; //타임아웃이면 다시 시도
        //에러거나 EOF면 종료
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
        	printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
        	break;
        }

        
        ethernet = (struct ethernet_hdr*)packet;
        if (ntohs(ethernet->protocol) != 0x0800) {
		printf("Not an IPv4 packet\n");
        	continue;
        } //IPv4 패킷이 아니면 다시 시도
        

        ip = (struct ipv4_hdr*)(packet + sizeof(*ethernet));
        //TCP 패킷이 아니면 다시 시도
        if (ip->protocol != 6) {
		printf("Not a TCP packet\n");
        	continue;
        }
	ip_header_len = (ip->ihl) << 2; 

		
        tcp = (struct tcp_hdr*)(packet + sizeof(*ethernet) + ip_header_len);
	tcp_header_len = (tcp->data_offset) << 2; 

        //데이터 길이 계산
	data_len = ntohs(ip->tot_len) - ip_header_len - tcp_header_len;

        //캡쳐한 길이가 ethernet header + ip header + tcp header보다 작으면 다시 시도
        if (header->caplen < sizeof(*ethernet) + ip_header_len + tcp_header_len) {
		printf("Captured length is less than the sum of Ethernet, IP, and TCP headers\n");
        	continue;
        }

        //Ethernet Header의 src mac / dst mac
	printf("<Ethernet Header>\n"); 
	printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet->src[0], ethernet->src[1], ethernet->src[2], ethernet->src[3], ethernet->src[4], ethernet->src[5]);
	printf("dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet->dst[0], ethernet->dst[1], ethernet->dst[2], ethernet->dst[3], ethernet->dst[4], ethernet->dst[5]);
        
        //IP Header의 src ip / dst ip
	printf("\n<IP Header>\n");  
	src_ip = ntohl(ip->src_add);
	dst_ip = ntohl(ip->dst_add);    
	printf("src ip: %u.%u.%u.%u\n", (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF, (src_ip >> 8) & 0xFF, src_ip & 0xFF); 
	printf("dst ip: %u.%u.%u.%u\n", (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF, (dst_ip >> 8) & 0xFF, dst_ip & 0xFF);
		
        //TCP Header의 src port / dst port
	printf("\n<TCP Header>\n");
	printf("src port: %u\n", ntohs(tcp->src_port));
	printf("dst port: %u\n", ntohs(tcp->dst_port));
	
        //Payload(Data)의 hexadecimal value(최대 20바이트까지만)
        if(data_len > 0) printf("\n<Payload>\n");
	for (int i = 0; i < data_len && i < 20; i++) {
		printf("%02x ", packet[sizeof(*ethernet) + ip_header_len + tcp_header_len + i]);
        }

        //실제로 캡쳐한 길이 출력
        printf("\n%u bytes captured\n-----------------\n", header->caplen);
    }

    pcap_close(pcap);
}
