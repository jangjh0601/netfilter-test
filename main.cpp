#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

char* host;

typedef struct id_and_flag{
    int id;
    int flag;
}id_and_flag;

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

int filter(unsigned char* buf, int size, char* host){
    int i;
    int j;
    struct libnet_ipv4_hdr* IP4 = (struct libnet_ipv4_hdr*) buf;
    uint8_t ipv4_size = (IP4->ip_hl) << 2;
    struct libnet_tcp_hdr* TCP = (struct libnet_tcp_hdr*)(buf + ipv4_size);
    uint8_t tcp_size = TCP->th_off << 2;

   unsigned char* HTTP = (unsigned char *)(buf + ipv4_size + tcp_size);
   int host_idx;
   int user_agent;
   char list[100] = "\0";
   if (HTTP[0] == 'G' && HTTP[1] == 'E' && HTTP[2] == 'T') {
       for (i = 0; i < size - (ipv4_size + tcp_size); i++){
           if (HTTP[i] == 'H' && HTTP[i+1] == 'o' && HTTP[i+2] == 's' && HTTP[i+3] == 't'){
               host_idx = i+6;
               printf("host_idx = %d\n", host_idx);
           }
           else if (HTTP[i] == 'U' && HTTP[i+1] == 's' && HTTP[i+2] == 'e' && HTTP[i+3] == 'r' && HTTP[i+4] == '-'){
               user_agent = i;
               printf("user-agent = %d\n", user_agent);
           }
       }
       //list = (char *)malloc(sizeof(char) * (user_agent - 2 - host_idx + 1));
       j = 0;
       for(i = host_idx; i < user_agent - 2; i++){
           list[j] =  HTTP[i];
           j++;
       }
       printf("\n");
   }

   if (strcmp((const char*)list, (const char*)host) == 0){
       printf("%s\n", list);
       return 1;
   }
   else
       return 0;
}

/* returns packet id */
struct id_and_flag print_pkt (struct nfq_data *tb)
{
    id_and_flag pkt;
    pkt.id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        pkt.id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
            ntohs(ph->hw_protocol), ph->hook, pkt.id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0){
        printf("payload_len=%d\n", ret);
        dump(data, ret); // data: ipv4 start pointer, ret = size
        pkt.flag = filter(data, ret, host);
    }

    fputc('\n', stdout);

    return pkt;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    id_and_flag pkt;
    pkt = print_pkt(nfa);
    printf("entering callback\n");

    if (pkt.flag == 0){
        printf("ACCEPT\n");
        return nfq_set_verdict(qh, pkt.id, NF_ACCEPT, 0, NULL);
    }
    else if (pkt.flag == 1){
        printf("DROP\n");
        return nfq_set_verdict(qh, pkt.id, NF_DROP, 0, NULL);
    }
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    host = argv[1];

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}

