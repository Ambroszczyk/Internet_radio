#include <iostream>
#include <cstring>
#include <ctime>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <set>
#include "err.h"
#include <thread>
#include <mutex>
#include <sys/time.h>
#include <chrono>
#include <fstream>
#include <algorithm>
#include <map>
#include <sstream>
#include "sikradio-define.h"

#define MAX_MESS_SIZE  1024

using namespace std;

/* Global variables */
string mcast_addr;
uint16_t data_port = 25090;
uint16_t ctrl_port = 35090;
size_t psize = 512; /* 512B */
size_t fsize = 128000; /* 128kB */
int rtime = 250; /* miliseconds */
string name = "Nienazwany Nadajnik";
/* sockets */
int data_sock, ctrl_sock;

bool stdin_end = false;

struct sockaddr_in data_remote_address;

/* Set of retransmitions */
set<uint64_t> retrmiss_set;
mutex ret_mut;

/* Curr sesion id */
uint64_t session_id;

/* Message of sent pactages */
class mess_fifo
{
public:
    mess_fifo(size_t size) : data(size), next_pos(0), find_pos(0), curr_size(0)
    {}

    void push(audio_pack ap)
    {
        if (data.size() == 0)
            return;
        data[next_pos] = ap;
        if (curr_size < data.size())
            curr_size++;
        next_pos = (next_pos + 1) % data.size();
    }

    audio_pack *find(size_t id)
    {
        if (curr_size == 0)
            return nullptr;
        size_t old_pos = find_pos;
        do {
            if (data[find_pos].first_byte_num == id) {
                return &data[find_pos];
            }
            find_pos = (find_pos + 1) % curr_size;
        } while (old_pos != find_pos);
        return nullptr;
    }

    /* For debuging */
    pair<int, int> dump_fifo()
    {
        if (curr_size == data.size()) {
            return pair<int, int>(data[next_pos].first_byte_num,
                                  data[(next_pos - 1 + curr_size) %
                                       curr_size].first_byte_num);
        } else {
            return pair<int, int>(data[0].first_byte_num,
                                  data[(next_pos - 1 + curr_size) %
                                       curr_size].first_byte_num);
        }
    };
private:
    vector<audio_pack> data;
    size_t next_pos;
    size_t find_pos;
    size_t curr_size;
};

/* Splits words by delim */
void split(const std::string &str, vector<string> &cont, char delim = ' ')
{
    std::stringstream ss(str);
    std::string token;
    while (std::getline(ss, token, delim)) {
        cont.push_back(token);
    }
}

/* Check if ip is multicast address */
bool is_multicast(string ip_addr)
{
    vector<string> v;
    split(ip_addr, v, '.');
    int val = stoi(v[0]);
    return val >= 224 && val <= 239;
}


/* Checks if commad line argument are correct and filles variables. */
bool parse_commandline(int argc, char *argv[])
{
    int tmp;

    map<char, bool> was;
    for (int i = 1; i < argc; i += 2) {
        char *par = argv[i];
        if (strlen(par) != 2 || par[0] != '-')
            return false;
        if (i + 1 == argc)
            return false;

        string val = string(argv[i + 1]);

        auto opt = par[1];
        /* duplicated option */
        if (was.find(opt) != was.end()) {
            return false;
        }
        was[opt] = true;


        switch (opt) {
            case 'a':
                mcast_addr = val;
                if (!correct_ip(mcast_addr))
                    return false;
                if (!is_multicast(mcast_addr))
                    return false;
                break;
            case 'P':
                tmp = parse_port(val);
                if (tmp == -1)
                    return false;
                data_port = (uint16_t) tmp;
                break;
            case 'C':
                tmp = parse_port(val);
                if (tmp == -1)
                    return false;
                ctrl_port = (uint16_t) tmp;
                break;
            case 'p':
                if (!is_number(val))
                    return false;
                psize = stoi(val);
                if (psize > 65536)
                    return false;
                break;
            case 'f':
                if (!is_number(val))
                    return false;
                fsize = stoi(val);
                if (fsize == 0)
                    return false;
                break;
            case 'R':
                if (!is_number(val))
                    return false;
                rtime = stoi(val);
                if (rtime == 0)
                    return false;
                break;
            case 'n':
                if (!valid_name(val))
                    return false;
                name = val;
                break;
            default:
                return false;
        }
    }
    return was.find('a') != was.end();
}

void init_data_socket()
{
    int optval;

    data_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (data_sock < 0)
        syserr("socket");

    optval = 1;
    if (setsockopt(data_sock, SOL_SOCKET, SO_BROADCAST, (void *) &optval,
                   sizeof optval) < 0)
        syserr("setsockopt broadcast");

    optval = TTL_VALUE;
    if (setsockopt(data_sock, IPPROTO_IP, IP_MULTICAST_TTL, (void *) &optval,
                   sizeof optval) < 0)
        syserr("setsockopt multicast ttl");

    data_remote_address.sin_family = AF_INET;
    data_remote_address.sin_port = htons(data_port);
    if (inet_aton(mcast_addr.c_str(), &data_remote_address.sin_addr) == 0)
        syserr("inet_aton");
}

void init_ctrl_socket()
{
    struct sockaddr_in local_address;
    struct timeval tv;

    ctrl_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctrl_sock < 0)
        syserr("socket");

    tv.tv_sec = 2;
    tv.tv_usec = 0;
    if (setsockopt(ctrl_sock, SOL_SOCKET, SO_RCVTIMEO, (void *) &tv,
                   sizeof(tv)) < 0)
        syserr("setsockopt timeout");

    int enable = 1;
    if (setsockopt(ctrl_sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) <
        0)
        syserr("setsockopt(SO_REUSEADDR) failed");

    local_address.sin_family = AF_INET;
    local_address.sin_addr.s_addr = htonl(INADDR_ANY);
    local_address.sin_port = htons(ctrl_port);
    if (bind(ctrl_sock, (struct sockaddr *) &local_address,
             sizeof local_address) < 0)
        syserr("bind");
}

void init_sockets()
{
    init_data_socket();
    init_ctrl_socket();
}

void close_sockets()
{
    close(data_sock);
    close(ctrl_sock);
}

/* Initialize id of current session. */
bool set_session_id()
{
    struct timeval tv;
    if (gettimeofday(&tv, nullptr) != 0)
        return false;
    session_id = (uint64_t) tv.tv_sec;
    return true;
}

/* Parses rexmit reply message */
set<int> parse_rexmit(string &com)
{
    set<int> res;
    vector<string> tmp;
    vector<string> numbers;

    split(com, tmp);
    split(tmp[1], numbers, ',');

    for (auto &s : numbers) {
        if (s.length() > 9)
            continue;
        res.insert(stoi(s));
    }
    return res;
}

/* Static framework for reply message */
const string reply_message()
{
    static string reply;
    if (reply.empty()) {
        reply = "BOREWICZ_HERE " + mcast_addr + " " + to_string(data_port) +
                " " + name + "\n";
    }
    return reply;
}

/* Main function for ctrl thread. */
void manage_ctrl()
{
    struct sockaddr_in client_address;
    socklen_t rcva_len, snda_len;
    int flags, sflags;
    ssize_t len, snd_len;

    char buffer[MAX_MESS_SIZE];

    snda_len = (socklen_t) sizeof(client_address);
    while (!stdin_end) {
        do {
            rcva_len = (socklen_t) sizeof(client_address);
            flags = 0; // we do not request anything special
            errno = 0;
            len = recvfrom(ctrl_sock, buffer, sizeof(buffer), flags,
                           (struct sockaddr *) &client_address, &rcva_len);
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                errno = 0;
                break;
            }
            if (len < 0)
                syserr("error on datagram from client socket");
            else {

                string fst_line = msg_fst_line(buffer, len);
                message_t com = message_type(fst_line);

                string reply;
                set<int> s;
                switch (com) {
                    case LOOKUP:
                        sflags = 0;
                        reply = reply_message();

                        snd_len = sendto(ctrl_sock, reply.c_str(),
                                         reply.length(), sflags,
                                         (struct sockaddr *) &client_address,
                                         snda_len);
                        if ((size_t) snd_len != reply.length())
                            conterr("error sending datagram to client socket");
                        break;
                    case REXMIT:
                        s = parse_rexmit(fst_line);
                        ret_mut.lock();
                        retrmiss_set.insert(s.begin(), s.end());
                        ret_mut.unlock();
                        break;
                    case REPLY:
                        break;
                    case ERROR:
                        break;

                }
            }
        } while (len > 0);
    }
}

/* Sends one pactage to given muticast addres */
void send_pack(audio_pack &ap)
{
    socklen_t static snda_len = (socklen_t) sizeof(data_remote_address);
    byte *data = ap.serialize();
    size_t len = psize + 16;

    ssize_t snd_len = sendto(data_sock, data, len, 0,
                             (struct sockaddr *) &data_remote_address,
                             snda_len);

    if ((size_t) snd_len != len)
        syserr("error on sending datagram to clients socket");
    delete[] data;
}

/* Main function for data thread. */
void manage_data()
{
    /* Ignore if retransmition is not in fifo */
    mess_fifo fifo((size_t) fsize / psize);
    auto *in_char = new char[psize];
    auto *in_byte = new byte[psize];
    uint64_t pack_nr = 0;

    while (!stdin_end) {
        auto end = chrono::system_clock::now() + chrono::milliseconds(rtime);
        while (chrono::system_clock::now() < end) {
            cin.read(in_char, psize);
            if (!cin || (size_t) cin.gcount() != psize) {
                stdin_end = true;
                break;
            }
            memcpy(in_byte, in_char, psize);
            audio_pack ap = audio_pack(session_id, pack_nr, in_byte, psize);

            send_pack(ap);

            fifo.push(ap);
            pack_nr += psize;
        }
        ret_mut.lock();
        set<uint64_t> rets = retrmiss_set;
        retrmiss_set.clear();
        ret_mut.unlock();

        for (auto rid : rets) {
            audio_pack *ap = fifo.find(rid);
            if (ap) {
                send_pack(*ap);
            }
        }
    }
    delete[] in_char;
    delete[] in_byte;
}


int main(int argc, char *argv[])
{
    if (!parse_commandline(argc, argv)) {
        exit_cmdl();
    }
    if (!set_session_id()) {
        syserr("Session id setting error");
    }
    init_sockets();
    thread tr_ctrl{manage_ctrl};
    thread tr_data{manage_data};
    tr_ctrl.join();
    tr_data.join();
    close_sockets();
}
