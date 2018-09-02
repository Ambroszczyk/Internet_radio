#include <vector>
#include <netinet/in.h>
#include <regex>
#include <iostream>
#include <arpa/inet.h>
#include "sikradio-define.h"

using namespace std;


audio_pack::audio_pack() = default;


audio_pack::audio_pack(uint64_t sid, uint64_t fbn, byte *ad, size_t psize) : session_id(sid), first_byte_num(fbn),
                                                                             audio_data(psize)
{
    memcpy(&audio_data[0], ad, audio_data.size());
}

audio_pack::audio_pack(uint64_t sid, uint64_t fbn) : session_id(sid), first_byte_num(fbn)
{}

audio_pack::audio_pack(byte *data, size_t len) : session_id(deserializell(data)),
                                                 first_byte_num(deserializell(data + 8)),
                                                 audio_data(data + 16, data + len)
{}

byte *audio_pack::serialize()
{
    /* calling function is responsible for freeing data */
    auto *data = new byte[audio_data.size() + 16];
    serializell(data, session_id);
    serializell(data + 8, first_byte_num);
    memcpy(data + 16, &audio_data[0], audio_data.size());
    return data;
}

/* For debuging */
void audio_pack::print()
{
    cerr << "session_id: " << session_id
         << " first_byte_num: " << first_byte_num
         << " audio_data.size()" << audio_data.size()
         << endl;
}


/* Deserialize long long type number. */
uint64_t audio_pack::deserializell(const byte *buff)
{
    uint64_t x = 0;
    memcpy(&x, buff, 8);
    return ntohll(x);
}

/* Serialize long long type number. */
void audio_pack::serializell(byte *buff, uint64_t x)
{
    uint64_t netx = htonll(x);
    memcpy(buff, &netx, 8);
}

/* From host to network long long version. */
uint64_t audio_pack::htonll(uint64_t x)
{
    if (htonl(1) == 1) {
        return x;
    } else
        return (((uint64_t) htonl((uint32_t) x)) << 32) + htonl((uint32_t) ((x) >> 32));
}

/* From host to network long long version */
uint64_t audio_pack::ntohll(uint64_t x)
{
    if (ntohl(1) == 1) {
        return x;
    } else
        return (((uint64_t) ntohl((uint32_t) x)) << 32) + ntohl((uint32_t) ((x) >> 32));
}

/* Checks if ip number is correct. */
bool correct_ip(string &ip)
{
    struct sockaddr_in sa;
    return 1 == inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr));
}

/* Checks if string has only letters. */
bool is_number(string &s)
{
    size_t len = (size_t) s.length();
    for (size_t i = 0; i < len; i++) {
        if (!isdigit(s[i]))
            return false;
    }
    return true;
}

/* Returns port number or -1 if port is not valid. */
int parse_port(string &s)
{
    //As it was not precised, we accept dynamic ports.
    const static int MAX_PORT_NUMBER = 65535;
    const static int MIN_PORT_NUMBER = 1024;

    size_t len = s.length();
    if (!is_number(s))
        return -1;

    if (len > 5 || len == 0 || s[0] == '0')
        return -1;

    int res = stoi(s);
    if (res > MAX_PORT_NUMBER || res < MIN_PORT_NUMBER)
        return -1;

    return res;
}

/* Returns type of message. */
message_t message_type(string &com)
{

    regex rexmit("LOUDER_PLEASE (0|[1-9][0-9]*)(,[1-9][0-9]*)*");
    regex reply("BOREWICZ_HERE [0-9.]+ [1-9][0-9]{3,4} [\x20-\x7F]+");
    if (strcmp(com.c_str(), "ZERO_SEVEN_COME_IN") == 0)
        return LOOKUP;
    if (regex_match(com, rexmit))
        return REXMIT;
    if (regex_match(com, reply))
        return REPLY;
    return ERROR;
}

/* Gives first line of message. */
string msg_fst_line(char *msg, ssize_t len)
{
    if (len < MAX_MESS_SIZE)
        msg[len] = 0;
    else
        msg[MAX_MESS_SIZE] = 0;
    string strbuff = string(msg);
    stringstream ss(strbuff);
    string fsl;
    getline(ss, fsl);
    return fsl;
}

/* Function validates if name is correct. */
bool valid_name(string &name)
{
    /* Cannot be empty. */
    if (name.size() == 0)
        return false;
    if (name.size() > MAX_STATION_NAME)
        return false;
    for (auto l : name) {
        if (l < 32 || l > 127)
            return false;
    }
    return true;
}

/* Command line arguments are not good, return 1 status */
void exit_cmdl()
{
    cerr << "Wrong command line argument(s)" << endl;
    exit(EXIT_FAILURE);
}
