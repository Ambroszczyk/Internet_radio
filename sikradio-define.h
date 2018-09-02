#include <vector>

#ifndef SIK_ZAD2_SIKRADIO_DEFINE_H
#define SIK_ZAD2_SIKRADIO_DEFINE_H

#define TTL_VALUE     6

#define MAX_MESS_SIZE  1024
#define MAX_PACK_SIZE 2048
#define MAX_STATION_NAME 64

using byte = uint8_t;

using namespace std;

enum message_t
{
    LOOKUP, REXMIT, REPLY, ERROR
};

class audio_pack
{
public:
    uint64_t session_id;
    uint64_t first_byte_num;
    vector<byte> audio_data;

    audio_pack();


    audio_pack(uint64_t sid, uint64_t fbn, byte *ad, size_t psize);
    audio_pack(uint64_t sid, uint64_t fbn);
    audio_pack(byte *data, size_t len) ;

    byte *serialize();

    /* For debuging */
    void print();

private:
    /* Deserialize long long type number. */
    uint64_t deserializell(const byte *buff);

    /* Serialize long long type number. */
    void serializell(byte *buff, uint64_t x);


    /* From host to network long long version. */
    uint64_t htonll(uint64_t x);

    /* From host to network long long version */
    uint64_t ntohll(uint64_t x);
};

/* Checks if ip number is correct. */
bool correct_ip(string &ip);

/* Checks if string has only letters. */
bool is_number(string &s);

/* Returns port number or -1 if port is not valid. */
int parse_port(string &s);

/* Returns type of message. */
message_t message_type(string &com);

/* Gives first line of message. */
string msg_fst_line(char *msg, ssize_t len);

/* Function validates if name is correct. */
bool valid_name(string& name);

void exit_cmdl();

#endif //SIK_ZAD2_SIKRADIO_DEFINE_H
