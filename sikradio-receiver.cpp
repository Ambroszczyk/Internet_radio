#include <cstdint>
#include <cstdlib>
#include <string>
#include <cstring>
#include <thread>
#include <zconf.h>
#include <arpa/inet.h>
#include <ctime>
#include <set>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <poll.h>
#include <signal.h>
#include <algorithm>
#include <map>

#include "err.h"
#include "sikradio-define.h"

#define MAX_UI_MSG_SIZE 1024
#define MAX_UI_SOCKS (_POSIX_OPEN_MAX - 3)

#define WILL (char)251
#define IAC (char)255
#define ESC 27
#define ECHO 1
#define SUPPRESS_GO_AHEAD 3

using namespace std;

using pii = pair<int, int>;
using time_point_t = std::chrono::time_point<std::chrono::system_clock>;

const string UP("\x1b\x5b\x41");
const string DOWN("\x1b\x5b\x42");

/* Global variables */
string discover_addr = "255.255.255.255";
uint16_t ctrl_port = 35090;
uint16_t ui_port = 15090;
size_t bsize = 65536;
int rtime = 250;
string name;
bool was_n_param = false;

/* Counter of retransmitions threads */
atomic<int> thread_ctr(0);

/* List of all the stations */
mutex mut_stlist;
condition_variable cv_stlist;

/* Sockets and mutexes for multithread communication */
int ctrl_sock, rexmit_sock, ui_sock;
struct sockaddr_in ctrl_remote_address, rexmit_remote_address;
mutex mut_rexmit;

std::mutex mut_ret;
set<uint64_t> set_ret;

/* Ending program parameteres cv and mutexes */
bool finish_ui = false;
bool end_prog = false;
mutex mut_end_prog;
condition_variable cv_end_prog;

/* ********************************CLASSES*********************************** */

/* Suppose every radio station has nonempty name, all information bout station
 * are here.  */
class station
{
public:
    string name;
    string ip;
    uint16_t port;
    int data_sock;
    time_point_t last_reply;
    struct sockaddr_in remote_address;

    bool operator==(const station &other) const
    {
        return (name == other.name) && (ip == other.ip) &&
               (port == other.port);
    }

    /* Used only to have set of stations sorted by name. */
    bool operator<(const station &s) const
    {
        if (name < s.name)
            return true;
        else {
            if (name == s.name) {
                if (ip < s.ip)
                    return true;
                else {
                    if (ip == s.ip) {
                        return port < s.port;
                    }
                }
            }
        }
        return false;
    }

    station() = default;

    /* Assumes that msg is in the right format. */
    station(string &msg) : station()
    {
        auto end = msg.end();
        auto itr1 = find(msg.begin(), end, ' ');
        auto itr2 = find(++itr1, end, ' ');
        string tmp_ip = string(itr1, itr2);
        itr1 = find(++itr2, end, ' ');
        string tmp = string(itr2, itr1);
        int tmp_port = parse_port(tmp);
        string tmp_name = string(++itr1, end);
        if (correct_ip(tmp_ip) && tmp_port != -1) {
            name = tmp_name;
            ip = tmp_ip;
            port = (uint16_t) tmp_port;
        }
    }


    void connect_data()
    {
        struct ip_mreq ip_mreq;
        struct sockaddr_in local_address;
        struct timeval tv;


        /* otworzenie gniazda */
        data_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (data_sock < 0)
            syserr("socket");

        tv.tv_sec = 0;
        tv.tv_usec = 500000;
        if (setsockopt(data_sock, SOL_SOCKET, SO_RCVTIMEO, (void *) &tv,
                       sizeof(tv)) < 0)
            syserr("setsockopt timeout");

        int enable = 1;
        if (setsockopt(data_sock, SOL_SOCKET, SO_REUSEADDR, &enable,
                       sizeof(int)) < 0)
            syserr("setsockopt(SO_REUSEADDR) failed");

        /* podpięcie się do grupy rozsyłania (ang. multicast) */
        ip_mreq.imr_interface.s_addr = htonl(INADDR_ANY);
        if (inet_aton(ip.c_str(), &ip_mreq.imr_multiaddr) == 0)
            syserr("inet_aton");
        if (setsockopt(data_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                       (void *) &ip_mreq,
                       sizeof ip_mreq) < 0)
            syserr("setsockopt");

        local_address.sin_family = AF_INET;
        local_address.sin_addr.s_addr = htonl(INADDR_ANY);
        local_address.sin_port = htons(port);
        if (bind(data_sock, (struct sockaddr *) &local_address,
                 sizeof local_address) < 0)
            syserr("bind");
    }

    void disconnect_data()
    {
        if (close(data_sock) < 0)
            syserr("socket close");
    }

    void connect_rexmit()
    {
        lock_guard<mutex> lr(mut_rexmit);
        rexmit_remote_address = remote_address;
    }

};

/* Class represents list on stations, station are sorted using comparison
 * operator on strings */
class stations_list
{
public:
    set<station> stations;
    station curr;
    int ver;
    bool activ;

    stations_list() : curr(), ver(0), activ(false)
    {
        string dashes;
        dashes.resize(72, '-');
        dashes += "\r\n";
        menu_header = dashes + "  SIK_Radio\r\n" + dashes;
        menu_buttom = dashes;
    }

    void push_or_update(station s)
    {
        auto itr = stations.find(s);
        if (itr != stations.end()) {
            stations.erase(itr);
        } else {
            ver++;
        }
        s.last_reply = chrono::system_clock::now();
        stations.insert(s);

        if (!activ) {
            if ((was_n_param && (name == s.name)) || !was_n_param) {
                curr = s;
                activ = true;
                ver++;
            }
        }
    }

    void pop(const station &s)
    {
        if (stations.find(s) == stations.end())
            return;
        if (s == curr) {
            curr = station();
            activ = false;
        }
        stations.erase(s);
        ver++;
    }

    void erase_timeouted()
    {
        auto time = chrono::system_clock::now();
        set<station> my_stations(stations);
        for (auto &s : my_stations) {
            if (time - s.last_reply > chrono::seconds(20))
                pop(s);
        }
    }

    /* Change current station up or down */
    void crs_move(int high)
    {
        if (stations.size() < 2)
            return;
        if (high == 0)
            return;


        int pos_idx = 0;
        for (auto itr = stations.begin(); itr != stations.end(); ++itr) {
            if (*itr == curr)
                break;
            pos_idx++;
        }
        if ((size_t) pos_idx == (stations.size() - 1) && high > 0)
            return;
        if (pos_idx == 0 && high < 0)
            return;

        int new_pos = min(max(0, pos_idx + high), (int) (stations.size() - 1));

        ver++;

        auto itr = stations.begin();
        for (int i = 0; i < new_pos; ++i) {
            ++itr;
        }

        curr = *itr;
    }

    /* Generetes menu to be displayed */
    string gen_menu()
    {
        string s = menu_header;
        for (auto itr = stations.begin(); itr != stations.end(); ++itr) {
            string prev = "    ";
            if ((*itr) == curr) {
                prev = "  > ";
            }
            s += prev + itr->name + "\r\n";
        }
        return s + menu_buttom;
    }

private:
    string menu_header;
    string menu_buttom;
};

/* Buffer of audio packes */
class ap_buffer
{
public:
    bool activ;
    uint64_t byte0;
    size_t psize;


    ap_buffer() : activ(false), read_pos(0), put_pos(0), data(), curr_size(0)
    {}

    void init_by_pack(audio_pack ap)
    {
        size_t psize = ap.audio_data.size();
        data.resize(bsize / psize);
        this->psize = psize;
        this->byte0 = ap.first_byte_num;
        this->activ = true;
        put(ap);
    }

    /* Adds bites of packes which require retransmitions */
    bool put(audio_pack ap, set<uint64_t> *retrmiss = nullptr)
    {
        if (data.empty())
            return false;
        size_t steps;
        if (curr_size != 0) {
            uint64_t max_b = max_byte();
            uint64_t min_b = min_byte();
            uint64_t pack_b = ap.first_byte_num;

            /* Ignore older pack */
            if (pack_b < byte0)
                return false;

            /* Ignore older pack */
            if (pack_b < min_b)
                return false;

            /* Retransmition, insert pack. */
            if (pack_b < max_b) {
                steps = (max_b - pack_b) / psize;
                data[(put_pos - 1 - steps + curr_size) % curr_size] = ap;
                {
                    lock_guard<mutex> lk(mut_ret);
                    if (set_ret.count(pack_b) != 0)
                        set_ret.erase(pack_b);
                }
                return true;
            }
            if (max_b == pack_b)
                return false;

            steps = (pack_b - max_b) / psize;

            /* Fill with empty packs */
            for (size_t i = 1; i <= steps - 1; i++) {
                if (retrmiss != nullptr)
                    retrmiss->insert(max_b + i * psize);
                data[put_pos] = audio_pack(ap.session_id, max_b + i * psize);
                inc_put_pos();
            }
        }
        data[put_pos] = ap;
        inc_put_pos();
        return true;
    }

    audio_pack read()
    {
        if (curr_size == 0) {
            return audio_pack();
        }
        audio_pack tmp = data[read_pos];
        read_pos = (read_pos + 1) % curr_size;
        return tmp;
    }

    uint64_t max_byte()
    {
        if (curr_size == 0)
            return 0;
        size_t prev = (put_pos == 0) ? curr_size - 1 : put_pos - 1;
        return data[prev].first_byte_num;
    }

    uint64_t min_byte()
    {
        return max_byte() - ((curr_size - 1) * psize);
    }

    /* Check if buffer should start writing data to stdout */
    bool start_stdout()
    {
        return max_byte() > byte0 + (3 * bsize / 4);
    }

    void clear()
    {
        data.clear();
        read_pos = 0;
        put_pos = 0;
        curr_size = 0;
        byte0 = 0;
        psize = 0;
    }

    /* For debuging */
    void print()
    {
        cerr << "activ: " << activ
             << " data.size(): " << data.size()
             << " curr_size: " << curr_size
             << " byte0: " << byte0
             << " psize: " << psize
             << " bsize: " << bsize
             << " max_byte: " << max_byte()
             << " min_byte: " << min_byte()
             << " waits_for_byte: " << byte0 + (3 * bsize / 4)
             << endl;
    }

private:
    size_t read_pos;
    size_t put_pos;
    vector<audio_pack> data;
    size_t curr_size;

    void inc_put_pos()
    {
        if (curr_size < data.size())
            curr_size++;
        put_pos = (put_pos + 1) % data.size();
    }
};

ap_buffer buffer;
mutex mut_buffer;
condition_variable cv_buffer;

stations_list stlist;


/* ****************************SIMPLY FUNCTIONS****************************** */

bool end_program()
{
    lock_guard<mutex> lk(mut_end_prog);
    return end_prog;
}

bool station_playes(station &s)
{
    unique_lock<mutex> lk(mut_stlist);
    return stlist.activ && stlist.curr == s;
}

string rexmit_msg(uint64_t to_send)
{
    return "LOUDER_PLEASE " + to_string(to_send) + "\n";
}

void clear_ret_sets()
{
    lock_guard<mutex> lk(mut_ret);
    set_ret.clear();
}

static void catch_int(int sig)
{
    finish_ui = true;
    fprintf(stderr,
            "Signal %d catched. No new connections will be accepted. Wait for"
            " the end of the program.\n", sig);
}


void turn_on_character_mode(int sock)
{
    char buffer[6] = {IAC, WILL, ECHO, IAC, WILL, SUPPRESS_GO_AHEAD};
    if (write(sock, buffer, 6) != 6) {
        syserr("turn of character mode write");
    }
}

void clear_screen(int sock)
{
    char buffer[2] = {ESC, 'c'};
    if (write(sock, buffer, 2) != 2) {
        syserr("screen clearing");
    }
}

void hide_cursor(int sock)
{
    char buffer[6] = {ESC, '[', '?', '2', '5', 'l'};
    if (write(sock, buffer, 6) != 6) {
        syserr("hide cursor");
    }
}

void send_string(int sock, const string &s)
{
    ssize_t snd_len = write(sock, s.c_str(), s.length());
    if ((size_t) snd_len != s.length()) {
        syserr("writing to client socket");
    }
}

/* ****************************THREADS MAINS********************************* */

/* Ctrl thread main function */
void manage_ctrl()
{
    struct sockaddr_in client_address;
    int sflags, flags;
    size_t len;
    ssize_t rcv_len, snd_len;
    socklen_t rcva_len, snda_len;
    char buffer[MAX_MESS_SIZE];
    char discv_mess[20] = "ZERO_SEVEN_COME_IN\n";

    snda_len = (socklen_t) sizeof(ctrl_remote_address);
    while (!end_program()) {
        auto end = chrono::system_clock::now() + chrono::seconds(5);
        while (chrono::system_clock::now() < end) {
            rcva_len = (socklen_t) sizeof(client_address);

            flags = 0; // we do not request anything special
            errno = 0;
            rcv_len = recvfrom(ctrl_sock, buffer, sizeof(buffer), flags,
                               (struct sockaddr *) &client_address,
                               &rcva_len);
            if (errno == EAGAIN ||
                errno == EWOULDBLOCK) {
                errno = 0;
            } else {
                if (rcv_len < 0)
                    conterr("error on datagram from client socket");
                else {
                    string fst_line = msg_fst_line(buffer, rcv_len);
                    message_t msg = message_type(fst_line);
                    if (msg != REPLY)
                        continue;
                    station s(fst_line);
                    if (!valid_name(s.name))
                        continue;
                    s.remote_address = client_address;
                    {
                        unique_lock<mutex> lk(mut_stlist);
                        stlist.push_or_update(s);
                    }
                    cv_stlist.notify_all();
                }
            }
            {
                unique_lock<mutex> lk(mut_stlist);
                stlist.erase_timeouted();
            }
        }
        sflags = 0;
        len = 19;

        snd_len = sendto(ctrl_sock, discv_mess, len, sflags,
                         (struct sockaddr *) &ctrl_remote_address,
                         snda_len);

        if ((size_t) snd_len != len)
            conterr("error on sending datagram to client socket");
    }
}

/* Retransmitions threads main function */
void manage_retransmition(uint64_t my_ret)
{
    thread_ctr++;
    ssize_t snd_len;
    int ctr = 0;
    socklen_t snda_len = (socklen_t) sizeof(ctrl_remote_address);

    while (!end_program()) {
        auto end = chrono::system_clock::now() + chrono::milliseconds(rtime);
        {
            lock_guard<mutex> lk(mut_ret);

            if (set_ret.find(my_ret) == set_ret.end()) {
                thread_ctr--;
                cv_end_prog.notify_all();
                return;
            }
        }
        ctr++;
        string rex_msg = rexmit_msg(my_ret);

        const char *tmp = rex_msg.c_str();
        auto tmp_size = rex_msg.size();
        {
            {
                lock_guard<mutex> lr(mut_rexmit);
                snd_len = sendto(rexmit_sock, tmp, tmp_size, 0,
                                 (struct sockaddr *) &rexmit_remote_address,
                                 snda_len);
            }
        }
        if ((size_t) snd_len != tmp_size)
            conterr("error on sending rexmit datagram to client socket");

        auto now = chrono::system_clock::now();
        this_thread::sleep_for(end - now);

    }
    thread_ctr--;
    cv_end_prog.notify_all();
}

/* Buffer thread main function */
void manage_buffer()
{
    while (!end_program()) {
        size_t psize;
        uint64_t exp_byte;
        {
            std::unique_lock<std::mutex> lk(mut_buffer);
            cv_buffer.wait(lk, [&] {
                return (buffer.activ && buffer.start_stdout()) || end_program();
            });
            if (end_program())
                return;
            exp_byte = buffer.byte0;
            psize = buffer.psize;
        }

        while (!end_program()) {
            audio_pack ap;
            {
                lock_guard<mutex> lk(mut_buffer);
                ap = buffer.read();

                if (ap.audio_data.empty() || ap.first_byte_num != exp_byte) {
                    buffer.activ = false;
                    break;
                }
            }

            for (auto b: ap.audio_data)
                cout << b;
            exp_byte += psize;
        }
    }
}

/* Playing thread main function */
void manage_stdout()
{
    station my_stat;
    byte read_buff[MAX_PACK_SIZE];
    ssize_t rcv_len;
    uint64_t my_sesid = 0;
    bool first_pack;

    while (!end_program()) {
        first_pack = true;
        {
            unique_lock<mutex> lk(mut_stlist);
            cv_stlist.wait(lk, [] { return stlist.activ || end_program(); });
            if (end_program())
                return;
            my_stat = stlist.curr;
        }

        my_stat.connect_data();
        my_stat.connect_rexmit();
        do {
            errno = 0;
            rcv_len = read(my_stat.data_sock, read_buff, sizeof read_buff);
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                errno = 0;
                break;
            }

            if (rcv_len < 0) {
                syserr("read");
            }
            audio_pack ap(read_buff, rcv_len);
            if (first_pack) {
                first_pack = false;
                my_sesid = ap.session_id;
                {
                    lock_guard<mutex> lk(mut_buffer);
                    buffer.clear();
                    buffer.init_by_pack(ap);
                }
            } else {
                /* Ignore. */
                if (ap.session_id < my_sesid)
                    continue;
                /* Start again. */
                if (ap.session_id > my_sesid) {
                    break;
                }

                mut_buffer.lock();
                if (!buffer.activ) {
                    mut_buffer.unlock();
                    break;
                }

                set<uint64_t> rets;
                buffer.put(ap, &rets);

                if (!rets.empty()) {
                    {
                        lock_guard<mutex> lk(mut_ret);
                        set_ret.insert(rets.begin(), rets.end());
                    }
                    for (auto r : rets) {
                        thread{[=] { manage_retransmition(r); }}.detach();
                    }
                }

                /* For buffer */
                if (buffer.start_stdout()) {
                    mut_buffer.unlock();
                    cv_buffer.notify_all();
                } else {
                    mut_buffer.unlock();
                }
            }
        } while (station_playes(my_stat));
        clear_ret_sets();
        my_stat.disconnect_data();
    }
}

/* Ui thread main function */
void manage_ui()
{
    struct pollfd client[MAX_UI_SOCKS];
    char buf[MAX_UI_MSG_SIZE];
    ssize_t rval;
    int msgsock, active_clients, ret, high;
    int lver = -1;

    if (signal(SIGINT, catch_int) == SIG_ERR) {
        perror("Unable to change signal handler");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < MAX_UI_SOCKS; ++i) {
        client[i].fd = -1;
        client[i].events = POLLIN | POLLOUT;
        client[i].revents = 0;
    }
    active_clients = 0;

    client[0].fd = ui_sock;

    if (listen(client[0].fd, 5) == -1) {
        perror("Starting to listen");
        exit(EXIT_FAILURE);
    }

    do {
        high = 0;
        for (int i = 0; i < MAX_UI_SOCKS; ++i)
            client[i].revents = 0;

        if (finish_ui && client[0].fd >= 0) {
            if (close(client[0].fd) < 0)
                perror("close");
            client[0].fd = -1;
        }

        ret = poll(client, MAX_UI_SOCKS, 500);
        if (ret < 0)
            perror("poll");
        else {
            if (ret > 0) {
                if (!finish_ui && (client[0].revents & POLLIN)) {
                    msgsock = accept(client[0].fd, (struct sockaddr *) 0,
                                     (socklen_t *) 0);
                    if (msgsock == -1)
                        perror("accept");
                    else {
                        int j;
                        for (j = 1; j < MAX_UI_SOCKS; ++j) {
                            if (client[j].fd == -1) {
                                client[j].fd = msgsock;
                                active_clients += 1;
                                clear_screen(msgsock);
                                turn_on_character_mode(msgsock);
                                hide_cursor(msgsock);
                                {
                                    lock_guard<mutex> lk(mut_stlist);
                                    string menu = stlist.gen_menu();
                                    send_string(msgsock, menu);
                                }
                                break;
                            }
                        }
                        if (j >= MAX_UI_SOCKS) {
                            cerr << "Too many clients" << endl;
                            if (close(msgsock) < 0)
                                perror("close");
                        }
                    }
                }
                for (int i = 1; i < MAX_UI_SOCKS; ++i) {
                    if (client[i].fd != -1
                        && (client[i].revents & (POLLIN | POLLERR))) {
                        rval = read(client[i].fd, buf, MAX_UI_MSG_SIZE);
                        if (rval < 0) {
                            perror("Reading stream message");
                            if (close(client[i].fd) < 0)
                                perror("close");
                            client[i].fd = -1;
                            active_clients -= 1;
                        } else if (rval == 0) {
                            cerr << "Ending connection" << endl;
                            if (close(client[i].fd) < 0)
                                perror("close");
                            client[i].fd = -1;
                            active_clients -= 1;
                        } else {
                            string message(buf, (unsigned long) rval);
                            if (message == UP)
                                high--;
                            if (message == DOWN)
                                high++;
                        }
                    }
                }
                {
                    lock_guard<mutex> lk(mut_stlist);
                    stlist.crs_move(high);
                    if (lver != stlist.ver) {
                        lver = stlist.ver;
                        string menu = stlist.gen_menu();
                        for (int i = 1; i < MAX_UI_SOCKS; ++i) {
                            if (client[i].fd != -1 &&
                                (client[i].revents & POLLOUT)) {
                                clear_screen(client[i].fd);
                                hide_cursor(client[i].fd);
                                send_string(client[i].fd, menu);
                            }
                        }
                    }

                }
            }
        }
    } while (!finish_ui || active_clients > 0);

    if (client[0].fd >= 0) {
        if (close(client[0].fd) < 0)
            perror("Closing main socket");
    }
    {
        lock_guard<mutex> lk(mut_end_prog);
        end_prog = true;
    }
    cv_end_prog.notify_all();
    cv_stlist.notify_all();
    cv_buffer.notify_all();
}


/* ******************************INITIALIZING******************************** */


bool parse_commandline(int argc, char *argv[])
{
    /* checks if commad line argument are correct and filles variables */
    int tmp;

    map<char, int> was;
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
            case 'd':
                if (!correct_ip(val))
                    return false;
                discover_addr = val;
                break;
            case 'C':
                tmp = parse_port(val);
                if (tmp == -1)
                    return false;
                ctrl_port = (uint16_t) tmp;
                break;
            case 'U':
                tmp = parse_port(val);
                if (tmp == -1)
                    return false;
                ui_port = (uint16_t) tmp;
                break;
            case 'b':
                if (!is_number(val))
                    return false;
                bsize = (size_t) stoi(val);
                if (bsize == 0)
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
                was_n_param = true;
                name = val;
                break;
            default:
                return false;
        }
    }
    return true;
}

int init_ctrl_sock()
{
    int sock, optval;
    struct timeval tv;
    struct sockaddr_in local_address;


    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        syserr("socket");

    optval = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (void *) &optval,
                   sizeof optval) < 0)
        syserr("setsockopt broadcast");

    optval = TTL_VALUE;
    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (void *) &optval,
                   sizeof optval) < 0)
        syserr("setsockopt multicast ttl");

    tv.tv_sec = 0;
    tv.tv_usec = 100000;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (void *) &tv, sizeof(tv)) <
        0)
        syserr("setsockopt timeout");

    local_address.sin_family = AF_INET;
    local_address.sin_addr.s_addr = htonl(INADDR_ANY);
    local_address.sin_port = htons(0);
    if (bind(sock, (struct sockaddr *) &local_address, sizeof local_address) <
        0)
        syserr("bind");

    ctrl_remote_address.sin_family = AF_INET;
    ctrl_remote_address.sin_port = htons(ctrl_port);
    if (inet_aton(discover_addr.c_str(), &ctrl_remote_address.sin_addr) == 0)
        syserr("inet_aton");

    return sock;
}

int init_ui_sock()
{
    struct timeval tv;
    struct sockaddr_in server_address;

    int sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        syserr("socket");

    tv.tv_sec = 0;
    tv.tv_usec = 250000;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (void *) &tv, sizeof(tv)) <
        0)
        syserr("setsockopt timeout");

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(ui_port);

    if (bind(sock, (struct sockaddr *) &server_address,
             sizeof(server_address)) < 0)
        syserr("bind");

    return sock;
}

void init_socks()
{
    ctrl_sock = init_ctrl_sock();
    ui_sock = init_ui_sock();
    rexmit_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (rexmit_sock < 0)
        syserr("socket");
}


/* ***********************************MAIN*********************************** */



int main(int argc, char *argv[])
{
    if (!parse_commandline(argc, argv)) {
        exit_cmdl();
    }

    init_socks();
    thread{manage_ctrl}.detach();
    thread{manage_stdout}.detach();
    thread{manage_buffer}.detach();
    thread{manage_ui}.detach();

    {
        unique_lock<mutex> lk(mut_end_prog);
        cv_end_prog.wait(lk, [] { return end_prog && thread_ctr.load() == 0; });
    }
    exit(EXIT_SUCCESS);
}
