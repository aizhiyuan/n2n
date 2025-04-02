/**
 * (C) 2007-22 - ntop.org and contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */

/*
 * This file has a large amount of duplication with the edge_management.c
 * code.  In the fullness of time, they should both be merged
 */

#include <errno.h> // 引入 errno，用于错误处理
#include <stdbool.h>
#include <stdint.h>       // 引入用于 uint8_t, uint32_t 等类型的头文件
#include <stdio.h>        // 引入用于 snprintf, size_t, sprintf, NULL 等的头文件
#include <string.h>       // 引入用于字符串操作的函数，如 memcmp, memcpy, strerror, strncpy
#include <sys/types.h>    // 引入时间类型，ssize_t 等
#include "management.h"   // 引入管理相关的头文件
#include "n2n.h"          // 引入 n2n 网络协议相关的头文件
#include "n2n_define.h"   // 引入协议相关的常量，如 N2N_SN_PKTBUF_SIZE, UNPURGEABLE 等
#include "n2n_typedefs.h" // 引入 n2n 网络协议相关的数据类型
#include "strbuf.h"       // 引入用于字符串缓冲区操作的头文件
#include "uthash.h"       // 引入 uthash 哈希表库，用于处理哈希表操作

#ifdef _WIN32
#include "win32/defs.h" // 引入 Windows 专用定义
#else
#include <sys/socket.h> // 引入与 socket 相关的头文件
#endif

int load_allowed_sn_community(n2n_sn_t *sss); /* defined in sn_utils.c */

static void mgmt_reload_communities(mgmt_req_t *req, strbuf_t *buf)
{
    // 仅允许写操作
    if (req->type != N2N_MGMT_WRITE)
    {
        mgmt_error(req, buf, "writeonly");
        return;
    }

    // 如果没有提供社区文件，则返回错误
    if (!req->sss->community_file)
    {
        mgmt_error(req, buf, "nofile");
        return;
    }

    int ok = load_allowed_sn_community(req->sss); // 加载社区数据
    send_json_1uint(req, buf, "row", "ok", ok);   // 发送加载结果
}

static void mgmt_timestamps(mgmt_req_t *req, strbuf_t *buf)
{
    size_t msg_len;

    // 格式化时间戳信息并发送
    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"start_time\":%lu,"
                       "\"last_fwd\":%ld,"
                       "\"last_reg_super\":%ld}\n",
                       req->tag,
                       req->sss->start_time,
                       req->sss->stats.last_fwd,
                       req->sss->stats.last_reg_super);

    send_reply(req, buf, msg_len); // 发送回复
}

static void mgmt_packetstats(mgmt_req_t *req, strbuf_t *buf)
{
    size_t msg_len;

    // 转发数据包统计
    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"forward\","
                       "\"tx_pkt\":%lu}\n",
                       req->tag,
                       req->sss->stats.fwd);
    send_reply(req, buf, msg_len);

    // 广播数据包统计
    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"broadcast\","
                       "\"tx_pkt\":%lu}\n",
                       req->tag,
                       req->sss->stats.broadcast);
    send_reply(req, buf, msg_len);

    // 超节点注册数据包统计
    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"reg_super\","
                       "\"rx_pkt\":%lu,"
                       "\"nak\":%lu}\n",
                       req->tag,
                       req->sss->stats.reg_super,
                       req->sss->stats.reg_super_nak);

    send_reply(req, buf, msg_len);

    // 错误数据包统计
    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"errors\","
                       "\"tx_pkt\":%lu}\n",
                       req->tag,
                       req->sss->stats.errors);

    send_reply(req, buf, msg_len);
}

static void mgmt_communities(mgmt_req_t *req, strbuf_t *buf)
{
    size_t msg_len;
    struct sn_community *community, *tmp;
    dec_ip_bit_str_t ip_bit_str = {'\0'}; // 初始化 IP 位字符串

    // 遍历所有社区
    HASH_ITER(hh, req->sss->communities, community, tmp)
    {
        msg_len = snprintf(buf->str, buf->size,
                           "{"
                           "\"_tag\":\"%s\","
                           "\"_type\":\"row\","
                           "\"community\":\"%s\","
                           "\"purgeable\":%i,"
                           "\"is_federation\":%i,"
                           "\"ip4addr\":\"%s\"}\n",
                           req->tag,
                           (community->is_federation) ? "-/-" : community->community,
                           community->purgeable,
                           community->is_federation,
                           (community->auto_ip_net.net_addr == 0) ? "" : ip_subnet_to_str(ip_bit_str, &community->auto_ip_net));

        send_reply(req, buf, msg_len); // 发送社区信息
    }
}

static void mgmt_edges(mgmt_req_t *req, strbuf_t *buf)
{
    size_t msg_len;
    struct sn_community *community, *tmp;
    struct peer_info *peer, *tmpPeer;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;
    dec_ip_bit_str_t ip_bit_str = {'\0'}; // 初始化 IP 位字符串

    // 遍历所有社区及其边缘节点
    HASH_ITER(hh, req->sss->communities, community, tmp)
    {
        HASH_ITER(hh, community->edges, peer, tmpPeer)
        {

            // 格式化每个节点的信息并发送
            msg_len = snprintf(buf->str, buf->size,
                               "{"
                               "\"_tag\":\"%s\","
                               "\"_type\":\"row\","
                               "\"community\":\"%s\","
                               "\"ip4addr\":\"%s\","
                               "\"purgeable\":%i,"
                               "\"macaddr\":\"%s\","
                               "\"sockaddr\":\"%s\","
                               "\"proto\":\"%s\","
                               "\"desc\":\"%s\","
                               "\"last_seen\":%li}\n",
                               req->tag,
                               (community->is_federation) ? "-/-" : community->community,
                               (peer->dev_addr.net_addr == 0) ? "" : ip_subnet_to_str(ip_bit_str, &peer->dev_addr),
                               peer->purgeable,
                               (is_null_mac(peer->mac_addr)) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                               sock_to_cstr(sockbuf, &(peer->sock)),
                               ((peer->socket_fd >= 0) && (peer->socket_fd != req->sss->sock)) ? "TCP" : "UDP",
                               peer->dev_desc,
                               peer->last_seen);

            send_reply(req, buf, msg_len); // 发送节点信息
        }
    }
}

// Forward define so we can include this in the mgmt_handlers[] table
static void mgmt_help(mgmt_req_t *req, strbuf_t *buf);

static const mgmt_handler_t mgmt_handlers[] = {
    {.cmd = "supernodes", .help = "Reserved for edge", .func = mgmt_unimplemented},

    {.cmd = "stop", .flags = FLAG_WROK, .help = "Gracefully exit edge", .func = mgmt_stop},
    {.cmd = "verbose", .flags = FLAG_WROK, .help = "Manage verbosity level", .func = mgmt_verbose},
    {.cmd = "reload_communities", .flags = FLAG_WROK, .help = "Reloads communities and user's public keys", .func = mgmt_reload_communities},
    {.cmd = "communities", .help = "List current communities", .func = mgmt_communities},
    {.cmd = "edges", .help = "List current edges/peers", .func = mgmt_edges},
    {.cmd = "timestamps", .help = "Event timestamps", .func = mgmt_timestamps},
    {.cmd = "packetstats", .help = "Traffic statistics", .func = mgmt_packetstats},
    {.cmd = "help", .flags = FLAG_WROK, .help = "Show JSON commands", .func = mgmt_help},
};

// TODO: want to keep the mgmt_handlers defintion const static, otherwise
// this whole function could be shared
static void mgmt_help(mgmt_req_t *req, strbuf_t *buf)
{
    /*
     * Even though this command is readonly, we deliberately do not check
     * the type - allowing help replies to both read and write requests
     */

    int i;
    int nr_handlers = sizeof(mgmt_handlers) / sizeof(mgmt_handler_t);
    for (i = 0; i < nr_handlers; i++)
    {
        mgmt_help_row(req, buf, mgmt_handlers[i].cmd, mgmt_handlers[i].help);
    }
}

// TODO: DRY (Don't Repeat Yourself) - 这意味着我们希望消除重复的代码
static void handleMgmtJson(mgmt_req_t *req, char *udp_buf, const int recvlen)
{
    strbuf_t *buf;       // 用于管理缓冲区的指针
    char cmdlinebuf[80]; // 用于存储命令行的缓冲区，最大长度为 80 字符

    /* 保存命令行，避免重用 udp_buf */
    strncpy(cmdlinebuf, udp_buf, sizeof(cmdlinebuf) - 1); // 将 udp_buf 中的命令行复制到 cmdlinebuf
    cmdlinebuf[sizeof(cmdlinebuf) - 1] = 0;               // 确保字符串以 '\0' 结尾

    traceEvent(TRACE_DEBUG, "mgmt json %s", cmdlinebuf); // 打印调试信息，显示收到的 JSON 命令

    /* 重用栈上的缓冲区来存储所有字符串 */
    STRBUF_INIT(buf, udp_buf, N2N_SN_PKTBUF_SIZE); // 初始化缓冲区，以便后续操作

    if (!mgmt_req_init2(req, buf, (char *)&cmdlinebuf))
    {
        // 如果初始化失败，则退出函数
        return;
    }

    int handler;                                        // 用于存储处理命令的索引
    lookup_handler(handler, mgmt_handlers, req->argv0); // 查找与命令匹配的处理器

    if (handler == -1)
    {
        mgmt_error(req, buf, "unknowncmd"); // 如果没有找到匹配的处理器，返回错误
        return;
    }

    // 如果请求是写操作且该命令是只读的，则返回只读错误
    if ((req->type == N2N_MGMT_WRITE) && !(mgmt_handlers[handler].flags & FLAG_WROK))
    {
        mgmt_error(req, buf, "readonly");
        return;
    }

    /*
     * TODO:
     * 请求者提供的 tag 可能包含会使 JSON 无效的字符。
     * - 我们需要关心这个问题吗？
     */

    // 发送开始的 JSON 数据
    send_json_1str(req, buf, "begin", "cmd", req->argv0);

    // 调用命令对应的处理函数
    mgmt_handlers[handler].func(req, buf);

    // 发送结束的 JSON 数据
    send_json_1str(req, buf, "end", "cmd", req->argv0);
    return;
}

static int sendto_mgmt(n2n_sn_t *sss,
                       const struct sockaddr *sender_sock, socklen_t sock_size,
                       const uint8_t *mgmt_buf,
                       size_t mgmt_size)
{
    // 通过管理 socket 将管理缓冲区发送到指定的地址和端口
    ssize_t r = sendto(sss->mgmt_sock, (void *)mgmt_buf, mgmt_size, 0 /*flags*/,
                       sender_sock, sock_size);

    // 如果发送失败，记录错误并增加错误计数
    if (r <= 0)
    {
        ++(sss->stats.errors);                                                       // 增加超节点的错误统计
        traceEvent(TRACE_ERROR, "sendto_mgmt : sendto failed. %s", strerror(errno)); // 打印错误信息
        return -1;                                                                   // 返回错误
    }

    // 发送成功，返回 0
    return 0;
}

int process_mgmt(n2n_sn_t *sss,
                 const struct sockaddr *sender_sock, socklen_t sock_size,
                 char *mgmt_buf,
                 size_t mgmt_size,
                 time_t now)
{
    // 定义返回的缓冲区，用于存储处理后的响应数据
    char resbuf[N2N_SN_PKTBUF_SIZE];
    size_t ressize = 0;                   // 结果数据的大小
    mgmt_req_t req;                       // 管理请求结构体
    uint32_t num_edges = 0;               // 用于统计边缘节点的数量
    uint32_t num_comm = 0;                // 用于统计社区的数量
    uint32_t num = 0;                     // 当前社区的边缘节点编号
    struct sn_community *community, *tmp; // 用于遍历社区
    struct peer_info *peer, *tmpPeer;     // 用于遍历边缘节点
    macstr_t mac_buf;                     // 用于存储 MAC 地址的缓冲区
    n2n_sock_str_t sockbuf;               // 用于存储 socket 地址的缓冲区
    char time_buf[10];                    // 用于存储时间（9个数字 + 1个结束符）
    dec_ip_bit_str_t ip_bit_str = {'\0'}; // 用于存储 IP 位字符串的缓冲区，初始化为空

    traceEvent(TRACE_DEBUG, "process_mgmt"); // 打印调试信息

    // 初始化管理请求的各项参数
    req.eee = NULL;
    req.sss = sss;                                    // 超节点结构体
    req.mgmt_sock = sss->mgmt_sock;                   // 管理socket
    req.keep_running = sss->keep_running;             // 是否保持运行
    req.mgmt_password_hash = sss->mgmt_password_hash; // 管理密码哈希值
    memcpy(&req.sender_sock, sender_sock, sock_size); // 复制发送者的socket地址
    req.sock_len = sock_size;                         // 存储socket的长度

    // 为了防止栈上的垃圾数据，确保管理请求缓冲区以'\0'结尾
    mgmt_buf[mgmt_size] = 0;

    // 处理帮助命令
    if ((0 == memcmp(mgmt_buf, "help", 4)) || (0 == memcmp(mgmt_buf, "?", 1)))
    {
        // 格式化帮助信息并存储到 resbuf 中
        ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                            "Help for supernode management console:\n"
                            "\thelp                 | This help message\n"
                            "\treload_communities   | Reloads communities and user's public keys\n"
                            "\t<enter>              | Display status and statistics\n");
        // 发送帮助信息
        sendto_mgmt(sss, sender_sock, sock_size, (const uint8_t *)resbuf, ressize);
        return 0; /* 不再输出其他状态 */
    }

    // 处理重新加载社区的命令
    if (0 == memcmp(mgmt_buf, "reload_communities", 18))
    {
        if (!sss->community_file) // 如果没有指定社区文件
        {
            // 返回错误信息，说明没有提供社区文件
            ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                "No community file provided (-c command line option)\n");
            sendto_mgmt(sss, sender_sock, sock_size, (const uint8_t *)resbuf, ressize);
            return 0; /* 不再输出其他状态 */
        }
        traceEvent(TRACE_NORMAL, "'reload_communities' command");

        // 重新加载社区文件
        if (load_allowed_sn_community(sss))
        {
            ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                "Error while re-loading community file (not found or no valid content)\n");
            sendto_mgmt(sss, sender_sock, sock_size, (const uint8_t *)resbuf, ressize);
            return 0; /* 不再输出其他状态 */
        }
        // 如果重新加载成功，返回 OK 信息
        ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                            "OK.\n");
        sendto_mgmt(sss, sender_sock, sock_size, (const uint8_t *)resbuf, ressize);
        return 0; /* 不再输出其他状态 */
    }

    // 如果是 JSON 请求，调用处理函数
    if ((mgmt_buf[0] >= 'a' || mgmt_buf[0] <= 'z') && (mgmt_buf[1] == ' '))
    {
        handleMgmtJson(&req, mgmt_buf, mgmt_size); // 处理 JSON 请求
        return 0;
    }

    // 显示当前的状态信息
    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        " ### | TAP                 | MAC               | EDGE                      | HINT            | LAST SEEN\n");
    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "========================================================================================================\n");

    // 遍历社区并输出每个社区的信息
    HASH_ITER(hh, sss->communities, community, tmp)
    {
        if (num_comm) // 如果不是第一个社区，添加分隔线
            ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                "--------------------------------------------------------------------------------------------------------\n");
        num_comm++;
        num_edges += HASH_COUNT(community->edges); // 统计边缘节点数量

        // 输出社区的基本信息（名称、是否可清除、是否是联邦等）
        ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                            "%s '%s'\n",
                            (community->is_federation) ? "FEDERATION" : ((community->purgeable) ? "COMMUNITY" : "FIXED NAME COMMUNITY"),
                            (community->is_federation) ? "-/-" : community->community);
        sendto_mgmt(sss, sender_sock, sock_size, (const uint8_t *)resbuf, ressize);
        ressize = 0;

        // 遍历该社区的边缘节点，并输出每个边缘节点的信息
        num = 0;
        HASH_ITER(hh, community->edges, peer, tmpPeer)
        {
            // 格式化时间信息
            sprintf(time_buf, "%9u", (unsigned int)(now - peer->last_seen));

            // 格式化并输出每个边缘节点的详细信息，包括 IP 地址、MAC 地址、描述、最后一次看到的时间等
            ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                "%4u | %-19s | %-17s | %-21s %-3s | %-15s | %9s\n",
                                ++num,
                                (peer->dev_addr.net_addr == 0) ? ((peer->purgeable) ? "" : "-l") : ip_subnet_to_str(ip_bit_str, &peer->dev_addr),
                                (is_null_mac(peer->mac_addr)) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                                sock_to_cstr(sockbuf, &(peer->sock)),
                                ((peer->socket_fd >= 0) && (peer->socket_fd != sss->sock)) ? "TCP" : "",
                                peer->dev_desc,
                                (peer->last_seen) ? time_buf : "");

            sendto_mgmt(sss, sender_sock, sock_size, (const uint8_t *)resbuf, ressize);
            ressize = 0;
        }
    }
    // 输出分隔线
    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "========================================================================================================\n");

    // 输出系统的统计信息
    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "uptime %lu | ", (now - sss->start_time)); // 系统启动时间

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "edges %u | ", num_edges); // 边缘节点的数量

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "reg_sup %u | ", (unsigned int)sss->stats.reg_super); // 超节点注册的数量

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "reg_nak %u | ", (unsigned int)sss->stats.reg_super_nak); // 超节点注册 NAK 数量

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "errors %u \n", (unsigned int)sss->stats.errors); // 错误统计

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "fwd %u | ", (unsigned int)sss->stats.fwd); // 转发的数据包数量

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "broadcast %u | ", (unsigned int)sss->stats.broadcast); // 广播数据包数量

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "cur_cmnts %u\n", HASH_COUNT(sss->communities)); // 当前社区的数量

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "last_fwd  %lu sec ago | ", (long unsigned int)(now - sss->stats.last_fwd)); // 最后一次转发的时间

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "last reg  %lu sec ago\n\n", (long unsigned int)(now - sss->stats.last_reg_super)); // 最后一次注册的时间

    // 发送统计信息
    sendto_mgmt(sss, sender_sock, sock_size, (const uint8_t *)resbuf, ressize);

    return 0;
}
