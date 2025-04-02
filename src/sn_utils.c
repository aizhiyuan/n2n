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

#include <errno.h> // for errno, EAFNOSUPPORT
#include <stdbool.h>
#include <stdint.h>            // for uint8_t, uint32_t, uint16_t, uint64_t
#include <stdio.h>             // for sscanf, snprintf, fclose, fgets, fopen
#include <stdlib.h>            // for free, calloc, getenv
#include <string.h>            // for memcpy, NULL, memset, size_t, strerror
#include <sys/param.h>         // for MAX
#include <sys/time.h>          // for timeval
#include <sys/types.h>         // for ssize_t
#include <time.h>              // for time_t, time
#include "auth.h"              // for ascii_to_bin, calculate_dynamic_key
#include "config.h"            // for PACKAGE_VERSION
#include "header_encryption.h" // for packet_header_encrypt, packet_header_...
#include "n2n.h"               // for sn_community, n2n_sn_t, peer_info
#include "n2n_regex.h"         // for re_matchp, re_compile
#include "n2n_wire.h"          // for encode_buf, encode_PEER_INFO, encode_...
#include "pearson.h"           // for pearson_hash_128, pearson_hash_32
#include "portable_endian.h"   // for be16toh, htobe16
#include "random_numbers.h"    // for n2n_rand, n2n_rand_sqr, n2n_seed, n2n...
#include "sn_selection.h"      // for sn_selection_criterion_gather_data
#include "speck.h"             // for speck_128_encrypt, speck_context_t
#include "uthash.h"            // for UT_hash_handle, HASH_ITER, HASH_DEL

#ifdef _WIN32
#include "win32/defs.h"
#else
#include <arpa/inet.h>   // for inet_addr, inet_ntoa
#include <netinet/in.h>  // for ntohl, in_addr_t, sockaddr_in, INADDR...
#include <netinet/tcp.h> // for TCP_NODELAY
#include <sys/select.h>  // for FD_ISSET, FD_SET, select, FD_SETSIZE
#include <sys/socket.h>  // for recvfrom, shutdown, sockaddr_storage
#endif

#define HASH_FIND_COMMUNITY(head, name, out) HASH_FIND_STR(head, name, out)

int resolve_create_thread(n2n_resolve_parameter_t **param, struct peer_info *sn_list);
int resolve_check(n2n_resolve_parameter_t *param, uint8_t resolution_request, time_t now);
int resolve_cancel_thread(n2n_resolve_parameter_t *param);

static ssize_t sendto_peer(n2n_sn_t *sss,
                           const struct peer_info *peer,
                           const uint8_t *pktbuf,
                           size_t pktsize);

static uint16_t reg_lifetime(n2n_sn_t *sss);

static int update_edge(n2n_sn_t *sss,
                       const n2n_common_t *cmn,
                       const n2n_REGISTER_SUPER_t *reg,
                       struct sn_community *comm,
                       const n2n_sock_t *sender_sock,
                       const SOCKET socket_fd,
                       n2n_auth_t *answer_auth,
                       int skip_add,
                       time_t now);

static int re_register_and_purge_supernodes(n2n_sn_t *sss,
                                            struct sn_community *comm,
                                            time_t *p_last_re_reg_and_purge,
                                            time_t now,
                                            uint8_t forced);

static int purge_expired_communities(n2n_sn_t *sss,
                                     time_t *p_last_purge,
                                     time_t now);

static int sort_communities(n2n_sn_t *sss,
                            time_t *p_last_sort,
                            time_t now);

int process_mgmt(n2n_sn_t *sss,
                 const struct sockaddr *sender_sock, socklen_t sock_size,
                 char *mgmt_buf,
                 size_t mgmt_size,
                 time_t now);

static int process_udp(n2n_sn_t *sss,
                       const struct sockaddr *sender_sock, socklen_t sock_size,
                       const SOCKET socket_fd,
                       uint8_t *udp_buf,
                       size_t udp_size,
                       time_t now);

/* ************************************** */

void close_tcp_connection(n2n_sn_t *sss, n2n_tcp_connection_t *conn)
{

    // 定义社区和节点结构体的指针，用于遍历社区和连接信息
    struct sn_community *comm, *tmp_comm;
    struct peer_info *edge, *tmp_edge;

    // 如果传入的连接为空，直接返回
    if (!conn)
        return;

    // 查找与给定 socket_fd 对应的 peer 信息，并删除该连接
    HASH_ITER(hh, sss->communities, comm, tmp_comm)
    {
        // 遍历当前社区的所有 peer 信息（连接）
        HASH_ITER(hh, comm->edges, edge, tmp_edge)
        {
            // 如果发现该连接的 socket_fd 与当前 peer 的 socket_fd 相同
            if (edge->socket_fd == conn->socket_fd)
            {
                // 从社区的 edges 哈希表中删除该连接（peer）
                HASH_DEL(comm->edges, edge);
                // 释放该连接的内存
                free(edge);
                // 跳转到关闭连接部分，退出循环
                goto close_conn; /* break - level 2 */
            }
        }
    }

close_conn:
    // 关闭连接，先通过 shutdown 完成关闭连接的双向通信
    shutdown(conn->socket_fd, SHUT_RDWR);
    // 关闭该 socket
    closesocket(conn->socket_fd);
    // 标记连接为不活动，表示该连接将稍后被删除
    conn->inactive = 1;
}

/* *************************************************** */

// 为用户认证生成共享密钥；只能在已知联盟名称（-F）并且社区列表完全读取（-c）之后进行
void calculate_shared_secrets(n2n_sn_t *sss)
{

    // 定义社区和用户结构体指针，用于遍历社区和用户信息
    struct sn_community *comm, *tmp_comm;
    sn_user_t *user, *tmp_user;

    // 记录日志事件，表示开始计算共享密钥
    traceEvent(TRACE_INFO, "started shared secrets calculation for edge authentication");

    // 生成私钥，基于联盟名称和前缀字符，跳过联盟名称中的 '*' 字符
    generate_private_key(sss->private_key, sss->federation->community + 1); /* skip '*' federation leading character */

    // 遍历所有社区
    HASH_ITER(hh, sss->communities, comm, tmp_comm)
    {
        // 如果该社区是联盟（federation），则跳过
        if (comm->is_federation)
        {
            continue;
        }

        // 遍历该社区中的所有允许的用户
        HASH_ITER(hh, comm->allowed_users, user, tmp_user)
        {
            // 计算每个用户的共享密钥（使用 ECDH 算法）
            generate_shared_secret(user->shared_secret, sss->private_key, user->public_key);

            // 将共享密钥准备为加密/解密的密钥上下文
            // 为 shared_secret_ctx 分配内存并初始化
            user->shared_secret_ctx = (he_context_t *)calloc(1, sizeof(speck_context_t));

            // 初始化加密上下文，使用 Speck 算法和共享密钥
            speck_init((speck_context_t **)&user->shared_secret_ctx, user->shared_secret, 128);
        }
    }

    // 记录日志事件，表示共享密钥计算完成
    traceEvent(TRACE_NORMAL, "calculated shared secrets for edge authentication");
}

// 计算动态密钥
void calculate_dynamic_keys(n2n_sn_t *sss)
{

    // 定义社区结构体指针，用于遍历所有社区
    struct sn_community *comm, *tmp_comm = NULL;

    // 记录日志事件，表示开始计算动态密钥
    traceEvent(TRACE_INFO, "calculating dynamic keys");

    // 遍历所有社区（哈希表）
    HASH_ITER(hh, sss->communities, comm, tmp_comm)
    {
        // 跳过联盟类型的社区
        if (comm->is_federation)
        {
            continue;
        }

        // 如果该社区有用户验证（用户/密码认证），则计算动态密钥
        if (comm->allowed_users)
        {
            // 计算动态密钥，传入的参数包括目标位置、时间、社区名称和联盟名称
            calculate_dynamic_key(comm->dynamic_key,                      /* 计算结果存放地址 */
                                  sss->dynamic_key_time,                  /* 时间，所有社区使用相同时间 */
                                  (uint8_t *)comm->community,             /* 社区名称 */
                                  (uint8_t *)sss->federation->community); /* 联盟名称 */

            // 更改数据包头部的动态密钥，用于加密/解密
            packet_header_change_dynamic_key(comm->dynamic_key,
                                             &(comm->header_encryption_ctx_dynamic),
                                             &(comm->header_iv_ctx_dynamic));

            // 记录调试日志，表示已经为该社区计算了动态密钥
            traceEvent(TRACE_DEBUG, "calculated dynamic key for community '%s'", comm->community);
        }
    }
}

// 计算动态密钥
void calculate_dynamic_keys(n2n_sn_t *sss)
{

    // 定义社区结构体指针，用于遍历所有社区
    struct sn_community *comm, *tmp_comm = NULL;

    // 记录日志事件，表示开始计算动态密钥
    traceEvent(TRACE_INFO, "calculating dynamic keys");

    // 遍历所有社区（哈希表）
    HASH_ITER(hh, sss->communities, comm, tmp_comm)
    {
        // 跳过联盟类型的社区
        if (comm->is_federation)
        {
            continue;
        }

        // 如果该社区有用户验证（用户/密码认证），则计算动态密钥
        if (comm->allowed_users)
        {
            // 计算动态密钥，传入的参数包括目标位置、时间、社区名称和联盟名称
            calculate_dynamic_key(comm->dynamic_key,                      /* 计算结果存放地址 */
                                  sss->dynamic_key_time,                  /* 时间，所有社区使用相同时间 */
                                  (uint8_t *)comm->community,             /* 社区名称 */
                                  (uint8_t *)sss->federation->community); /* 联盟名称 */

            // 更改数据包头部的动态密钥，用于加密/解密
            packet_header_change_dynamic_key(comm->dynamic_key,
                                             &(comm->header_encryption_ctx_dynamic),
                                             &(comm->header_iv_ctx_dynamic));

            // 记录调试日志，表示已经为该社区计算了动态密钥
            traceEvent(TRACE_DEBUG, "calculated dynamic key for community '%s'", comm->community);
        }
    }
}

/** 加载允许的社区列表。现有的/之前的社区将被删除，
 *  成功时返回 0，文件未找到时返回 -1，未找到有效条目时返回 -2
 */
int load_allowed_sn_community(n2n_sn_t *sss)
{

    // 定义一些用于读取文件和处理数据的临时变量
    char buffer[4096], *line, *cmn_str, net_str[20], format[20];

    sn_user_t *user, *tmp_user;
    n2n_desc_t username;
    n2n_private_public_key_t public_key;
    char ascii_public_key[(N2N_PRIVATE_PUBLIC_KEY_SIZE * 8 + 5) / 6 + 1];

    dec_ip_str_t ip_str = {'\0'};
    uint8_t bitlen;
    in_addr_t net;
    uint32_t mask;
    FILE *fd = fopen(sss->community_file, "r"); // 打开社区配置文件

    // 用于遍历社区、边缘连接、节点关联等的结构体指针
    struct sn_community *comm, *tmp_comm, *last_added_comm = NULL;
    struct peer_info *edge, *tmp_edge;
    node_supernode_association_t *assoc, *tmp_assoc;
    n2n_tcp_connection_t *conn;
    time_t any_time = 0;

    uint32_t num_communities = 0;

    struct sn_community_regular_expression *re, *tmp_re;
    uint32_t num_regex = 0;
    int has_net;

    // 如果文件未打开，返回文件未找到错误
    if (fd == NULL)
    {
        traceEvent(TRACE_WARNING, "File %s not found", sss->community_file);
        return -1;
    }

    // 重置数据结构 ------------------------------

    // 向所有从用户/密码认证的社区的边缘发送 RE_REGISTER_SUPER 消息
    send_re_register_super(sss);

    // 删除所有社区（不包括联盟）
    HASH_ITER(hh, sss->communities, comm, tmp_comm)
    {
        if (comm->is_federation)
        {
            continue; // 跳过联盟
        }

        // 删除社区中的所有边缘
        HASH_ITER(hh, comm->edges, edge, tmp_edge)
        {
            // 删除所有边缘关联（与其他超级节点的关联）
            HASH_ITER(hh, comm->assoc, assoc, tmp_assoc)
            {
                HASH_DEL(comm->assoc, assoc);
                free(assoc);
            }

            // 如果连接的 socket_fd 有效，关闭 TCP 连接并删除边缘
            if ((edge->socket_fd != sss->sock) && (edge->socket_fd >= 0))
            {
                HASH_FIND_INT(sss->tcp_connections, &(edge->socket_fd), conn);
                close_tcp_connection(sss, conn); // 关闭连接并删除边缘
            }
            else
            {
                HASH_DEL(comm->edges, edge);
                free(edge);
            }
        }

        // 删除社区中的所有允许的用户
        HASH_ITER(hh, comm->allowed_users, user, tmp_user)
        {
            free(user->shared_secret_ctx);
            HASH_DEL(comm->allowed_users, user);
            free(user);
        }

        // 删除社区
        HASH_DEL(sss->communities, comm);
        if (NULL != comm->header_encryption_ctx_static)
        {
            // 删除头部加密密钥
            free(comm->header_encryption_ctx_static);
            free(comm->header_iv_ctx_static);
            free(comm->header_encryption_ctx_dynamic);
            free(comm->header_iv_ctx_dynamic);
        }
        free(comm);
    }

    // 删除所有的社区名称匹配的正则表达式
    HASH_ITER(hh, sss->rules, re, tmp_re)
    {
        HASH_DEL(sss->rules, re);
        free(re);
    }

    // 准备读取文件数据 -------------------------------

    // 设置新的动态密钥时间，所有社区都需要重新计算动态密钥
    sss->dynamic_key_time = time(NULL);
    // 联盟中的超级节点也需要重新注册
    re_register_and_purge_supernodes(sss, sss->federation, &any_time, any_time, 1 /* 强制 */);

    // 格式定义，用于解析用户密钥条目
    sprintf(format, "%c %%%ds %%%lds", N2N_USER_KEY_LINE_STARTER, N2N_DESC_SIZE - 1, sizeof(ascii_public_key) - 1);

    // 逐行读取配置文件
    while ((line = fgets(buffer, sizeof(buffer), fd)) != NULL)
    {
        int len = strlen(line);

        if ((len < 2) || line[0] == '#') // 跳过空行和注释行
        {
            continue;
        }

        len--;
        while (len > 0)
        {
            if ((line[len] == '\n') || (line[len] == '\r'))
            {
                line[len] = '\0';
                len--;
            }
            else
            {
                break;
            }
        }

        // 用户密钥行用于边缘认证？
        if (line[0] == N2N_USER_KEY_LINE_STARTER)
        { /* 特殊的第一个字符 */
            if (sscanf(line, format, username, ascii_public_key) == 2)
            { /* 格式正确 */
                if (last_added_comm)
                { /* 是否有有效的社区来添加用户 */
                    user = (sn_user_t *)calloc(1, sizeof(sn_user_t));
                    if (user)
                    {
                        // 设置用户名
                        memcpy(user->name, username, sizeof(username));
                        // 设置公钥
                        ascii_to_bin(public_key, ascii_public_key);
                        memcpy(user->public_key, public_key, sizeof(public_key));
                        // 共享密钥稍后计算
                        HASH_ADD(hh, last_added_comm->allowed_users, public_key, sizeof(n2n_private_public_key_t), user);
                        traceEvent(TRACE_INFO, "added user '%s' with public key '%s' to community '%s'",
                                   user->name, ascii_public_key, last_added_comm->community);
                        // 启用头部加密
                        last_added_comm->header_encryption = HEADER_ENCRYPTION_ENABLED;
                        packet_header_setup_key(last_added_comm->community,
                                                &(last_added_comm->header_encryption_ctx_static),
                                                &(last_added_comm->header_encryption_ctx_dynamic),
                                                &(last_added_comm->header_iv_ctx_static),
                                                &(last_added_comm->header_iv_ctx_dynamic));
                    }
                    continue;
                }
            }
        }

        // --- 处理社区名称或正则表达式

        // 先切割出可能的 IP 子网地址
        cmn_str = (char *)calloc(len + 1, sizeof(char));
        has_net = (sscanf(line, "%s %s", cmn_str, net_str) == 2);

        // 如果包含典型的正则字符...
        if (NULL != strpbrk(cmn_str, ".*+?[]\\"))
        {
            // 处理为正则表达式
            re = (struct sn_community_regular_expression *)calloc(1, sizeof(struct sn_community_regular_expression));
            if (re)
            {
                re->rule = re_compile(cmn_str);
                HASH_ADD_PTR(sss->rules, rule, re);
                num_regex++;
                traceEvent(TRACE_INFO, "added regular expression for allowed communities '%s'", cmn_str);
                free(cmn_str);
                last_added_comm = NULL;
                continue;
            }
        }

        // 处理社区名称
        comm = (struct sn_community *)calloc(1, sizeof(struct sn_community));

        if (comm != NULL)
        {
            comm_init(comm, cmn_str);
            comm->purgeable = false;                             // 该社区不可被清除
            comm->header_encryption = HEADER_ENCRYPTION_UNKNOWN; // 暂时未知是否使用头部加密
            packet_header_setup_key(comm->community,
                                    &(comm->header_encryption_ctx_static),
                                    &(comm->header_encryption_ctx_dynamic),
                                    &(comm->header_iv_ctx_static),
                                    &(comm->header_iv_ctx_dynamic));
            HASH_ADD_STR(sss->communities, community, comm);
            last_added_comm = comm;

            num_communities++;
            traceEvent(TRACE_INFO, "added allowed community '%s' [total: %u]",
                       (char *)comm->community, num_communities);

            // 检查是否为子网地址
            if (has_net)
            {
                if (sscanf(net_str, "%15[^/]/%hhu", ip_str, &bitlen) != 2)
                {
                    traceEvent(TRACE_WARNING, "bad net/bit format '%s' for community '%c', ignoring; see comments inside community.list file",
                               net_str, cmn_str);
                    has_net = 0;
                }
                net = inet_addr(ip_str);
                mask = bitlen2mask(bitlen);
                if ((net == (in_addr_t)(-1)) || (net == INADDR_NONE) || (net == INADDR_ANY) || ((ntohl(net) & ~mask) != 0))
                {
                    traceEvent(TRACE_WARNING, "bad network '%s/%u' in '%s' for community '%s', ignoring",
                               ip_str, bitlen, net_str, cmn_str);
                    has_net = 0;
                }
                if ((bitlen > 30) || (bitlen == 0))
                {
                    traceEvent(TRACE_WARNING, "bad prefix '%hhu' in '%s' for community '%s', ignoring",
                               bitlen, net_str, cmn_str);
                    has_net = 0;
                }
            }
            if (has_net)
            {
                comm->auto_ip_net.net_addr = ntohl(net);
                comm->auto_ip_net.net_bitlen = bitlen;
                traceEvent(TRACE_INFO, "assigned sub-network %s/%u to community '%s'",
                           inet_ntoa(*(struct in_addr *)&net),
                           comm->auto_ip_net.net_bitlen,
                           comm->community);
            }
            else
            {
                assign_one_ip_subnet(sss, comm);
            }
        }
        free(cmn_str);
    }

    fclose(fd);

    if ((num_regex + num_communities) == 0)
    {
        traceEvent(TRACE_WARNING, "file %s does not contain any valid community names or regular expressions", sss->community_file);
        return -2;
    }

    traceEvent(TRACE_NORMAL, "loaded %u fixed-name communities from %s",
               num_communities, sss->community_file);

    traceEvent(TRACE_NORMAL, "loaded %u regular expressions for community name matching from %s",
               num_regex, sss->community_file);

    // 计算允许用户的共享密钥（与联盟共享）
    calculate_shared_secrets(sss);

    // 计算社区的动态密钥
    calculate_dynamic_keys(sss);

    // 禁止新增社区
    sss->lock_communities = 1;

    return 0;
}

/* *************************************************** */

/** 向一个文件描述符的套接字发送数据报。
 *
 *    @return 发生错误时返回 -1，否则返回发送的字节数
 */
static ssize_t sendto_fd(n2n_sn_t *sss,
                         SOCKET socket_fd,
                         const struct sockaddr *socket,
                         const uint8_t *pktbuf,
                         size_t pktsize)
{

    ssize_t sent = 0; // 发送的字节数初始化为0
    n2n_tcp_connection_t *conn;

    // 使用 sendto 函数向指定的 socket 发送数据包
    sent = sendto(socket_fd, (void *)pktbuf, pktsize, 0 /* flags */,
                  socket, sizeof(struct sockaddr_in));

    // 如果发送失败，且 errno 表示有错误
    if ((sent <= 0) && (errno))
    {
        char *c = strerror(errno); // 获取错误信息的字符串表示
        traceEvent(TRACE_ERROR, "sendto failed (%d) %s", errno, c);
#ifdef _WIN32
        traceEvent(TRACE_ERROR, "WSAGetLastError(): %u", WSAGetLastError());
#endif
        // 如果发生错误的连接是 TCP 连接（即不是常规的 socket）
        if ((socket_fd >= 0) && (socket_fd != sss->sock))
        {
            // 查找该 TCP 连接对应的 peer 并关闭该连接
            HASH_FIND_INT(sss->tcp_connections, &socket_fd, conn);
            close_tcp_connection(sss, conn);
            return -1; // 返回发送失败
        }
    }
    else
    {
        // 如果发送成功，记录发送字节数
        traceEvent(TRACE_DEBUG, "sendto sent=%d to ", (signed int)sent);
    }

    return sent; // 返回实际发送的字节数
}

/** 向网络字节序的套接字（类型为 struct sockaddr）发送数据报。
 *
 *    @return 发生错误时返回 -1，否则返回发送的字节数
 */
static ssize_t sendto_sock(n2n_sn_t *sss,
                           SOCKET socket_fd,
                           const struct sockaddr *socket,
                           const uint8_t *pktbuf,
                           size_t pktsize)
{

    ssize_t sent = 0; // 用于存储已发送的字节数
    int value = 0;    // 用于设置 TCP 选项

    // 如果连接是 TCP 连接（即不是常规的套接字）...
    if ((socket_fd >= 0) && (socket_fd != sss->sock))
    {
        // 设置 TCP_NODELAY 选项，禁用 Nagle 算法，减少延迟
        setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value));

// 在 Linux 系统下设置 TCP_CORK，合并多个小数据包，提高效率
#ifdef LINUX
        setsockopt(socket_fd, IPPROTO_TCP, TCP_CORK, &value, sizeof(value));
#endif

        // 在发送实际数据之前，先发送数据包的长度
        uint16_t pktsize16 = htobe16(pktsize); // 将数据包大小转换为网络字节序
        sent = sendto_fd(sss, socket_fd, socket, (uint8_t *)&pktsize16, sizeof(pktsize16));

        if (sent <= 0)
            return -1; // 如果发送失败，返回 -1
        // 发送数据包的长度已完成，接下来发送实际的数据
    }

    // 发送实际的数据包
    sent = sendto_fd(sss, socket_fd, socket, pktbuf, pktsize);

    // 如果连接是 TCP 连接（即不是常规的套接字）...
    if ((socket_fd >= 0) && (socket_fd != sss->sock))
    {
        // 重新启用 Nagle 算法
        value = 1; // 确保 value 设置为 1
        setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, (void *)&value, sizeof(value));

// 在 Linux 系统下，关闭 TCP_CORK 选项
#ifdef LINUX
        value = 0;
        setsockopt(socket_fd, IPPROTO_TCP, TCP_CORK, &value, sizeof(value));
#endif
    }

    return sent; // 返回发送的字节数
}

/** 向一个对等体发送数据报，该对等体的目标套接字信息包含在其 sock 字段（类型为 n2n_sock_t）中。
 *  它调用 sendto_sock 完成最终的发送。
 *
 *    @return 错误时返回 -1，否则返回发送的字节数
 */
static ssize_t sendto_peer(n2n_sn_t *sss,
                           const struct peer_info *peer,
                           const uint8_t *pktbuf,
                           size_t pktsize)
{

    n2n_sock_str_t sockbuf; // 用于存储对等体套接字的字符串表示

    // 如果对等体的套接字是 IPv4
    if (AF_INET == peer->sock.family)
    {

        // 创建一个 IPv4 类型的 sockaddr_in 结构体，并填充相关的 IP 地址和端口信息
        struct sockaddr_in socket;
        fill_sockaddr((struct sockaddr *)&socket, sizeof(socket), &(peer->sock));

        // 记录调试日志，显示发送的数据大小和目标地址
        traceEvent(TRACE_DEBUG, "sent %lu bytes to [%s]",
                   pktsize,
                   sock_to_cstr(sockbuf, &(peer->sock)));

        // 调用 sendto_sock 函数发送数据
        return sendto_sock(sss,
                           (peer->socket_fd >= 0) ? peer->socket_fd : sss->sock,
                           (const struct sockaddr *)&socket, pktbuf, pktsize);
    }
    else
    {
        // 如果套接字是 IPv6（当前未实现），返回错误
        /* AF_INET6 尚未实现 */
        errno = EAFNOSUPPORT;
        return -1;
    }
}

/** 尝试将消息广播到社区中的所有边缘节点。
 *
 *    该函数会将完全相同的数据报发送到注册到超级节点的零个或多个边缘节点。
 */
static int try_broadcast(n2n_sn_t *sss,
                         const struct sn_community *comm,
                         const n2n_common_t *cmn,
                         const n2n_mac_t srcMac,
                         uint8_t from_supernode,
                         const uint8_t *pktbuf,
                         size_t pktsize,
                         time_t now)
{

    struct peer_info *scan, *tmp; // 用于遍历边缘节点
    macstr_t mac_buf;             // 用于存储 MAC 地址的字符串表示
    n2n_sock_str_t sockbuf;       // 用于存储套接字的字符串表示

    traceEvent(TRACE_DEBUG, "try_broadcast");

    /* 确保广播消息到达其他超级节点以及与它们连接的边缘节点。
     * try_broadcast 需要一个 from_supernode 参数：如果设置，
     * 则仅转发到社区的边缘节点。如果未设置，则广播到所有本地已知的社区节点，
     * 以及与社区关联的所有超级节点。*/

    if (!from_supernode)
    {
        // 遍历超级节点的边缘节点
        HASH_ITER(hh, sss->federation->edges, scan, tmp)
        {
            int data_sent_len;

            // 只转发到活动的超级节点
            if (scan->last_seen + LAST_SEEN_SN_INACTIVE > now)
            {
                // 向超级节点发送数据包
                data_sent_len = sendto_peer(sss, scan, pktbuf, pktsize);

                // 如果发送失败，记录错误
                if (data_sent_len != pktsize)
                {
                    ++(sss->stats.errors);
                    traceEvent(TRACE_WARNING, "multicast %lu to supernode [%s] %s failed %s",
                               pktsize,
                               sock_to_cstr(sockbuf, &(scan->sock)),
                               macaddr_str(mac_buf, scan->mac_addr),
                               strerror(errno));
                }
                else
                {
                    ++(sss->stats.broadcast);
                    traceEvent(TRACE_DEBUG, "multicast %lu to supernode [%s] %s",
                               pktsize,
                               sock_to_cstr(sockbuf, &(scan->sock)),
                               macaddr_str(mac_buf, scan->mac_addr));
                }
            }
        }
    }

    // 如果社区信息存在，遍历社区中的所有边缘节点
    if (comm)
    {
        HASH_ITER(hh, comm->edges, scan, tmp)
        {
            // 如果目标 MAC 地址与源 MAC 地址不同
            if (memcmp(srcMac, scan->mac_addr, sizeof(n2n_mac_t)) != 0)
            {
                /* REVISIT: 如果数据包的源套接字与目标套接字相同，则应排除。 */
                int data_sent_len;

                // 向边缘节点发送数据包
                data_sent_len = sendto_peer(sss, scan, pktbuf, pktsize);

                // 如果发送失败，记录错误
                if (data_sent_len != pktsize)
                {
                    ++(sss->stats.errors);
                    traceEvent(TRACE_WARNING, "multicast %lu to [%s] %s failed %s",
                               pktsize,
                               sock_to_cstr(sockbuf, &(scan->sock)),
                               macaddr_str(mac_buf, scan->mac_addr),
                               strerror(errno));
                }
                else
                {
                    ++(sss->stats.broadcast);
                    traceEvent(TRACE_DEBUG, "multicast %lu to [%s] %s",
                               pktsize,
                               sock_to_cstr(sockbuf, &(scan->sock)),
                               macaddr_str(mac_buf, scan->mac_addr));
                }
            }
        }
    }

    return 0;
}

static int try_forward(n2n_sn_t *sss,
                       const struct sn_community *comm,
                       const n2n_common_t *cmn,
                       const n2n_mac_t dstMac,
                       uint8_t from_supernode,
                       const uint8_t *pktbuf,
                       size_t pktsize,
                       time_t now)
{

    struct peer_info *scan;
    node_supernode_association_t *assoc;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;

    // 查找目标 MAC 地址对应的边缘节点
    HASH_FIND_PEER(comm->edges, dstMac, scan);

    // 如果找到对应的边缘节点
    if (NULL != scan)
    {
        int data_sent_len;
        // 向找到的边缘节点发送数据包
        data_sent_len = sendto_peer(sss, scan, pktbuf, pktsize);

        // 如果数据包发送成功，记录成功统计
        if (data_sent_len == pktsize)
        {
            ++(sss->stats.fwd);
            traceEvent(TRACE_DEBUG, "unicast %lu to [%s] %s",
                       pktsize,
                       sock_to_cstr(sockbuf, &(scan->sock)),
                       macaddr_str(mac_buf, scan->mac_addr));
        }
        else
        {
            // 发送失败，记录错误
            ++(sss->stats.errors);
            traceEvent(TRACE_ERROR, "unicast %lu to [%s] %s FAILED (%d: %s)",
                       pktsize,
                       sock_to_cstr(sockbuf, &(scan->sock)),
                       macaddr_str(mac_buf, scan->mac_addr),
                       errno, strerror(errno));
            return -1;
        }
    }
    else
    {
        // 如果未找到边缘节点并且不是来自超级节点的包
        if (!from_supernode)
        {
            // 检查目标 MAC 是否与某个超级节点相关联
            HASH_FIND(hh, comm->assoc, dstMac, sizeof(n2n_mac_t), assoc);
            if (assoc)
            {
                traceEvent(TRACE_DEBUG, "found mac address associated with a known supernode, forwarding packet to that supernode");
                // 转发数据包到关联的超级节点
                sendto_sock(sss, sss->sock,
                            &(assoc->sock),
                            pktbuf, pktsize);
            }
            else
            {
                // 如果目标 MAC 未知，广播数据包到所有联邦超级节点
                traceEvent(TRACE_DEBUG, "unknown mac address, broadcasting packet to all federated supernodes");
                try_broadcast(sss, NULL, cmn, sss->mac_addr, from_supernode, pktbuf, pktsize, now);
            }
        }
        else
        {
            // 如果数据包来自超级节点并且目标 MAC 未知，丢弃该数据包
            traceEvent(TRACE_DEBUG, "unknown mac address in packet from a supernode, dropping the packet");
            /* 不是已知的 MAC 地址，丢弃数据包 */
            return -2;
        }
    }

    return 0;
}

/** 初始化社区结构体的一些字段 **/
int comm_init(struct sn_community *comm, char *cmn)
{

    // 将社区名称（cmn）复制到社区结构体中的 community 字段
    // 保证不超过 N2N_COMMUNITY_SIZE，并确保字符串以 '\0' 结尾
    strncpy((char *)comm->community, cmn, N2N_COMMUNITY_SIZE);
    comm->community[N2N_COMMUNITY_SIZE - 1] = '\0'; // 确保字符串终止符

    // 设置社区类型为非联盟（默认值）
    comm->is_federation = IS_NO_FEDERATION;

    return 0; /* 初始化成功 */
}

/** 初始化超级节点结构体的默认值 **/
int sn_init_defaults(n2n_sn_t *sss)
{

    char *tmp_string;

#ifdef _WIN32
    initWin32(); // 如果在 Windows 平台上，初始化 Windows 特有的设置
#endif

    pearson_hash_init(); // 初始化 Pearson 哈希算法

    memset(sss, 0, sizeof(n2n_sn_t)); // 清空超级节点结构体，初始化所有字段为零

    // 设置版本信息
    strncpy(sss->version, PACKAGE_VERSION, sizeof(n2n_version_t));
    sss->version[sizeof(n2n_version_t) - 1] = '\0'; // 确保字符串以 '\0' 结尾

    // 设置默认的守护进程标志和绑定地址
    sss->daemon = 1;                /* 默认运行为守护进程 */
    sss->bind_address = INADDR_ANY; /* 绑定到任意地址 */

    // 设置默认的本地和管理端口
    sss->lport = N2N_SN_LPORT_DEFAULT;
    sss->mport = N2N_SN_MGMT_PORT;

    // 设置默认的套接字值
    sss->sock = -1;
    sss->mgmt_sock = -1;

    // 设置默认的最小和最大自动 IP 网络地址及子网掩码
    sss->min_auto_ip_net.net_addr = inet_addr(N2N_SN_MIN_AUTO_IP_NET_DEFAULT);
    sss->min_auto_ip_net.net_addr = ntohl(sss->min_auto_ip_net.net_addr);
    sss->min_auto_ip_net.net_bitlen = N2N_SN_AUTO_IP_NET_BIT_DEFAULT;
    sss->max_auto_ip_net.net_addr = inet_addr(N2N_SN_MAX_AUTO_IP_NET_DEFAULT);
    sss->max_auto_ip_net.net_addr = ntohl(sss->max_auto_ip_net.net_addr);
    sss->max_auto_ip_net.net_bitlen = N2N_SN_AUTO_IP_NET_BIT_DEFAULT;

    // 为联盟分配内存并初始化
    sss->federation = (struct sn_community *)calloc(1, sizeof(struct sn_community));
    if (sss->federation)
    {
        // 设置联盟名称，如果环境变量 N2N_FEDERATION 存在，使用其值
        if (getenv("N2N_FEDERATION"))
            snprintf(sss->federation->community, N2N_COMMUNITY_SIZE - 1, "*%s", getenv("N2N_FEDERATION"));
        else
            strncpy(sss->federation->community, (char *)FEDERATION_NAME, N2N_COMMUNITY_SIZE);

        // 确保字符串以 '\0' 结尾
        sss->federation->community[N2N_COMMUNITY_SIZE - 1] = '\0';

        // 设置联盟标志为已启用
        sss->federation->is_federation = IS_FEDERATION;
        sss->federation->purgeable = false; // 联盟不可清除

        // 默认启用头部加密
        sss->federation->header_encryption = HEADER_ENCRYPTION_ENABLED;

        // 设置加密密钥
        packet_header_setup_key(sss->federation->community,
                                &(sss->federation->header_encryption_ctx_static),
                                &(sss->federation->header_encryption_ctx_dynamic),
                                &(sss->federation->header_iv_ctx_static),
                                &(sss->federation->header_iv_ctx_dynamic));

        sss->federation->edges = NULL;
    }

    // 初始化随机数生成器
    n2n_srand(n2n_seed());

    // 设置随机认证令牌
    sss->auth.scheme = n2n_auth_simple_id;
    memrnd(sss->auth.token, N2N_AUTH_ID_TOKEN_SIZE);
    sss->auth.token_size = N2N_AUTH_ID_TOKEN_SIZE;

    // 设置随机 MAC 地址
    memrnd(sss->mac_addr, N2N_MAC_SIZE);
    sss->mac_addr[0] &= ~0x01; // 清除组播位
    sss->mac_addr[0] |= 0x02;  // 设置本地分配位

    // 计算并设置管理密码哈希
    tmp_string = calloc(1, strlen(N2N_MGMT_PASSWORD) + 1);
    if (tmp_string)
    {
        strncpy((char *)tmp_string, N2N_MGMT_PASSWORD, strlen(N2N_MGMT_PASSWORD) + 1);
        sss->mgmt_password_hash = pearson_hash_64((uint8_t *)tmp_string, strlen(N2N_MGMT_PASSWORD));
        free(tmp_string);
    }

    return 0; /* 初始化成功 */
}

/** 初始化超级节点 **/
void sn_init(n2n_sn_t *sss)
{

    // 尝试创建解析线程并初始化解析参数
    if (resolve_create_thread(&(sss->resolve_parameter), sss->federation->edges) == 0)
    {
        traceEvent(TRACE_NORMAL, "successfully created resolver thread");
    }
}

/** 反初始化超级节点结构体并释放其拥有的内存 **/
void sn_term(n2n_sn_t *sss)
{

    struct sn_community *community, *tmp;
    struct sn_community_regular_expression *re, *tmp_re;
    n2n_tcp_connection_t *conn, *tmp_conn;
    node_supernode_association_t *assoc, *tmp_assoc;

    // 取消解析线程
    resolve_cancel_thread(sss->resolve_parameter);

    // 关闭超级节点的套接字
    if (sss->sock >= 0)
    {
        closesocket(sss->sock); // 关闭套接字
    }
    sss->sock = -1; // 将套接字设置为 -1，表示没有打开套接字

    // 关闭所有 TCP 连接
    HASH_ITER(hh, sss->tcp_connections, conn, tmp_conn)
    {
        shutdown(conn->socket_fd, SHUT_RDWR); // 关闭连接的读写操作
        closesocket(conn->socket_fd);         // 关闭套接字
        HASH_DEL(sss->tcp_connections, conn); // 从连接列表中删除该连接
        free(conn);                           // 释放连接的内存
    }

    // 关闭 TCP 套接字
    if (sss->tcp_sock >= 0)
    {
        shutdown(sss->tcp_sock, SHUT_RDWR); // 关闭连接的读写操作
        closesocket(sss->tcp_sock);         // 关闭 TCP 套接字
    }
    sss->tcp_sock = -1; // 将 TCP 套接字设置为 -1，表示没有打开套接字

    // 关闭管理套接字
    if (sss->mgmt_sock >= 0)
    {
        closesocket(sss->mgmt_sock); // 关闭管理套接字
    }
    sss->mgmt_sock = -1; // 将管理套接字设置为 -1，表示没有打开套接字

    // 释放社区资源
    HASH_ITER(hh, sss->communities, community, tmp)
    {
        clear_peer_list(&community->edges); // 清除社区中的边缘列表
        if (NULL != community->header_encryption_ctx_static)
        {
            free(community->header_encryption_ctx_static); // 释放加密上下文
            free(community->header_encryption_ctx_dynamic);
        }
        // 删除所有关联
        HASH_ITER(hh, community->assoc, assoc, tmp_assoc)
        {
            HASH_DEL(community->assoc, assoc); // 从关联列表中删除
            free(assoc);                       // 释放关联的内存
        }
        HASH_DEL(sss->communities, community); // 从社区列表中删除社区
        free(community);                       // 释放社区的内存
    }

    // 释放正则表达式资源
    HASH_ITER(hh, sss->rules, re, tmp_re)
    {
        HASH_DEL(sss->rules, re); // 从规则列表中删除
        if (NULL != re->rule)
        {
            free(re->rule); // 释放正则表达式规则的内存
        }
        free(re); // 释放正则表达式结构体的内存
    }

    // 释放社区文件的内存
    if (sss->community_file)
        free(sss->community_file);

#ifdef _WIN32
    destroyWin32(); // 如果在 Windows 平台，销毁 Windows 特有的资源
#endif
}

void update_node_supernode_association(struct sn_community *comm,
                                       n2n_mac_t *edgeMac, const struct sockaddr *sender_sock, socklen_t sock_size,
                                       time_t now)
{

    node_supernode_association_t *assoc;

    // 查找社区中是否已存在指定的 MAC 地址对应的超级节点关联
    HASH_FIND(hh, comm->assoc, edgeMac, sizeof(n2n_mac_t), assoc);
    if (!assoc)
    {
        // 如果没有找到关联，创建一个新的关联
        assoc = (node_supernode_association_t *)calloc(1, sizeof(node_supernode_association_t));
        if (assoc)
        {
            // 初始化新的关联结构体
            memcpy(&(assoc->mac), edgeMac, sizeof(n2n_mac_t)); // 复制边缘节点的 MAC 地址
            memcpy(&(assoc->sock), sender_sock, sock_size);    // 复制发送者的套接字地址
            assoc->sock_len = sock_size;                       // 记录套接字地址的长度
            assoc->last_seen = now;                            // 设置最后一次见面的时间
            // 将新的关联添加到社区的关联哈希表中
            HASH_ADD(hh, comm->assoc, mac, sizeof(n2n_mac_t), assoc);
        }
        else
        {
            // 如果内存分配失败，更新现有的关联结构体：仅更新套接字地址和时间
            memcpy(&(assoc->sock), sender_sock, sock_size);
            assoc->sock_len = sock_size;
            assoc->last_seen = now;
        }
    }
}

/** 确定新注册的适当生命周期
 *
 *    如果超级节点已经进入预关闭阶段，则此生命周期应确保注册不会继续超过关闭点。
 */
static uint16_t reg_lifetime(n2n_sn_t *sss)
{

    /* 注意：UDP 防火墙通常具有 30 秒的超时 */
    return 15; // 返回 15 秒作为注册生命周期
}

/** 验证来自已知边缘节点的认证令牌
*该函数由 update_edge 和 UNREGISTER_SUPER 处理时调用，
*用于验证存储的认证令牌。
*/
static int auth_edge(const n2n_auth_t *present, const n2n_auth_t *presented, n2n_auth_t *answer, struct sn_community *community)
{

    sn_user_t *user = NULL;

    // 检查认证方案是否为 n2n_auth_none（表示没有认证）
    if (present->scheme == n2n_auth_none)
    {
        // 对于 n2n_auth_none 方案（在超级节点设置时通过 '-M' 选项）
        // 如果需要，返回一个空的令牌（不是用于 NAK）
        if (answer)
            memset(answer, 0, sizeof(n2n_auth_t));
        // 0 表示认证成功（总是成功）
        return 0;
    }

    // 检查是否为简单 ID 认证方案
    if ((present->scheme == n2n_auth_simple_id) && (presented->scheme == n2n_auth_simple_id))
    {
        // 对于 n2n_auth_simple_id 方案：如果需要，返回一个空的令牌（不是用于 NAK）
        if (answer)
            memset(answer, 0, sizeof(n2n_auth_t));

        // 0 表示认证成功（令牌相等）
        return (memcmp(present, presented, sizeof(n2n_auth_t)));
    }

    // 检查是否为用户名/密码认证方案
    if ((present->scheme == n2n_auth_user_password) && (presented->scheme == n2n_auth_user_password))
    {
        // 检查提交的公钥是否在允许的用户列表中
        HASH_FIND(hh, community->allowed_users, &presented->token, sizeof(n2n_private_public_key_t), user);
        if (user)
        {
            if (answer)
            {
                // 复制 presented 的认证信息到 answer
                memcpy(answer, presented, sizeof(n2n_auth_t));

                // 返回双重加密的挑战（再加密一次），存放在公钥字段的前半部分，边缘节点可以验证
                memcpy(answer->token, answer->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, N2N_AUTH_CHALLENGE_SIZE);
                speck_128_encrypt(answer->token, (speck_context_t *)user->shared_secret_ctx);

                // 使用用户的共享密钥解密挑战
                speck_128_decrypt(answer->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, (speck_context_t *)user->shared_secret_ctx);
                // 使用社区的动态密钥对挑战进行异或运算
                memxor(answer->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, community->dynamic_key, N2N_AUTH_CHALLENGE_SIZE);
                // 使用用户的共享密钥对挑战进行异或运算
                memxor(answer->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, user->shared_secret, N2N_AUTH_CHALLENGE_SIZE);
                // 使用用户的共享密钥加密挑战
                speck_128_encrypt(answer->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, (speck_context_t *)user->shared_secret_ctx);
                // 用户在列表中？认证成功！(稍后会检查边缘节点是否能处理这个密钥进行后续通信)
            }
            return 0;
        }
    }

    // 如果前面的认证失败，则返回失败
    return -1;
}

/** 提供当前的 / 新的本地认证令牌
 *  REVISIT: 行为应当依赖于某些本地认证方案设置（待实现）
 */
static int get_local_auth(n2n_sn_t *sss, n2n_auth_t *auth)
{
    // 使用 n2n_auth_simple_id 方案
    memcpy(auth, &(sss->auth), sizeof(n2n_auth_t)); // 将本地的认证令牌拷贝到 auth 中

    return 0; // 返回 0 表示成功
}

/** 处理来自未知边缘节点的远程认证令牌，
 *  根据认证方案采取必要的操作，并
 *  可提供用于 REGISTER_SUPER_ACK 的响应认证令牌
 */
static int handle_remote_auth(n2n_sn_t *sss, const n2n_auth_t *remote_auth,
                              n2n_auth_t *answer_auth,
                              struct sn_community *community)
{
    sn_user_t *user = NULL;

    // 检查远程认证令牌的方案是否与社区要求的方案一致
    if ((NULL == community->allowed_users) != (remote_auth->scheme != n2n_auth_user_password))
    {
        // 认证令牌的方案与预期方案不匹配
        return -1;
    }

    switch (remote_auth->scheme)
    {
    case n2n_auth_none:      // 没有认证
    case n2n_auth_simple_id: // 简单 ID 认证
        // 对于无认证或者简单 ID 认证方案，返回一个零令牌的响应
        memset(answer_auth, 0, sizeof(n2n_auth_t));
        return 0;
    case n2n_auth_user_password: // 用户名/密码认证
        // 检查提交的公钥是否在允许的用户列表中
        HASH_FIND(hh, community->allowed_users, &remote_auth->token, sizeof(n2n_private_public_key_t), user);
        if (user)
        {
            // 如果用户存在，复制远程认证令牌到 answer_auth
            memcpy(answer_auth, remote_auth, sizeof(n2n_auth_t));

            // 返回双重加密的挑战（再加密一次），放在公钥字段的前半部分，供边缘节点验证
            memcpy(answer_auth->token, answer_auth->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, N2N_AUTH_CHALLENGE_SIZE);
            speck_128_encrypt(answer_auth->token, (speck_context_t *)user->shared_secret_ctx);

            // 使用用户的共享密钥解密挑战
            speck_128_decrypt(answer_auth->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, (speck_context_t *)user->shared_secret_ctx);
            // 使用社区的动态密钥对挑战进行异或运算
            memxor(answer_auth->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, community->dynamic_key, N2N_AUTH_CHALLENGE_SIZE);
            // 使用用户的共享密钥对挑战进行异或运算
            memxor(answer_auth->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, user->shared_secret, N2N_AUTH_CHALLENGE_SIZE);
            // 使用用户的共享密钥加密挑战
            speck_128_encrypt(answer_auth->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, (speck_context_t *)user->shared_secret_ctx);
            return 0;
        }
        break;
    default:
        break;
    }

    // 如果没有成功：认证失败
    return -1;
}

/** 更新边缘节点表，记录联系到超级节点的边缘节点的详细信息 */
static int update_edge(n2n_sn_t *sss,
                       const n2n_common_t *cmn,
                       const n2n_REGISTER_SUPER_t *reg,
                       struct sn_community *comm,
                       const n2n_sock_t *sender_sock,
                       const SOCKET socket_fd,
                       n2n_auth_t *answer_auth,
                       int skip_add,
                       time_t now)
{
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;
    struct peer_info *scan, *iter, *tmp;
    int ret;

    traceEvent(TRACE_DEBUG, "update_edge for %s [%s]",
               macaddr_str(mac_buf, reg->edgeMac),
               sock_to_cstr(sockbuf, sender_sock));

    // 查找边缘节点是否已经存在
    HASH_FIND_PEER(comm->edges, reg->edgeMac, scan);

    // 如果未知，检查是否可以通过 IP 地址匹配找到
    if (NULL == scan)
    {
        HASH_ITER(hh, comm->edges, iter, tmp)
        {
            if (iter->dev_addr.net_addr == reg->dev_addr.net_addr)
            {
                scan = iter;
                HASH_DEL(comm->edges, scan);
                memcpy(scan->mac_addr, reg->edgeMac, sizeof(n2n_mac_t));
                HASH_ADD_PEER(comm->edges, scan);
                break;
            }
        }
    }

    // 如果边缘节点是未知的
    if (NULL == scan)
    {
        // 进行认证并返回响应
        if (handle_remote_auth(sss, &(reg->auth), answer_auth, comm) == 0)
        {
            if (skip_add == SN_ADD)
            {
                scan = (struct peer_info *)calloc(1, sizeof(struct peer_info)); // 分配内存
                scan->purgeable = true;
                memcpy(&(scan->mac_addr), reg->edgeMac, sizeof(n2n_mac_t));
                scan->dev_addr.net_addr = reg->dev_addr.net_addr;
                scan->dev_addr.net_bitlen = reg->dev_addr.net_bitlen;
                memcpy((char *)scan->dev_desc, reg->dev_desc, N2N_DESC_SIZE);
                memcpy(&(scan->sock), sender_sock, sizeof(n2n_sock_t));
                scan->socket_fd = socket_fd;
                scan->last_cookie = reg->cookie;
                scan->last_valid_time_stamp = initial_time_stamp();
                // 如果设置了标志，存储边缘节点的首选套接字
                if (cmn->flags & N2N_FLAGS_SOCKET)
                    memcpy(&scan->preferred_sock, &reg->sock, sizeof(n2n_sock_t));
                else
                    scan->preferred_sock.family = AF_INVALID;

                // 存储认证令牌
                memcpy(&(scan->auth), &(reg->auth), sizeof(n2n_auth_t));
                // 如果禁用 MAC/IP 地址欺骗保护，则手动设置为 'auth_none'
                if ((reg->auth.scheme == n2n_auth_simple_id) && (sss->override_spoofing_protection))
                    scan->auth.scheme = n2n_auth_none;

                HASH_ADD_PEER(comm->edges, scan);

                traceEvent(TRACE_INFO, "created edge  %s ==> %s",
                           macaddr_str(mac_buf, reg->edgeMac),
                           sock_to_cstr(sockbuf, sender_sock));
            }
            ret = update_edge_new_sn;
        }
        else
        {
            traceEvent(TRACE_INFO, "authentication failed");
            ret = update_edge_auth_fail;
        }
    }
    else
    {
        // 如果边缘节点已经存在
        if (auth_edge(&(scan->auth), &(reg->auth), answer_auth, comm) == 0)
        {
            // 如果套接字地址不相同，更新套接字地址和其他信息
            if (!sock_equal(sender_sock, &(scan->sock)))
            {
                scan->dev_addr.net_addr = reg->dev_addr.net_addr;
                scan->dev_addr.net_bitlen = reg->dev_addr.net_bitlen;
                memcpy((char *)scan->dev_desc, reg->dev_desc, N2N_DESC_SIZE);
                memcpy(&(scan->sock), sender_sock, sizeof(n2n_sock_t));
                scan->socket_fd = socket_fd;
                scan->last_cookie = reg->cookie;
                // 如果设置了标志，更新边缘节点的首选套接字
                if (cmn->flags & N2N_FLAGS_SOCKET)
                    memcpy(&scan->preferred_sock, &reg->sock, sizeof(n2n_sock_t));
                else
                    scan->preferred_sock.family = AF_INVALID;

                traceEvent(TRACE_INFO, "updated edge  %s ==> %s",
                           macaddr_str(mac_buf, reg->edgeMac),
                           sock_to_cstr(sockbuf, sender_sock));
                ret = update_edge_sock_change;
            }
            else
            {
                scan->last_cookie = reg->cookie;

                traceEvent(TRACE_DEBUG, "edge unchanged %s ==> %s",
                           macaddr_str(mac_buf, reg->edgeMac),
                           sock_to_cstr(sockbuf, sender_sock));

                ret = update_edge_no_change;
            }
        }
        else
        {
            traceEvent(TRACE_INFO, "authentication failed");
            ret = update_edge_auth_fail;
        }
    }

    if ((scan != NULL) && (ret != update_edge_auth_fail))
    {
        scan->last_seen = now;
    }

    return ret;
}

/**
 * 检查特定的 IP 地址是否仍然可用，即该 IP 地址是否已被该社区的其他边缘设备使用
 */
static int ip_addr_available(struct sn_community *comm, n2n_ip_subnet_t *ip_addr)
{
    int success = 1; // 默认认为该 IP 地址可用
    struct peer_info *peer, *tmp_peer;

    // 前提条件：同一社区内的 peer 列表已根据 peer 的 tap ip 地址排序
    HASH_ITER(hh, comm->edges, peer, tmp_peer)
    {
        // 如果当前 peer 的地址大于我们要检查的地址，则可以跳出循环
        if (peer->dev_addr.net_addr > ip_addr->net_addr)
        {
            break;
        }

        // 如果发现已有 peer 使用该 IP 地址，则认为该 IP 地址不可用
        if (peer->dev_addr.net_addr == ip_addr->net_addr)
        {
            success = 0;
            break;
        }
    }

    return success; // 返回 IP 地址是否可用
}

/**
 * 用于对 peer 进行排序，依据其 tap IP 地址的主机部分进行排序
 */
static signed int peer_tap_ip_sort(struct peer_info *a, struct peer_info *b)
{
    // 提取 a 和 b 的主机部分地址，通过与子网掩码进行与操作得到
    uint32_t a_host_id = a->dev_addr.net_addr & (~bitlen2mask(a->dev_addr.net_bitlen));
    uint32_t b_host_id = b->dev_addr.net_addr & (~bitlen2mask(b->dev_addr.net_bitlen));

    // 返回排序结果
    return ((signed int)a_host_id - (signed int)b_host_id);
}

/**
 * 为社区分配一个 IP 地址，基于 MAC 地址的哈希值，尝试从某个地址开始分配 IP 地址
 */
static int assign_one_ip_addr(struct sn_community *comm, n2n_desc_t dev_desc, n2n_ip_subnet_t *ip_addr)
{
    uint32_t tmp, success, net_id, mask, max_host, host_id = 1;
    dec_ip_bit_str_t ip_bit_str = {'\0'};

    mask = bitlen2mask(comm->auto_ip_net.net_bitlen); // 获取子网掩码
    net_id = comm->auto_ip_net.net_addr & mask;       // 网络 ID 地址
    max_host = ~mask;                                 // 最大主机地址

    // 排序 peer 列表，提前准备好检查 IP 可用性
    HASH_SORT(comm->edges, peer_tap_ip_sort);

    // 基于设备描述符 (MAC 地址) 生成一个初步的 IP 地址建议
    tmp = pearson_hash_32(dev_desc, sizeof(n2n_desc_t)) & max_host;
    if (tmp == 0)
        tmp++; // 避免 IP 地址为 0
    if (tmp == max_host)
        tmp--; // 避免广播地址

    tmp |= net_id; // 添加网络地址

    // 将这个建议作为候选 IP 地址
    ip_addr->net_bitlen = comm->auto_ip_net.net_bitlen;

    // 从建议的 IP 地址开始，向下检查可用性
    for (host_id = tmp; host_id > net_id; host_id--)
    {
        ip_addr->net_addr = host_id;
        success = ip_addr_available(comm, ip_addr);
        if (success)
        {
            break; // 找到可用的地址
        }
    }
    // 如果向下没有找到合适的地址，再向上查找
    if (!success)
    {
        for (host_id = tmp + 1; host_id < (net_id + max_host); host_id++)
        {
            ip_addr->net_addr = host_id;
            success = ip_addr_available(comm, ip_addr);
            if (success)
            {
                break; // 找到可用的地址
            }
        }
    }

    // 如果找到了可用的 IP 地址
    if (success)
    {
        traceEvent(TRACE_INFO, "assign IP %s to tap adapter of edge", ip_subnet_to_str(ip_bit_str, ip_addr));
        return 0; // 分配成功
    }
    else
    {
        traceEvent(TRACE_WARNING, "no assignable IP to edge tap adapter");
        return -1; // 分配失败
    }
}

/**
 * 检查子网是否可用，即是否与其他社区的子网重叠
 */
int subnet_available(n2n_sn_t *sss,
                     struct sn_community *comm,
                     uint32_t net_id,
                     uint32_t mask)
{
    struct sn_community *cmn, *tmpCmn;
    int success = 1;

    HASH_ITER(hh, sss->communities, cmn, tmpCmn)
    {
        if (cmn == comm) // 忽略自己
        {
            continue;
        }
        if (cmn->is_federation == IS_FEDERATION) // 联邦社区不考虑
        {
            continue;
        }
        // 检查是否有重叠的子网
        if ((net_id <= (cmn->auto_ip_net.net_addr + ~bitlen2mask(cmn->auto_ip_net.net_bitlen))) &&
            (net_id + ~mask >= cmn->auto_ip_net.net_addr))
        {
            success = 0; // 子网冲突
            break;
        }
    }

    return success; // 返回子网是否可用
}

/**
 * 为社区分配一个子网，尝试从某个网段开始分配子网
 */
int assign_one_ip_subnet(n2n_sn_t *sss,
                         struct sn_community *comm)
{
    uint32_t net_id, net_id_i, mask, net_increment;
    uint32_t no_subnets;
    uint8_t success;
    in_addr_t net;

    mask = bitlen2mask(sss->min_auto_ip_net.net_bitlen); // 获取子网掩码
    // 计算可用的子网数量
    no_subnets = (sss->max_auto_ip_net.net_addr - sss->min_auto_ip_net.net_addr);
    no_subnets >>= (32 - sss->min_auto_ip_net.net_bitlen); // 按照子网掩码缩小范围
    no_subnets += 1;

    // 提议一个子网
    net_id = pearson_hash_32((const uint8_t *)comm->community, N2N_COMMUNITY_SIZE) % no_subnets;
    net_id = sss->min_auto_ip_net.net_addr + (net_id << (32 - sss->min_auto_ip_net.net_bitlen));

    // 向下检查子网是否可用
    net_increment = (~mask + 1);
    for (net_id_i = net_id; net_id_i >= sss->min_auto_ip_net.net_addr; net_id_i -= net_increment)
    {
        success = subnet_available(sss, comm, net_id_i, mask);
        if (success)
        {
            break;
        }
    }
    // 向上检查子网是否可用
    if (!success)
    {
        for (net_id_i = net_id + net_increment; net_id_i <= sss->max_auto_ip_net.net_addr; net_id_i += net_increment)
        {
            success = subnet_available(sss, comm, net_id_i, mask);
            if (success)
            {
                break;
            }
        }
    }

    // 如果分配成功
    if (success)
    {
        comm->auto_ip_net.net_addr = net_id_i; // 分配子网
        comm->auto_ip_net.net_bitlen = sss->min_auto_ip_net.net_bitlen;
        net = htonl(comm->auto_ip_net.net_addr);
        traceEvent(TRACE_INFO, "assigned sub-network %s/%u to community '%s'",
                   inet_ntoa(*(struct in_addr *)&net),
                   comm->auto_ip_net.net_bitlen,
                   comm->community);
        return 0; // 成功
    }
    else
    {
        comm->auto_ip_net.net_addr = 0; // 无法分配子网
        comm->auto_ip_net.net_bitlen = 0;
        traceEvent(TRACE_WARNING, "no assignable sub-network left for community '%s'",
                   comm->community);
        return -1; // 失败
    }
}

/**
 * 查找和验证边缘设备的时间戳，确保它没有过期（如果需要，更新时间戳）。
 *
 * @param edges 当前社区的边缘设备列表
 * @param sn 目标设备的信息
 * @param mac 设备的 MAC 地址
 * @param stamp 收到的数据包的时间戳
 * @param allow_jitter 是否允许时间戳的抖动（误差）
 *
 * @return 返回 1 如果时间戳验证成功，返回 0 如果失败。
 */
static int find_edge_time_stamp_and_verify(struct peer_info *edges,
                                           peer_info_t *sn, n2n_mac_t mac,
                                           uint64_t stamp, int allow_jitter)
{
    uint64_t *previous_stamp = NULL;

    if (sn)
    {
        previous_stamp = &(sn->last_valid_time_stamp);
    }
    else
    {
        struct peer_info *edge;
        HASH_FIND_PEER(edges, mac, edge);

        if (edge)
        {
            // time_stamp_verify_and_update 允许 previous_stamp 为 NULL
            previous_stamp = &(edge->last_valid_time_stamp);
        }
    }

    // 如果时间戳验证失败，返回 0；如果成功，返回 1
    return time_stamp_verify_and_update(stamp, previous_stamp, allow_jitter);
}

/**
 * 重新注册并清理超时的超级节点。
 * 如果不强制执行，检查是否需要重新注册，并清理长时间没有响应的超级节点。
 */
static int re_register_and_purge_supernodes(n2n_sn_t *sss, struct sn_community *comm, time_t *p_last_re_reg_and_purge, time_t now, uint8_t forced)
{
    time_t time;
    struct peer_info *peer, *tmp;

    if (!forced)
    {
        if ((now - (*p_last_re_reg_and_purge)) < RE_REG_AND_PURGE_FREQUENCY)
        {
            return 0; // 如果没有到达重新注册和清理的时间间隔，直接返回
        }

        // 清理长时间未见的超级节点
        if (comm)
        {
            purge_expired_nodes(&(comm->edges), sss->sock, &sss->tcp_connections, p_last_re_reg_and_purge,
                                RE_REG_AND_PURGE_FREQUENCY, LAST_SEEN_SN_INACTIVE);
        }
    }

    // 如果指定了社区，则进行重新注册操作
    if (comm != NULL)
    {
        HASH_ITER(hh, comm->edges, peer, tmp)
        {
            time = now - peer->last_seen; // 计算节点自上次连接以来的时间

            if (!forced)
            {
                if (time <= LAST_SEEN_SN_ACTIVE)
                {
                    continue; // 如果超级节点依然活跃，则跳过
                }
            }

            /* 重新注册（发送 REGISTER_SUPER 包） */
            uint8_t pktbuf[N2N_PKT_BUF_SIZE] = {0};
            size_t idx;
            n2n_common_t cmn;
            n2n_REGISTER_SUPER_t reg;
            n2n_sock_str_t sockbuf;

            memset(&cmn, 0, sizeof(cmn));
            memset(&reg, 0, sizeof(reg));

            cmn.ttl = N2N_DEFAULT_TTL;
            cmn.pc = n2n_register_super;
            cmn.flags = N2N_FLAGS_FROM_SUPERNODE;
            memcpy(cmn.community, comm->community, N2N_COMMUNITY_SIZE);

            reg.cookie = n2n_rand(); // 为注册包生成一个随机 cookie
            peer->last_cookie = reg.cookie;

            reg.dev_addr.net_addr = ntohl(peer->dev_addr.net_addr);
            reg.dev_addr.net_bitlen = mask2bitlen(ntohl(peer->dev_addr.net_bitlen));
            get_local_auth(sss, &(reg.auth)); // 获取本地认证信息

            reg.key_time = sss->dynamic_key_time;

            idx = 0;
            encode_mac(reg.edgeMac, &idx, sss->mac_addr);

            idx = 0;
            encode_REGISTER_SUPER(pktbuf, &idx, &cmn, &reg);

            traceEvent(TRACE_DEBUG, "send REGISTER_SUPER to %s",
                       sock_to_cstr(sockbuf, &(peer->sock)));

            packet_header_encrypt(pktbuf, idx, idx,
                                  comm->header_encryption_ctx_static, comm->header_iv_ctx_static,
                                  time_stamp());

            /* 发送到超级节点 */
            sendto_peer(sss, peer, pktbuf, idx);
        }
    }

    return 0; // 成功完成重新注册和清理
}

/**
 * 清理过期的社区及其成员。
 *
 * @param sss 超级节点的状态结构
 * @param p_last_purge 最后清理的时间
 * @param now 当前时间
 */
static int purge_expired_communities(n2n_sn_t *sss,
                                     time_t *p_last_purge,
                                     time_t now)
{
    struct sn_community *comm, *tmp_comm;
    node_supernode_association_t *assoc, *tmp_assoc;
    size_t num_reg = 0;
    size_t num_assoc = 0;

    if ((now - (*p_last_purge)) < PURGE_REGISTRATION_FREQUENCY)
    {
        return 0; // 如果没有到达清理频率，直接返回
    }

    traceEvent(TRACE_DEBUG, "purging old communities and edges");

    HASH_ITER(hh, sss->communities, comm, tmp_comm)
    {
        // 联邦社区不参与清理
        if (comm->is_federation == IS_FEDERATION)
            continue;

        // 清理社区内的本地 peer
        num_reg += purge_peer_list(&comm->edges, sss->sock, &sss->tcp_connections, now - REGISTRATION_TIMEOUT);

        // 清理社区的关联 peer（连接到其他超级节点的）
        HASH_ITER(hh, comm->assoc, assoc, tmp_assoc)
        {
            if (comm->assoc->last_seen < (now - 3 * REGISTRATION_TIMEOUT))
            {
                HASH_DEL(comm->assoc, assoc);
                free(assoc);
                num_assoc++;
            }
        }

        // 如果没有活跃的 peer 并且社区是可清理的，进行社区清理
        if ((comm->edges == NULL) && (comm->purgeable))
        {
            traceEvent(TRACE_INFO, "purging idle community %s", comm->community);
            if (NULL != comm->header_encryption_ctx_static)
            {
                // 释放社区加密上下文
                free(comm->header_encryption_ctx_static);
                free(comm->header_iv_ctx_static);
                free(comm->header_encryption_ctx_dynamic);
                free(comm->header_iv_ctx_dynamic);
            }
            // 清除所有关联
            HASH_ITER(hh, comm->assoc, assoc, tmp_assoc)
            {
                HASH_DEL(comm->assoc, assoc);
                free(assoc);
            }
            HASH_DEL(sss->communities, comm); // 从社区列表中删除该社区
            free(comm);                       // 释放社区的内存
        }
    }
    (*p_last_purge) = now;

    traceEvent(TRACE_DEBUG, "purge_expired_communities removed %ld locally registered edges and %ld remotely associated edges",
               num_reg, num_assoc);

    return 0; // 清理完成
}

/**
 * 按照每个社区的已加密包数量进行排序，排序规则是从大到小。
 */
static int number_enc_packets_sort(struct sn_community *a, struct sn_community *b)
{
    return (b->number_enc_packets - a->number_enc_packets); // 比较已加密包的数量，进行降序排序
}

/**
 * 对社区列表进行排序，基于每个社区的已加密包数量。
 *
 * @param sss 超级节点的状态结构
 * @param p_last_sort 最后排序的时间
 * @param now 当前时间
 */
static int sort_communities(n2n_sn_t *sss,
                            time_t *p_last_sort,
                            time_t now)
{
    struct sn_community *comm, *tmp;

    if ((now - (*p_last_sort)) < SORT_COMMUNITIES_INTERVAL)
    {
        return 0; // 如果没有到达排序的时间间隔，直接返回
    }

    // 定期对社区按已加密包数量进行排序
    HASH_SORT(sss->communities, number_enc_packets_sort);

    // 排序后将所有社区的已加密包计数重置为 0
    HASH_ITER(hh, sss->communities, comm, tmp)
    {
        comm->number_enc_packets = 0;
    }

    (*p_last_sort) = now;

    return 0; // 排序完成
}

/** 检查数据报并决定如何处理它。
 * 该函数会处理传入的UDP数据包，必要时解密头部，
 * 解码数据包，然后将其转发或响应到相应的对等节点或超级节点。
 */
static int process_udp(n2n_sn_t *sss,
                       const struct sockaddr *sender_sock, socklen_t sock_size,
                       const SOCKET socket_fd,
                       uint8_t *udp_buf,
                       size_t udp_size,
                       time_t now)
{

    n2n_common_t cmn; /* 包头中的通用字段 */
    size_t rem;
    size_t idx;
    size_t msg_type;
    uint8_t from_supernode;
    peer_info_t *sn = NULL;
    n2n_sock_t sender;
    n2n_sock_t *orig_sender;
    macstr_t mac_buf;
    macstr_t mac_buf2;
    n2n_sock_str_t sockbuf;
    uint8_t hash_buf[16] = {0}; /* 大小为16（最大值），即使实际值为N2N_REG_SUP_HASH_CHECK_LEN（<= 16） */

    struct sn_community *comm, *tmp;
    uint32_t header_enc = 0; /* 1表示使用静态密钥加密，2表示使用动态密钥加密 */
    uint64_t stamp;
    int skip_add;
    time_t any_time = 0;

    memset(&sender, 0, sizeof(n2n_sock_t));
    fill_n2nsock(&sender, sender_sock);
    orig_sender = &sender;

    traceEvent(TRACE_DEBUG, "处理传入的UDP数据包 [长度: %lu][发送者: %s]",
               udp_size, sock_to_cstr(sockbuf, &sender));

    /* 检查数据包头部是否未加密。以下检查大约有99.99962%的准确性。
     * 它高度依赖于数据包通用部分的结构
     * 对于wire.c:encode/decode_common的更改需要与此代码一起修改。 */
    if (udp_size < 24)
    {
        traceEvent(TRACE_DEBUG, "丢弃一个太短的无效数据包");
        return -1;
    }
    if ((udp_buf[23] == (uint8_t)0x00)                                                         // 社区名称以空字符结束
        && (udp_buf[00] == N2N_PKT_VERSION)                                                    // 正确的包版本
        && ((be16toh(*(uint16_t *)&(udp_buf[02])) & N2N_FLAGS_TYPE_MASK) <= MSG_TYPE_MAX_TYPE) // 消息类型
        && (be16toh(*(uint16_t *)&(udp_buf[02])) < N2N_FLAGS_OPTIONS)                          // 标志
    )
    {
        /* 很可能是未加密的 */
        /* 确保这里不会发生降级，并且不会将未加密的数据包注入到需要加密头部的社区中 */
        HASH_FIND_COMMUNITY(sss->communities, (char *)&udp_buf[04], comm);
        if (comm)
        {
            if (comm->header_encryption == HEADER_ENCRYPTION_ENABLED)
            {
                traceEvent(TRACE_DEBUG, "丢弃一个未加密头部的数据包，该数据包被发送到使用加密头部的社区 '%s'",
                           comm->community);
                return -1;
            }
            if (comm->header_encryption == HEADER_ENCRYPTION_UNKNOWN)
            {
                traceEvent(TRACE_INFO, "将社区 '%s' 锁定为未加密头部",
                           comm->community);
                /* 如果尚未设置，则设置为'无加密' */
                comm->header_encryption = HEADER_ENCRYPTION_NONE;
                comm->header_encryption_ctx_static = NULL;
                comm->header_encryption_ctx_dynamic = NULL;
            }
        }
    }
    else
    {
        /* 很可能是加密的 */
        /* 遍历已知社区（作为密钥）以解密 */
        HASH_ITER(hh, sss->communities, comm, tmp)
        {
            /* 跳过明确未加密的社区 */
            if (comm->header_encryption == HEADER_ENCRYPTION_NONE)
            {
                continue;
            }

            // 匹配静态（1）或动态（2）上下文？
            // 首先检查动态上下文，因为它与静态密钥加密模式下的加密方式相同
            if (packet_header_decrypt(udp_buf, udp_size,
                                      comm->community,
                                      comm->header_encryption_ctx_dynamic, comm->header_iv_ctx_dynamic,
                                      &stamp))
            {
                header_enc = 2;
            }
            if (!header_enc)
            {
                pearson_hash_128(hash_buf, udp_buf, max(0, (int)udp_size - (int)N2N_REG_SUP_HASH_CHECK_LEN));
                header_enc = packet_header_decrypt(udp_buf, max(0, (int)udp_size - (int)N2N_REG_SUP_HASH_CHECK_LEN), comm->community,
                                                   comm->header_encryption_ctx_static, comm->header_iv_ctx_static, &stamp);
            }

            if (header_enc)
            {
                // 时间戳验证将在数据包特定部分进行，因为它需要根据MAC地址从哈希列表中确定发送者，
                // 这一切都取决于数据包类型和数据包结构（MAC不总是在相同的位置）

                if (comm->header_encryption == HEADER_ENCRYPTION_UNKNOWN)
                {
                    traceEvent(TRACE_INFO, "将社区 '%s' 锁定为加密头部",
                               comm->community);
                    /* 设置为'加密'，如果尚未设置 */
                    comm->header_encryption = HEADER_ENCRYPTION_ENABLED;
                }
                // 统计加密包的数量，以便不时对社区进行排序
                // 上面几个代码行的HASH_ITER会随着更忙碌的社区而加速
                (comm->number_enc_packets)++;
                // 不需要进一步测试其他社区
                break;
            }
        }
        if (!header_enc)
        {
            // 没有找到匹配的密钥/社区
            traceEvent(TRACE_DEBUG, "丢弃了一个看似加密的数据包，"
                                    "没有找到匹配的使用加密头部的社区");
            return -1;
        }
    }

    /* 使用decode_common()来确定数据包的类型并处理它：
     *
     * REGISTER_SUPER 添加一个边缘并生成一个返回的REGISTER_SUPER_ACK
     *
     * REGISTER、REGISTER_ACK和PACKET消息将转发到其目标边缘。如果目标未知，则会广播PACKET消息。
     */

    rem = udp_size; /* 倒计时剩余的包字节，防止缓冲区溢出 */
    idx = 0;        /* 遍历解码包头的部分 */

    if (decode_common(&cmn, udp_buf, &rem, &idx) < 0)
    {
        traceEvent(TRACE_ERROR, "解码通用部分失败");
        return -1; /* 解码失败 */
    }

    msg_type = cmn.pc; /* 数据包代码 */

    // 用户/密码认证的特殊情况
    // 社区的认证方案和消息类型需要与所使用的密钥（动态）匹配
    if (comm)
    {
        if ((comm->allowed_users) && (msg_type != MSG_TYPE_REGISTER_SUPER) && (msg_type != MSG_TYPE_REGISTER_SUPER_ACK) && (msg_type != MSG_TYPE_REGISTER_SUPER_NAK))
        {
            if (header_enc != 2)
            {
                traceEvent(TRACE_WARNING, "丢弃了一个使用静态密钥加密的数据包，期望使用动态密钥");
                return -1;
            }
        }
    }

    from_supernode = cmn.flags & N2N_FLAGS_FROM_SUPERNODE;
    if (from_supernode)
    {
        skip_add = SN_ADD_SKIP;
        sn = add_sn_to_list_by_mac_or_sock(&(sss->federation->edges), &sender, null_mac, &skip_add);
        // 只有REGISTER_SUPER可以来自未知的超级节点
        if ((!sn) && (msg_type != MSG_TYPE_REGISTER_SUPER))
        {
            traceEvent(TRACE_DEBUG, "丢弃来自未知超级节点的传入数据");
            return -1;
        }
    }

    if (cmn.ttl < 1)
    {
        traceEvent(TRACE_WARNING, "TTL已过期");
        return 0; /* 不再处理 */
    }

    --(cmn.ttl); /* 将该值复制到所有转发的数据包中 */

    switch (msg_type)
    {
    case MSG_TYPE_PACKET:
    {
        /* 从一个边缘到另一个边缘通过超级节点转发的PACKET消息 */

        /* pkt将原地修改并重新编码为可能不同大小的输出，
         * 由于添加了套接字。*/
        n2n_PACKET_t pkt;
        n2n_common_t cmn2;
        uint8_t encbuf[N2N_SN_PKTBUF_SIZE];
        size_t encx = 0;
        int unicast;      /* 如果是单播，则为非零 */
        uint8_t *rec_buf; /* 可以是udp_buf或encbuf */

        if (!comm)
        {
            traceEvent(TRACE_DEBUG, "未知社区的PACKET %s", cmn.community);
            return -1;
        }

        sss->stats.last_fwd = now;
        decode_PACKET(&pkt, &cmn, udp_buf, &rem, &idx);

        // 已经检查了有效的社区
        if (comm->header_encryption == HEADER_ENCRYPTION_ENABLED)
        {
            if (!find_edge_time_stamp_and_verify(comm->edges, sn, pkt.srcMac, stamp, TIME_STAMP_ALLOW_JITTER))
            {
                traceEvent(TRACE_DEBUG, "丢弃PACKET，因为时间戳错误");
                return -1;
            }
        }

        unicast = (0 == is_multi_broadcast(pkt.dstMac));

        traceEvent(TRACE_DEBUG, "RX PACKET (%s) %s -> %s %s",
                   (unicast ? "单播" : "广播"),
                   macaddr_str(mac_buf, pkt.srcMac),
                   macaddr_str(mac_buf2, pkt.dstMac),
                   (from_supernode ? "来自超级节点" : "本地"));

        if (!from_supernode)
        {
            memcpy(&cmn2, &cmn, sizeof(n2n_common_t));

            /* 即使之前没有套接字，也要添加套接字 */
            cmn2.flags |= N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;

            memcpy(&pkt.sock, &sender, sizeof(sender));

            rec_buf = encbuf;
            /* 重新编码头部 */
            encode_PACKET(encbuf, &encx, &cmn2, &pkt);

            uint16_t oldEncx = encx;

            /* 保持原始有效负载不变 */
            encode_buf(encbuf, &encx, (udp_buf + idx), (udp_size - idx));

            if (comm->header_encryption == HEADER_ENCRYPTION_ENABLED)
            {
                // 如果是用户-密码认证，还需要加密有效负载的IV，假设ChaCha20和SPECK具有相同的IV大小
                packet_header_encrypt(rec_buf, oldEncx + (NULL != comm->allowed_users) * min(encx - oldEncx, N2N_SPECK_IVEC_SIZE), encx,
                                      comm->header_encryption_ctx_dynamic, comm->header_iv_ctx_dynamic,
                                      time_stamp());
            }
        }
        else
        {
            /* 已经来自超级节点。无需修改，只需转发到目标。 */

            traceEvent(TRACE_DEBUG, "Rx PACKET 转发未修改");

            rec_buf = udp_buf;
            encx = udp_size;

            if (comm->header_encryption == HEADER_ENCRYPTION_ENABLED)
            {
                // 如果是用户-密码认证，还需要加密有效负载的IV，假设ChaCha20和SPECK具有相同的IV大小
                packet_header_encrypt(rec_buf, idx + (NULL != comm->allowed_users) * min(encx - idx, N2N_SPECK_IVEC_SIZE), encx,
                                      comm->header_encryption_ctx_dynamic, comm->header_iv_ctx_dynamic,
                                      time_stamp());
            }
        }

        /* 转发最终产品的共同部分。 */
        if (unicast)
        {
            try_forward(sss, comm, &cmn, pkt.dstMac, from_supernode, rec_buf, encx, now);
        }
        else
        {
            try_broadcast(sss, comm, &cmn, pkt.srcMac, from_supernode, rec_buf, encx, now);
        }
        break;
    }

    case MSG_TYPE_REGISTER:
    {
        /* 从一个边缘转发REGISTER到下一个边缘 */

        n2n_REGISTER_t reg;
        n2n_common_t cmn2;
        uint8_t encbuf[N2N_SN_PKTBUF_SIZE];
        size_t encx = 0;
        int unicast;      /* 如果是单播，则为非零 */
        uint8_t *rec_buf; /* 可以是udp_buf或encbuf */

        if (!comm)
        {
            traceEvent(TRACE_DEBUG, "REGISTER来自未知社区 %s", cmn.community);
            return -1;
        }

        sss->stats.last_fwd = now;
        decode_REGISTER(&reg, &cmn, udp_buf, &rem, &idx);

        // 已经检查了有效的社区
        if (comm->header_encryption == HEADER_ENCRYPTION_ENABLED)
        {
            if (!find_edge_time_stamp_and_verify(comm->edges, sn, reg.srcMac, stamp, TIME_STAMP_NO_JITTER))
            {
                traceEvent(TRACE_DEBUG, "丢弃REGISTER，因为时间戳错误");
                return -1;
            }
        }

        unicast = (0 == is_multi_broadcast(reg.dstMac));

        if (unicast)
        {
            traceEvent(TRACE_DEBUG, "Rx REGISTER %s -> %s %s",
                       macaddr_str(mac_buf, reg.srcMac),
                       macaddr_str(mac_buf2, reg.dstMac),
                       ((cmn.flags & N2N_FLAGS_FROM_SUPERNODE) ? "来自超级节点" : "本地"));

            if (0 == (cmn.flags & N2N_FLAGS_FROM_SUPERNODE))
            {
                memcpy(&cmn2, &cmn, sizeof(n2n_common_t));

                /* 即使之前没有套接字，也要添加套接字 */
                cmn2.flags |= N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;

                memcpy(&reg.sock, &sender, sizeof(sender));

                /* 重新编码头部 */
                encode_REGISTER(encbuf, &encx, &cmn2, &reg);

                rec_buf = encbuf;
            }
            else
            {
                /* 已经来自超级节点。无需修改，只需转发到目标。 */

                rec_buf = udp_buf;
                encx = udp_size;
            }

            if (comm->header_encryption == HEADER_ENCRYPTION_ENABLED)
            {
                packet_header_encrypt(rec_buf, encx, encx,
                                      comm->header_encryption_ctx_dynamic, comm->header_iv_ctx_dynamic,
                                      time_stamp());
            }
            try_forward(sss, comm, &cmn, reg.dstMac, from_supernode, rec_buf, encx, now); /* 仅单播 */
        }
        else
        {
            traceEvent(TRACE_ERROR, "Rx REGISTER，目标为多播地址");
        }
        break;
    }

    default:
        /* 未知的消息类型 */
        traceEvent(TRACE_WARNING, "无法处理的数据包类型 %d：已忽略", (signed int)msg_type);
    } /* switch(msg_type) */

    return 0;
}

/** 长时间运行的处理入口点。为了在某些平台上简化守护进程功能，已从主函数中拆分出来。 */
int run_sn_loop(n2n_sn_t *sss)
{

    uint8_t pktbuf[N2N_SN_PKTBUF_SIZE]; // 存储接收到的数据包
    time_t last_purge_edges = 0;        // 上次清除边缘节点的时间
    time_t last_sort_communities = 0;   // 上次排序社区的时间
    time_t last_re_reg_and_purge = 0;   // 上次重新注册和清理的时间

    sss->start_time = time(NULL); // 记录当前时间作为启动时间

    // 主循环，直到 keep_running 被设置为 false
    while (*sss->keep_running)
    {
        int rc;                                // 用于 select 的返回值
        ssize_t bread;                         // 接收到的字节数
        int max_sock;                          // 最大套接字值
        fd_set socket_mask;                    // 用于 select 的套接字集合
        n2n_tcp_connection_t *conn, *tmp_conn; // TCP 连接结构体

#ifdef N2N_HAVE_TCP
        SOCKET tmp_sock;        // 临时套接字，用于接收新的 TCP 连接
        n2n_sock_str_t sockbuf; // 存储套接字的字符串表示
#endif
        struct timeval wait_time; // 用于 select 的超时时间
        time_t before, now = 0;   // 当前时间与之前的时间用于计算超时

        FD_ZERO(&socket_mask); // 清空套接字集合

        FD_SET(sss->sock, &socket_mask); // 设置外部 UDP 套接字
#ifdef N2N_HAVE_TCP
        FD_SET(sss->tcp_sock, &socket_mask); // 设置 TCP 套接字
#endif
        FD_SET(sss->mgmt_sock, &socket_mask); // 设置管理端口的套接字

        // 确定 select 时的最大套接字值
        max_sock = MAX(MAX(sss->sock, sss->mgmt_sock), sss->tcp_sock);

#ifdef N2N_HAVE_TCP
        // 将所有已知的 TCP 连接套接字添加到集合中
        HASH_ITER(hh, sss->tcp_connections, conn, tmp_conn)
        {
            FD_SET(conn->socket_fd, &socket_mask); // 添加 TCP 连接套接字
            if (conn->socket_fd > max_sock)
                max_sock = conn->socket_fd; // 更新最大套接字值
        }
#endif

        wait_time.tv_sec = 10; // 设置 select 等待的时间（10秒）
        wait_time.tv_usec = 0;

        before = time(NULL); // 获取当前时间

        // 调用 select 函数等待套接字事件
        rc = select(max_sock + 1, &socket_mask, NULL, NULL, &wait_time);

        now = time(NULL); // 再次获取当前时间

        if (rc > 0) // 如果有可用的套接字
        {
            // 处理外部的 UDP 数据包
            if (FD_ISSET(sss->sock, &socket_mask))
            {
                struct sockaddr_storage sas;
                struct sockaddr *sender_sock = (struct sockaddr *)&sas;
                socklen_t ss_size = sizeof(sas);

                // 接收 UDP 数据包
                bread = recvfrom(sss->sock, (void *)pktbuf, N2N_SN_PKTBUF_SIZE, 0, sender_sock, &ss_size);

                if ((bread < 0)
#ifdef _WIN32
                    && (WSAGetLastError() != WSAECONNRESET)
#endif
                )
                {
                    // 处理接收错误
                    traceEvent(TRACE_ERROR, "recvfrom() 失败 %d errno %d (%s)", bread, errno, strerror(errno));
#ifdef _WIN32
                    traceEvent(TRACE_ERROR, "WSAGetLastError(): %u", WSAGetLastError());
#endif
                    *sss->keep_running = false; // 设置 stop 运行标志，退出循环
                    break;
                }

                // 如果接收到了数据
                if (bread > 0)
                {
                    // 处理数据包
                    process_udp(sss, sender_sock, ss_size, sss->sock, pktbuf, bread, now);
                }
            }

#ifdef N2N_HAVE_TCP
            // 处理已知的 TCP 连接
            HASH_ITER(hh, sss->tcp_connections, conn, tmp_conn)
            {
                if (conn->inactive) // 跳过标记为非活动的连接
                    continue;

                // 检查是否有数据到达该连接
                if (FD_ISSET(conn->socket_fd, &socket_mask))
                {
                    struct sockaddr_storage sas;
                    struct sockaddr *sender_sock = (struct sockaddr *)&sas;
                    socklen_t ss_size = sizeof(sas);

                    // 接收 TCP 数据
                    bread = recvfrom(conn->socket_fd,
                                     conn->buffer + conn->position, conn->expected - conn->position, 0,
                                     sender_sock, &ss_size);

                    if (bread <= 0)
                    {
                        // 关闭连接并打印日志
                        traceEvent(TRACE_INFO, "关闭 TCP 连接 [%s]", sock_to_cstr(sockbuf, (n2n_sock_t *)sender_sock));
                        close_tcp_connection(sss, conn);
                        continue;
                    }

                    conn->position += bread;

                    if (conn->position == conn->expected)
                    {
                        if (conn->position == sizeof(uint16_t)) // 读取包头，准备接收数据包
                        {
                            conn->expected += be16toh(*(uint16_t *)(conn->buffer));
                            if (conn->expected > N2N_SN_PKTBUF_SIZE)
                            {
                                traceEvent(TRACE_INFO, "关闭 TCP 连接 [%s]", sock_to_cstr(sockbuf, (n2n_sock_t *)sender_sock));
                                close_tcp_connection(sss, conn);
                                continue;
                            }
                        }
                        else // 完整数据包已接收
                        {
                            // 处理接收到的 UDP 数据
                            process_udp(sss, &(conn->sock), conn->sock_len, conn->socket_fd,
                                        conn->buffer + sizeof(uint16_t), conn->position - sizeof(uint16_t), now);

                            // 重置连接，等待新的数据包长度
                            conn->expected = sizeof(uint16_t);
                            conn->position = 0;
                        }
                    }
                }
            }

            // 移除非活动或已关闭的 TCP 连接
            HASH_ITER(hh, sss->tcp_connections, conn, tmp_conn)
            {
                if (conn->inactive)
                {
                    HASH_DEL(sss->tcp_connections, conn);
                    free(conn);
                }
            }

            // 接受新的 TCP 连接
            if (FD_ISSET(sss->tcp_sock, &socket_mask))
            {
                struct sockaddr_storage sas;
                struct sockaddr *sender_sock = (struct sockaddr *)&sas;
                socklen_t ss_size = sizeof(sas);

                if ((HASH_COUNT(sss->tcp_connections) + 4) < FD_SETSIZE) // 检查是否有空间接受新连接
                {
                    tmp_sock = accept(sss->tcp_sock, sender_sock, &ss_size);
                    if (tmp_sock >= 0)
                    {
                        conn = (n2n_tcp_connection_t *)calloc(1, sizeof(n2n_tcp_connection_t));
                        if (conn)
                        {
                            conn->socket_fd = tmp_sock;
                            memcpy(&(conn->sock), sender_sock, ss_size);
                            conn->sock_len = ss_size;
                            conn->inactive = 0;
                            conn->expected = sizeof(uint16_t);
                            conn->position = 0;
                            HASH_ADD_INT(sss->tcp_connections, socket_fd, conn);
                            traceEvent(TRACE_INFO, "接受到来自 [%s] 的 TCP 连接", sock_to_cstr(sockbuf, (n2n_sock_t *)sender_sock));
                        }
                    }
                }
                else
                {
                    // 如果连接数已达上限，拒绝新连接
                    traceEvent(TRACE_DEBUG, "由于达到最大连接数，拒绝来自 [%s] 的 TCP 连接", sock_to_cstr(sockbuf, (n2n_sock_t *)sender_sock));
                }
            }
#endif /* N2N_HAVE_TCP */

            // 处理管理端口输入
            if (FD_ISSET(sss->mgmt_sock, &socket_mask))
            {
                struct sockaddr_storage sas;
                struct sockaddr *sender_sock = (struct sockaddr *)&sas;
                socklen_t ss_size = sizeof(sas);

                bread = recvfrom(sss->mgmt_sock, (void *)pktbuf, N2N_SN_PKTBUF_SIZE, 0,
                                 sender_sock, &ss_size);

                if (bread <= 0)
                {
                    // 处理管理端口接收失败
                    traceEvent(TRACE_ERROR, "recvfrom() 失败 %d errno %d (%s)", bread, errno, strerror(errno));
                    *sss->keep_running = false;
                    break;
                }

                // 处理接收到的管理数据包
                process_mgmt(sss, sender_sock, ss_size, (char *)pktbuf, bread, now);
            }
        }
        else
        {
            if (((now - before) < wait_time.tv_sec) && (*sss->keep_running))
            {
                // 如果没有真正的超时，可能是某个 TCP 连接出了问题，关闭所有连接
                traceEvent(TRACE_DEBUG, "错误地标记了超时，假设 TCP 连接出现问题，关闭所有连接");
                HASH_ITER(hh, sss->tcp_connections, conn, tmp_conn)
                close_tcp_connection(sss, conn);
            }
            else
                traceEvent(TRACE_DEBUG, "超时");
        }

        // 定期重新注册和清理超节点
        re_register_and_purge_supernodes(sss, sss->federation, &last_re_reg_and_purge, now, 0);
        purge_expired_communities(sss, &last_purge_edges, now);
        sort_communities(sss, &last_sort_communities, now);
        resolve_check(sss->resolve_parameter, 0, now);
    } /* while */

    sn_term(sss); // 终止处理

    return 0;
}
