/**
 * (C) 2007-22 - ntop.org 和贡献者
 *
 * 本程序是免费软件；您可以根据自由软件基金会发布的 GNU 通用公共许可证条款重新分发和/或修改它；无论是许可证第 3 版，还是
 *（您可选择）任何后续版本。
 *
 * 本程序分发时希望它有用，
 * 但不附带任何担保；甚至不附带
 * 适销性或特定用途适用性的默示担保。有关更多详细信息，请参阅
 * GNU 通用公共许可证。
 *
 * 您应该已收到 GNU 通用公共许可证的副本
 * 以及本程序；如果没有，请参阅 <http://www.gnu.org/licenses/>
 *
 */

/* n2n-2.x 的超级节点 */

#include <ctype.h>  // 用于 isspace
#include <errno.h>  // 用于 errno
#include <getopt.h> // 用于 required_argument、getopt_long、no_arg...
#include <signal.h> // 用于 signal、SIGHUP、SIGINT、SIGPIPE、SIGTERM
#include <stdbool.h>
#include <stdint.h>    // 用于 uint8_t、uint32_t
#include <stdio.h>     // 用于 printf、NULL、fclose、fgets、fopen
#include <stdlib.h>    // 用于 exit、atoi、calloc、free
#include <string.h>    // 用于 strerror、strlen、memcpy、strncpy、str...
#include <sys/types.h> // 用于 time_t、u_char、u_int
#include <time.h>      // 用于时间
#include <unistd.h>    // 用于 _exit、daemon、getgid、getuid、setgid
#include "n2n.h"       // 用于 n2n_sn_t、sn_community、traceEvent
#include "pearson.h"   // 用于 pearson_hash_64
#include "uthash.h"    // 用于 UT_hash_handle、HASH_ITER、HASH_ADD_STR

#ifdef _WIN32
#include "win32/defs.h"
#else
#include <arpa/inet.h>  // 用于 inet_addr
#include <netinet/in.h> // 用于 ntohl、INADDR_ANY、INADDR_NONE、in_addr_t
#include <pwd.h>        // 用于 getpwnam、passwd
#include <sys/socket.h> // 用于听着，AF_INET
#endif
#define HASH_FIND_COMMUNITY(head, name, out) HASH_FIND_STR(head, name, out)

static n2n_sn_t sss_node;

void close_tcp_connection(n2n_sn_t *sss, n2n_tcp_connection_t *conn);
void calculate_shared_secrets(n2n_sn_t *sss);
int load_allowed_sn_community(n2n_sn_t *sss);
int resolve_create_thread(n2n_resolve_parameter_t **param, struct peer_info *sn_list);

/** 如果命令行参数无效，则打印帮助消息。 */
static void help(int level)
{

    if (level == 0) /* 无需帮助 */
        return;

    printf("\n");
    print_n2n_version();

    if (level == 1) /* 简短帮助*/
    {

        printf(" 基本用法：supernode <配置文件>（参见 supernode.conf）\n"
               "\n"
               " 或 supernode "
               "[可选参数，至少一个] "
               "\n "
               "\n 从技术上讲，所有参数都是可选的，但 supernode 可执行文件"
               "\n 至少需要一个参数才能运行，例如 -v 或 -f，否则"
               "\n 显示简短帮助文本"
               "\n\n -h 显示包含所有可用选项的快速参考"
               "\n --help 提供详细的参数描述"
               "\n n2n、edge 和 supernode 的 man 文件包含深入信息"
               "\n\n");
    }
    else if (level == 2) /* 快速参考 */
    {

        printf(" 一般用法：supernode <配置文件>（参见 supernode.conf）\n"
               "\n"
               " 或 supernode "
               "[-p [<本地绑定 ip 地址>:]<本地端口>] "
               "\n "
               "[-F <联合名称>] "
               "\n 下级选项 "
               "[-l <超级节点主机:端口>] "
               "\n 连接 "
#ifdef SN_MANUAL_MAC
               "[-m <mac 地址>] "
#endif
               "[-M] "
               "[-V <版本文本>] "
               "\n\n 覆盖网络 "
               "[-c <社区列表文件>] "
               "\n 配置 "
               "[-a <网络 ip>-<网络 ip>/<cidr 后缀>] "
               "\n\n 本地选项 "
#if defined(N2N_HAVE_DAEMON)
               "[-f] "
#endif
               "[-t <管理端口>] "
               "\n "
               "[--管理密码 <pw>] "
               "[-v] "
#ifndef _WIN32
               "\n "
               "[-u <数字用户 ID>]"
               "[-g <数字组 ID>]"
#endif
               "\n\n  的含义"
               "[-M] 禁用 MAC 和 IP 地址欺骗保护"
               "\n 标志选项 "
#if defined(N2N_HAVE_DAEMON)
               "[-f] 不分叉但在前台运行"
               "\n "
#endif
               "[-v] 使更详细，根据需要重复"
               "\n "
               "\n 从技术上讲，所有参数都是可选的，但超级节点可执行文件"
               "\n 至少需要一个参数才能运行，例如-v 或 -f，否则为"
               "\n 显示简短帮助文本"
               "\n\n -h 显示此快速参考，包括所有可用选项"
               "\n --help 提供详细的参数描述"
               "\n n2n、edge 和 supernode 的 man 文件包含深入信息"
               "\n\n");
    }
    else /* 长帮助 */
    {

        printf(" 一般用法：超级节点 <配置文件>（参见 supernode.conf）\n"
               "\n"
               " 或超级节点 [可选参数，至少一个]\n\n");
        printf(" 底层网络连接选项\n");
        printf(" ---------------------------------------------\n\n");
        printf(" -p [<ip>:]<port> | 固定本地 UDP 端口（默认为 %u）和可选\n"
               " | 仅绑定到指定的本地 IP 地址（默认为 'any'）\n",
               N2N_SN_LPORT_DEFAULT);
        printf(" -F <fed name> | 超级节点联合的名称，默认为\n"
               " | '%s'\n",
               (char *)FEDERATION_NAME);
        printf(" -l <​​host:port> | 已知超级节点的 IP 地址或名称以及端口\n");
#ifdef SN_MANUAL_MAC
        printf(" -m <mac> | 超级节点的固定 MAC 地址，例如。\n"
               " | '-m 10:20:30:40:50:60'，否则为随机\n");
#endif
        printf(" -M | 禁用所有 MAC 和 IP 地址欺骗保护\n"
               " | 非用户名密码验证社区\n");
        printf(" -V <version text> | 向边缘发送最多 19 个字母的自定义超级节点版本字符串 \n"
               " | 长度，在其管理端口输出中可见\n");
        printf("\n");
        printf(" TAP 设备和覆盖网络配置\n");
        printf(" --------------------------------------------\n\n");
        printf(" -c <path> | 包含允许社区的文件\n");
        printf(" -a <net-net/n> | 自动 IP 地址服务的子网范围，例如。\n"
               " | '-a 192.168.0.0-192.168.255.0/24'，默认值\n"
               " | 至 '10.128.255.0-10.255.255.0/24'\n");
        printf("\n");
        printf(" 本地选项\n");
        printf(" -------------\n\n");
#if defined(N2N_HAVE_DAEMON)
        printf(" -f | 不分叉并作为守护进程运行，而是在前台运行\n");
#endif
        printf(" -t <port> | 管理 UDP 端口，用于一台机器上的多个超级节点，\n"
               " | 默认为 %u\n",
               N2N_SN_MGMT_PORT);
        printf(" --management_... | 管理端口密码，默认为 '%s'\n"
               " ...password <pw> | \n",
               N2N_MGMT_PASSWORD);
        printf(" -v | 使其更详细，根据需要重复\n");
#ifndef _WIN32
        printf(" -u <UID> | 放弃权限时使用的数字用户 ID\n");
        printf(" -g <GID> | 放弃权限时使用的数字组 ID\n");
#endif
        printf("\n 从技术上讲，所有参数都是可选的，但超级节点可执行文件"
               "\n 至少需要一个参数才能运行，例如 -v 或 -f，否则"
               "\n 会显示简短的帮助文本"
               "\n\n -h 显示包含所有可用选项的快速参考"
               "\n --help 提供此详细参数描述"
               "\n n2n、edge 和超级节点的 man 文件包含深入信息"
               "\n\n");
    }

    exit(0);
}

/* *************************************************** */

/**
 * @brief 设置超级节点（supernode）的运行选项
 * @param optkey 选项字符标识（如 'p'、't' 等）
 * @param _optarg 选项对应的参数字符串
 * @param sss 超级节点状态结构体指针
 * @return 返回状态码：
 *         0 - 成功
 *         1 - 参数格式错误
 *         2 - 无效选项或值
 *         3 - 请求显示帮助信息
 *
 * 该函数根据命令行参数配置超级节点的各种运行参数，包括网络绑定、端口设置、联邦配置等。
 */
static int setOption(int optkey, char *_optarg, n2n_sn_t *sss)
{
    // 调试用：可以取消注释以查看选项设置情况
    // traceEvent(TRACE_NORMAL, "Option %c = %s", optkey, _optarg ? _optarg : "");

    switch (optkey)
    {
    case 'p': /* 本地绑定端口设置 */
    {
        /* 格式可能是：
         * 1) IP:端口（如 192.168.1.1:1234）
         * 2) 仅IP（如 192.168.1.1）
         * 3) 仅端口（如 1234） */
        char *colon = strpbrk(_optarg, ":");
        if (colon)
        {                                                  /* 情况1：IP地址:端口格式 */
            *colon = 0;                                    // 临时替换冒号为字符串结束符
            sss->bind_address = ntohl(inet_addr(_optarg)); // 转换IP地址为网络字节序
            sss->lport = atoi(++colon);                    // 解析端口号

            // 验证IP地址有效性
            if (sss->bind_address == INADDR_NONE)
            {
                traceEvent(TRACE_WARNING, "bad address to bind to, binding to any IP address");
                sss->bind_address = INADDR_ANY; // 默认绑定所有接口
            }
            // 验证端口有效性
            if (sss->lport == 0)
            {
                traceEvent(TRACE_WARNING, "bad local port format, defaulting to %u", N2N_SN_LPORT_DEFAULT);
                sss->lport = N2N_SN_LPORT_DEFAULT; // 使用默认端口
            }
        }
        else
        { /* 情况2或3：仅IP或仅端口 */
            char *dot = strpbrk(_optarg, ".");
            if (dot)
            { /* 情况2：仅IP地址 */
                sss->bind_address = ntohl(inet_addr(_optarg));
                if (sss->bind_address == INADDR_NONE)
                {
                    traceEvent(TRACE_WARNING, "bad address to bind to, binding to any IP address");
                    sss->bind_address = INADDR_ANY;
                }
            }
            else
            { /* 情况3：仅端口号 */
                sss->lport = atoi(_optarg);
                if (sss->lport == 0)
                {
                    traceEvent(TRACE_WARNING, "bad local port format, defaulting to %u", N2N_SN_LPORT_DEFAULT);
                    sss->lport = N2N_SN_LPORT_DEFAULT;
                }
            }
        }
        break;
    }

    case 't': /* 管理端口设置 */
        sss->mport = atoi(_optarg);
        if (sss->mport == 0)
            traceEvent(TRACE_WARNING, "bad management port format, defaulting to %u", N2N_SN_MGMT_PORT);
        // 注意：默认值在sn_init()中确保
        break;

    case 'l': /* 上级超级节点配置（格式：host:port） */
    {
        n2n_sock_t *socket;
        struct peer_info *anchor_sn;
        size_t length;
        int rv = -1;
        int skip_add;
        char *double_column = strchr(_optarg, ':'); // 查找端口分隔符

        // 检查主机名长度是否超限
        length = strlen(_optarg);
        if (length >= N2N_EDGE_SN_HOST_SIZE)
        {
            traceEvent(TRACE_WARNING, "size of -l argument too long: %zu; maximum size is %d", length, N2N_EDGE_SN_HOST_SIZE);
            return 1;
        }

        // 必须包含端口号
        if (!double_column)
        {
            traceEvent(TRACE_WARNING, "invalid -l format, missing port");
            return 1;
        }

        // 解析超级节点地址
        socket = (n2n_sock_t *)calloc(1, sizeof(n2n_sock_t));
        rv = supernode2sock(socket, _optarg); // 将字符串转换为socket结构

        // 检查解析结果（允许DNS解析失败，因为可能稍后解析）
        if (rv < -2)
        {
            traceEvent(TRACE_WARNING, "invalid supernode parameter");
            free(socket);
            return 1;
        }

        // 如果联邦模式已启用，添加到节点列表
        if (sss->federation != NULL)
        {
            skip_add = SN_ADD;
            // 按MAC或socket地址添加节点
            anchor_sn = add_sn_to_list_by_mac_or_sock(&(sss->federation->edges), socket, null_mac, &skip_add);

            if (anchor_sn != NULL)
            {
                // 保存节点信息
                anchor_sn->ip_addr = calloc(1, N2N_EDGE_SN_HOST_SIZE);
                if (anchor_sn->ip_addr)
                {
                    strncpy(anchor_sn->ip_addr, _optarg, N2N_EDGE_SN_HOST_SIZE - 1);
                    memcpy(&(anchor_sn->sock), socket, sizeof(n2n_sock_t));
                    memcpy(anchor_sn->mac_addr, null_mac, sizeof(n2n_mac_t));
                    anchor_sn->purgeable = false;                            // 不可清除
                    anchor_sn->last_valid_time_stamp = initial_time_stamp(); // 初始化时间戳
                }
            }
        }

        free(socket);
        break;
    }

    case 'a': /* 自动IP分配范围设置（格式：minIP-maxIP/bitlen） */
    {
        dec_ip_str_t ip_min_str = {'\0'};
        dec_ip_str_t ip_max_str = {'\0'};
        in_addr_t net_min, net_max;
        uint8_t bitlen;
        uint32_t mask;

        // 解析IP范围格式
        if (sscanf(_optarg, "%15[^\\-]-%15[^/]/%hhu", ip_min_str, ip_max_str, &bitlen) != 3)
        {
            traceEvent(TRACE_WARNING, "bad net-net/bit format '%s'.", _optarg);
            return 2;
        }

        // 转换IP地址并验证
        net_min = inet_addr(ip_min_str);
        net_max = inet_addr(ip_max_str);
        mask = bitlen2mask(bitlen); // 计算子网掩码

        // 验证IP范围有效性
        if ((net_min == (in_addr_t)(-1)) || (net_min == INADDR_NONE) || (net_min == INADDR_ANY) ||
            (net_max == (in_addr_t)(-1)) || (net_max == INADDR_NONE) || (net_max == INADDR_ANY) ||
            (ntohl(net_min) > ntohl(net_max)) ||
            ((ntohl(net_min) & ~mask) != 0) || ((ntohl(net_max) & ~mask) != 0))
        {
            traceEvent(TRACE_WARNING, "bad network range '%s...%s/%u' in '%s', defaulting to '%s...%s/%d'",
                       ip_min_str, ip_max_str, bitlen, _optarg,
                       N2N_SN_MIN_AUTO_IP_NET_DEFAULT, N2N_SN_MAX_AUTO_IP_NET_DEFAULT, N2N_SN_AUTO_IP_NET_BIT_DEFAULT);
            return 2;
        }

        // 验证子网前缀长度
        if ((bitlen > 30) || (bitlen == 0))
        {
            traceEvent(TRACE_WARNING, "bad prefix '%hhu' in '%s', defaulting to '%s...%s/%d'",
                       bitlen, _optarg,
                       N2N_SN_MIN_AUTO_IP_NET_DEFAULT, N2N_SN_MAX_AUTO_IP_NET_DEFAULT, N2N_SN_AUTO_IP_NET_BIT_DEFAULT);
            return 2;
        }

        traceEvent(TRACE_NORMAL, "the network range for community ip address service is '%s...%s/%hhu'",
                   ip_min_str, ip_max_str, bitlen);

        // 保存有效配置
        sss->min_auto_ip_net.net_addr = ntohl(net_min);
        sss->min_auto_ip_net.net_bitlen = bitlen;
        sss->max_auto_ip_net.net_addr = ntohl(net_max);
        sss->max_auto_ip_net.net_bitlen = bitlen;

        break;
    }

#ifndef _WIN32
    case 'u': /* 非特权用户ID设置（仅限非Windows系统） */
        sss->userid = atoi(_optarg);
        break;

    case 'g': /* 非特权组ID设置（仅限非Windows系统） */
        sss->groupid = atoi(_optarg);
        break;
#endif

    case 'F': /* 联邦名称设置 */
        snprintf(sss->federation->community, N2N_COMMUNITY_SIZE - 1, "*%s", _optarg);
        sss->federation->community[N2N_COMMUNITY_SIZE - 1] = '\0';
        sss->federation->purgeable = false; // 联邦节点不可清除
        break;

#ifdef SN_MANUAL_MAC
    case 'm': /* 手动设置MAC地址 */
    {
        str2mac(sss->mac_addr, _optarg); // 转换字符串为MAC地址

        // 清除多播位（第0字节的最低位）
        sss->mac_addr[0] &= ~0x01;
        // 设置本地分配位（第0字节的次低位）
        sss->mac_addr[0] |= 0x02;

        break;
    }
#endif

    case 'M': /* 覆盖欺骗保护 */
        sss->override_spoofing_protection = 1;
        break;

    case 'V': /* 版本信息设置 */
        strncpy(sss->version, _optarg, sizeof(n2n_version_t));
        sss->version[sizeof(n2n_version_t) - 1] = '\0'; // 确保字符串终止
        break;

    case 'c': /* 社区文件路径设置 */
        sss->community_file = calloc(1, strlen(_optarg) + 1);
        if (sss->community_file)
            strcpy(sss->community_file, _optarg);
        break;

    case ']': /* 管理端口密码设置 */
    {
        // 使用Pearson哈希算法生成64位密码哈希
        sss->mgmt_password_hash = pearson_hash_64((uint8_t *)_optarg, strlen(_optarg));
        break;
    }

#if defined(N2N_HAVE_DAEMON)
    case 'f': /* 前台运行模式（不守护进程化） */
        sss->daemon = 0;
        break;
#endif

    case 'h': /* 显示简要帮助 */
        return 2;

    case '@': /* 显示详细帮助 */
        return 3;

    case 'v': /* 增加日志详细级别 */
        setTraceLevel(getTraceLevel() + 1);
        break;

    default: /* 未知选项处理 */
        traceEvent(TRACE_WARNING, "unknown option -%c:", (char)optkey);
        return 2;
    }

    return 0; // 成功返回
}
/* *********************************************** */

/**
 * @brief 长选项配置结构体数组
 *
 * 该数组定义了超级节点支持的所有长格式命令行选项（--option），
 * 每个选项对应一个短格式选项（-o）。
 * 使用 getopt_long() 函数解析命令行参数时会用到此配置。
 */
static const struct option long_options[] = {
    /* 格式说明：
     * {"长选项名", 参数要求, NULL, 对应短选项字符},
     *
     * 参数要求可以是：
     *   no_argument        - 不需要参数（标志选项）
     *   required_argument  - 必须带参数
     *   optional_argument  - 参数可选
     */

    /* 社区文件路径（对应短选项 -c） */
    {"communities", required_argument, NULL, 'c'},

#if defined(N2N_HAVE_DAEMON)
    /* 前台运行模式（不守护进程化，对应短选项 -f）
     * 仅在支持守护进程的系统上有效 */
    {"foreground", no_argument, NULL, 'f'},
#endif

    /* 本地绑定端口/地址（对应短选项 -p）
     * 格式可以是：
     *   --local-port=IP:PORT
     *   --local-port=IP
     *   --local-port=PORT */
    {"local-port", required_argument, NULL, 'p'},

    /* 管理端口设置（对应短选项 -t） */
    {"mgmt-port", required_argument, NULL, 't'},

    /* 自动IP分配范围（对应短选项 -a）
     * 格式：--autoip=minIP-maxIP/bitlen
     * 例如：--autoip=10.0.0.1-10.0.0.254/24 */
    {"autoip", required_argument, NULL, 'a'},

    /* 增加日志详细级别（对应短选项 -v）
     * 可多次使用增加详细级别 */
    {"verbose", no_argument, NULL, 'v'},

    /* 显示详细帮助（对应特殊短选项 @）
     * 使用特殊字符 '@' 来标识长帮助请求 */
    {"help", no_argument, NULL, '@'},

    /* 管理端口密码（对应特殊短选项 ]）
     * 使用特殊字符 ']' 来标识密码选项 */
    {"management-password", required_argument, NULL, ']'},

    /* 结束标记（必须全部为NULL/0） */
    {NULL, 0, NULL, 0}};
/* *************************************************** */

/* 读取命令行选项 */
static int loadFromCLI(int argc, char *const argv[], n2n_sn_t *sss)
{

    u_char c;

    while ((c = getopt_long(argc, argv,
                            "p:l:t:a:c:F:vhMV:"
#ifdef SN_MANUAL_MAC
                            "m:"
#endif
#if defined(N2N_HAVE_DAEMON)
                            "f"
#endif
#ifndef _WIN32
                            "u:g:"
#endif
                            ,
                            long_options, NULL)) != '?')
    {
        if (c == 255)
        {
            break;
        }
        help(setOption(c, optarg, sss));
    }

    return 0;
}

/* *************************************************** */

/**
 * @brief 去除字符串首尾的空白字符和引号
 * @param s 要处理的字符串（会被直接修改）
 * @return 返回处理后的字符串指针（与输入指针相同）
 *
 * 该函数会原地修改字符串，删除以下字符：
 * 1. 首部的空格/制表符/换行符等空白字符
 * 2. 首部的单引号或双引号
 * 3. 尾部的空白字符
 * 4. 尾部的单引号或双引号
 */
static char *trim(char *s)
{
    char *end; // 用于指向字符串末尾的指针

    /* 处理字符串开头部分 */
    // 循环检查第一个字符是否是空白字符或引号
    while (isspace(s[0]) || (s[0] == '"') || (s[0] == '\''))
    {
        s++; // 如果是，就将指针向后移动，相当于"跳过"这些字符
    }

    /* 检查是否已经是空字符串 */
    if (s[0] == 0)
    {
        return s; // 如果已经是空字符串，直接返回
    }

    /* 处理字符串结尾部分 */
    end = &s[strlen(s) - 1]; // 将end指针指向字符串最后一个有效字符

    // 从后向前检查，直到遇到非空白/非引号字符或到达字符串开头
    while (end > s && (isspace(end[0]) || (end[0] == '"') || (end[0] == '\'')))
    {
        end--; // 向前移动指针，跳过这些字符
    }
    end[1] = 0; // 在最后一个有效字符后设置字符串结束符'\0'

    return s; // 返回处理后的字符串
}

/* *************************************************** */

/* 解析配置文件 */
/**
 * @brief 从命令行加载并解析配置参数
 * @param argc 参数个数（来自main函数）
 * @param argv 参数数组（来自main函数）
 * @param sss 超级节点状态结构体指针
 * @return 始终返回0，错误通过help()函数处理
 *
 * 该函数使用getopt_long解析命令行参数，支持长短两种选项格式，
 * 并将解析结果通过setOption函数应用到超级节点配置中。
 */
static int loadFromCLI(int argc, char *const argv[], n2n_sn_t *sss)
{
    u_char c; // 存储当前解析到的选项字符

    // 循环解析所有命令行参数
    while ((c = getopt_long(argc, argv,
                            /* 短选项字符串定义（带冒号表示需要参数）*/
                            "p:l:t:a:c:F:vhMV:" // 基础选项
#ifdef SN_MANUAL_MAC
                            "m:" // MAC地址设置（条件编译）
#endif
#if defined(N2N_HAVE_DAEMON)
                            "f" // 前台运行模式（条件编译）
#endif
#ifndef _WIN32
                            "u:g:" // 用户/组ID设置（非Windows）
#endif
                            ,
                            long_options,  // 长选项配置数组
                            NULL)) != '?') // 遇到未知选项返回'?'
    {
        // getopt_long返回255表示所有选项解析完成
        if (c == 255)
        {
            break;
        }

        /* 处理当前选项：
         * 1. 通过setOption应用配置
         * 2. 根据返回值调用help函数（当需要显示帮助时）*/
        help(setOption(c, optarg, sss));
    }

    return 0; // 始终返回0，实际错误通过help()处理
}
/* *************************************************** */

/* 将联盟添加到超级节点的社区列表中 */
/**
 * @brief 将联邦(federation)添加到社区(communities)哈希表中
 * @param sss 超级节点状态结构体指针
 * @return 始终返回0
 *
 * 该函数将联邦社区（如果存在）添加到全局社区哈希表中，
 * 用于集中管理所有社区信息。使用uthash库实现哈希表操作。
 */
static int add_federation_to_communities(n2n_sn_t *sss)
{
    uint32_t num_communities = 0; // 用于统计当前社区总数

    /* 检查联邦是否存在 */
    if (sss->federation != NULL)
    {
        /* 使用uthash宏将联邦添加到哈希表：
         * 参数说明：
         *   sss->communities - 目标哈希表
         *   community        - 哈希键字段名（社区结构体中的字段）
         *   sss->federation  - 要添加的结构体指针 */
        HASH_ADD_STR(sss->communities, community, sss->federation);

        /* 统计当前社区总数 */
        num_communities = HASH_COUNT(sss->communities);

        /* 记录日志：
         * TRACE_INFO级别 - 普通信息性日志
         * 格式：添加联邦社区[社区名]，当前总数[数量] */
        traceEvent(TRACE_INFO,
                   "added federation '%s' to the list of communities [total: %u]",
                   (char *)sss->federation->community, // 联邦社区名称
                   num_communities);                   // 当前社区总数
    }

    return 0; // 统一返回0表示成功（即使联邦不存在也视为成功）
}

/* *************************************************** */

#ifdef __linux__
/**
 * @brief 转储所有社区和边缘节点的注册信息
 * @param signo 信号编号（未使用，但符合信号处理函数原型）
 *
 * 该函数遍历超级节点维护的所有社区和边缘节点信息，
 * 以可读格式输出到日志系统。通常用于调试或响应管理命令。
 */
static void dump_registrations(int signo)
{
    // 定义迭代指针和临时变量
    struct sn_community *comm, *ctmp; // 社区哈希表迭代指针
    struct peer_info *list, *tmp;     // 边缘节点列表迭代指针
    char buf[32];                     // MAC地址格式化缓冲区
    time_t now = time(NULL);          // 获取当前时间戳
    u_int num = 0;                    // 边缘节点计数器

    // 输出分隔线
    traceEvent(TRACE_NORMAL, "====================================");

    /* 第一层遍历：所有社区 */
    HASH_ITER(hh, sss_node.communities, comm, ctmp)
    {
        // 输出当前社区名称
        traceEvent(TRACE_NORMAL, "dumping community: %s", comm->community);

        /* 第二层遍历：当前社区下的所有边缘节点 */
        HASH_ITER(hh, comm->edges, list, tmp)
        {
            // IPv4节点格式
            if (list->sock.family == AF_INET)
            {
                traceEvent(TRACE_NORMAL,
                           "[id: %u][MAC: %s][edge: %u.%u.%u.%u:%u][last seen: %u sec ago]",
                           ++num,                                        // 节点序号
                           macaddr_str(buf, list->mac_addr),             // MAC地址字符串
                           list->sock.addr.v4[0], list->sock.addr.v4[1], // IPv4地址分解输出
                           list->sock.addr.v4[2], list->sock.addr.v4[3],
                           list->sock.port,        // 端口号
                           now - list->last_seen); // 最后活跃时间差
            }
            // IPv6节点格式（简化输出）
            else
            {
                traceEvent(TRACE_NORMAL,
                           "[id: %u][MAC: %s][edge: IPv6:%u][last seen: %u sec ago]",
                           ++num,
                           macaddr_str(buf, list->mac_addr),
                           list->sock.port,
                           now - list->last_seen);
            }
        }
    }

    // 结束分隔线
    traceEvent(TRACE_NORMAL, "====================================");
}
#endif

/* *************************************************** */

/* 全局运行控制标志 */
static bool keep_running = true; // 控制主循环是否继续运行的标志位

/* 平台特定的终止信号处理程序
 * 支持Linux和Windows平台 */
#if defined(__linux__) || defined(_WIN32)
#ifdef _WIN32
/**
 * @brief Windows控制台事件处理函数
 * @param sig 接收到的控制事件代码
 * @return 总是返回TRUE表示已处理
 */
BOOL WINAPI term_handler(DWORD sig)
#else
/**
 * @brief Linux信号处理函数
 * @param sig 接收到的信号编号
 */
static void term_handler(int sig)
#endif
{
    static int called = 0; // 防止重复调用的静态标志

    /* 第一次调用时触发优雅关闭流程 */
    if (called)
    {
        // 第二次收到信号时强制退出
        traceEvent(TRACE_NORMAL, "ok, I am leaving now");
        _exit(0); // 立即终止进程
    }
    else
    {
        // 第一次收到终止信号
        traceEvent(TRACE_NORMAL, "shutting down...");
        called = 1; // 设置已调用标志
    }

    /* 设置全局运行标志为false
     * 让主循环可以自然退出 */
    keep_running = false;

#ifdef _WIN32
    return (TRUE); // Windows需要返回TRUE表示已处理
#endif
}
#endif /* defined(__linux__) || defined(_WIN32) */

/* *************************************************** */

/** 内核调用的主程序入口点 */
int main(int argc, char *const argv[])
{
    int rc; // 返回值变量
#ifndef _WIN32
    struct passwd *pw = NULL; // Linux用户信息结构
#endif
    struct peer_info *scan, *tmp; // 用于哈希表遍历的临时指针

    /* 初始化超级节点默认值 */
    sn_init_defaults(&sss_node);
    /* 将联邦社区添加到社区列表 */
    add_federation_to_communities(&sss_node);

    /* 参数处理逻辑 */
    if ((argc >= 2) && (argv[1][0] != '-'))
    {
        /* 情况1：第一个参数是配置文件路径 */
        rc = loadFromFile(argv[1], &sss_node);
        if (argc > 2)
        {
            /* 如果有额外参数，继续处理命令行参数 */
            rc = loadFromCLI(argc, argv, &sss_node);
        }
    }
    else if (argc > 1)
    {
        /* 情况2：只有命令行参数 */
        rc = loadFromCLI(argc, argv, &sss_node);
    }
    else
    {
        /* 情况3：无参数时的默认处理 */
#ifdef _WIN32
        // Windows下尝试加载当前目录的supernode.conf
        rc = loadFromFile("supernode.conf", &sss_node);
#else
        rc = -1; // 非Windows系统要求必须指定配置
#endif
    }

    /* 参数加载失败处理 */
    if (rc < 0)
    {
        help(1); /* 显示简短帮助信息 */
    }

    /* 加载允许的社区列表（如果有指定社区文件） */
    if (sss_node.community_file)
    {
        load_allowed_sn_community(&sss_node);
    }

#if defined(N2N_HAVE_DAEMON)
    /* 守护进程模式处理 */
    if (sss_node.daemon)
    {
        setUseSyslog(1); /* 将日志输出重定向到syslog */

        if (-1 == daemon(0, 0))
        { // 转换为守护进程
            traceEvent(TRACE_ERROR, "failed to become daemon");
            exit(-5);
        }
    }
#endif

    /* 安全检查警告 */
    if (!strcmp(sss_node.federation->community, FEDERATION_NAME))
    {
        traceEvent(TRACE_WARNING, "使用默认联邦名称；仅限测试使用，建议使用自定义联邦名称(-F)！");
    }

    if (sss_node.override_spoofing_protection)
    {
        traceEvent(TRACE_WARNING, "已禁用MAC和IP地址欺骗保护；仅限测试使用，建议使用用户密码认证(-I, -J, -P)！");
    }

    /* 计算共享密钥 */
    calculate_shared_secrets(&sss_node);

    traceEvent(TRACE_DEBUG, "当前跟踪级别: %d", getTraceLevel());

    /* 主UDP套接字初始化 */
    sss_node.sock = open_socket(sss_node.lport, sss_node.bind_address, 0 /* UDP */);
    if (-1 == sss_node.sock)
    {
        traceEvent(TRACE_ERROR, "无法打开主套接字: %s", strerror(errno));
        exit(-2);
    }
    else
    {
        traceEvent(TRACE_NORMAL, "超级节点正在监听UDP端口 %u (主端口)", sss_node.lport);
    }

#ifdef N2N_HAVE_TCP
    /* 辅助TCP套接字初始化 */
    sss_node.tcp_sock = open_socket(sss_node.lport, sss_node.bind_address, 1 /* TCP */);
    if (-1 == sss_node.tcp_sock)
    {
        traceEvent(TRACE_ERROR, "无法打开辅助TCP套接字: %s", strerror(errno));
        exit(-2);
    }
    else
    {
        traceEvent(TRACE_NORMAL, "超级节点已打开TCP端口 %u (辅助端口)", sss_node.lport);
    }

    /* 开始监听TCP连接 */
    if (-1 == listen(sss_node.tcp_sock, N2N_TCP_BACKLOG_QUEUE_SIZE))
    {
        traceEvent(TRACE_ERROR, "无法在辅助TCP套接字上监听: %s", strerror(errno));
        exit(-2);
    }
    else
    {
        traceEvent(TRACE_NORMAL, "超级节点正在监听TCP端口 %u (辅助端口)", sss_node.lport);
    }
#endif

    /* 管理套接字初始化 */
    sss_node.mgmt_sock = open_socket(sss_node.mport, INADDR_LOOPBACK, 0 /* UDP */);
    if (-1 == sss_node.mgmt_sock)
    {
        traceEvent(TRACE_ERROR, "无法打开管理套接字: %s", strerror(errno));
        exit(-2);
    }
    else
    {
        traceEvent(TRACE_NORMAL, "超级节点正在监听UDP端口 %u (管理端口)", sss_node.mport);
    }

    /* 初始化联邦中所有边缘节点的套接字描述符 */
    HASH_ITER(hh, sss_node.federation->edges, scan, tmp)
    {
        scan->socket_fd = sss_node.sock;
    }

#ifndef _WIN32
    /* Linux权限降级处理 */
    /*
     * 如果命令行未指定uid/gid，则尝试使用"n2n"或"nobody"用户的uid/gid
     */
    if (((pw = getpwnam("n2n")) != NULL) || ((pw = getpwnam("nobody")) != NULL))
    {
        /*
         * 如果uid/gid未通过CLI设置，则从getpwnam获取
         * 否则重置为0
         */
        sss_node.userid = (sss_node.userid == 0) ? pw->pw_uid : 0;
        sss_node.groupid = (sss_node.groupid == 0) ? pw->pw_gid : 0;
    }

    /* 如果请求了非零的uid/gid，尝试切换到该用户/组 */
    if ((sss_node.userid != 0) || (sss_node.groupid != 0))
    {
        traceEvent(TRACE_NORMAL, "正在降低权限到uid=%d, gid=%d",
                   (signed int)sss_node.userid, (signed int)sss_node.groupid);

        /* 完成需要root权限的操作，降级到非特权用户 */
        if ((setgid(sss_node.groupid) != 0) || (setuid(sss_node.userid) != 0))
        {
            traceEvent(TRACE_ERROR, "无法降低权限 [%u/%s]", errno, strerror(errno));
        }
    }

    /* 安全检查：警告以root身份运行 */
    if ((getuid() == 0) || (getgid() == 0))
    {
        traceEvent(TRACE_WARNING, "不建议以root身份运行，请考虑使用-u/-g选项");
    }
#endif

    /* 初始化超级节点 */
    sn_init(&sss_node);
    traceEvent(TRACE_NORMAL, "超级节点已启动");

    /* 信号处理设置 */
#ifdef __linux__
    signal(SIGPIPE, SIG_IGN);           // 忽略管道破裂信号
    signal(SIGTERM, term_handler);      // 终止信号处理
    signal(SIGINT, term_handler);       // Ctrl+C处理
    signal(SIGHUP, dump_registrations); // 挂起信号用于转储注册信息
#endif
#ifdef _WIN32
    SetConsoleCtrlHandler(term_handler, TRUE); // Windows控制台事件处理
#endif

    /* 设置运行控制标志并进入主循环 */
    sss_node.keep_running = &keep_running;
    return run_sn_loop(&sss_node); // 进入主事件循环
}