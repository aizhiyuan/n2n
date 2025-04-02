/**
 * (C) 2007-22 - ntop.org 和贡献者
 *
 * 本程序是自由软件；您可以在自由软件基金会发布的GNU通用公共许可证的条款下重新分发和/或修改它；
 * 许可证的版本为第3版，或者（根据您的选择）任何更高版本。
 *
 * 本程序分发是为了希望它有用，但不附带任何保证；
 * 甚至不包括对适销性或特定用途适用性的隐含保证。有关详细信息，请参阅GNU通用公共许可证。
 *
 * 您应该已经收到了GNU通用公共许可证的副本；
 * 如果没有，请查看 <http://www.gnu.org/licenses/>
 */

#include <stdint.h>          // 引入用于 UINT64_MAX、uint32_t、int64_t、uint64_t 的头文件
#include <stdio.h>           // 引入用于 snprintf、NULL 等的头文件
#include <string.h>          // 引入用于 memcpy、memset 等的头文件
#include "n2n.h"             // 引入自定义的 n2n 头文件，包含 peer_info_t、n2n_edge_t、SN_SELECTION_CRIT 等定义
#include "portable_endian.h" // 引入字节序转换函数，如 be32toh、be64toh、htobe64
#include "sn_selection.h"    // 引入选择标准相关定义，如 selection_criterion_str_t、sn_selection_cr 等
#include "uthash.h"          // 引入 uthash 库，用于处理哈希表

// 函数声明
static SN_SELECTION_CRITERION_DATA_TYPE sn_selection_criterion_common_read(n2n_edge_t *eee);
static int sn_selection_criterion_sort(peer_info_t *a, peer_info_t *b);

/* 初始化 peer_info 结构体中的 selection_criterion 字段 */
int sn_selection_criterion_init(peer_info_t *peer)
{

    if (peer != NULL)
    {
        sn_selection_criterion_default(&(peer->selection_criterion)); // 设置默认值
    }

    return 0; /* 成功 */
}

/* 根据选定的策略将 selection_criterion 字段设置为默认值 */
int sn_selection_criterion_default(SN_SELECTION_CRITERION_DATA_TYPE *selection_criterion)
{

    *selection_criterion = (SN_SELECTION_CRITERION_DATA_TYPE)(UINT64_MAX >> 1) - 1; // 设置默认值为 UINT64_MAX 的一半减去 1

    return 0; /* 成功 */
}

/* 将 selection_criterion 字段设置为“坏”值（比默认值差），根据选定的策略 */
int sn_selection_criterion_bad(SN_SELECTION_CRITERION_DATA_TYPE *selection_criterion)
{

    *selection_criterion = (SN_SELECTION_CRITERION_DATA_TYPE)(UINT64_MAX >> 1); // 设置为较差的值

    return 0; /* 成功 */
}

/* 将 selection_criterion 字段设置为“好”值（比默认值好），根据选定的策略 */
int sn_selection_criterion_good(SN_SELECTION_CRITERION_DATA_TYPE *selection_criterion)
{

    *selection_criterion = (SN_SELECTION_CRITERION_DATA_TYPE)(UINT64_MAX >> 1) - 2; // 设置为较好的值

    return 0; /* 成功 */
}

/* 从 PEER_INFO 载荷中获取数据并将其转换为 selection_criterion。
 * 该函数高度依赖于所选的选择标准策略。
 */
int sn_selection_criterion_calculate(n2n_edge_t *eee, peer_info_t *peer, SN_SELECTION_CRITERION_DATA_TYPE *data)
{

    SN_SELECTION_CRITERION_DATA_TYPE common_data;
    int sum = 0;

    common_data = sn_selection_criterion_common_read(eee); // 获取公共的 selection_criterion 数据

    switch (eee->conf.sn_selection_strategy)
    {

    case SN_SELECTION_STRATEGY_LOAD:
    {
        peer->selection_criterion = (SN_SELECTION_CRITERION_DATA_TYPE)(be32toh(*data) + common_data); // 加载策略，计算选择标准

        // 为了减少超节点负载的波动，采取了“粘性因子”的缓解措施
        if (peer == eee->curr_sn)
        {
            sum = HASH_COUNT(eee->known_peers) + HASH_COUNT(eee->pending_peers);     // 计算已知和待定的 peer 数量
            peer->selection_criterion = peer->selection_criterion * sum / (sum + 1); // 动态计算粘性因子
        }
        break;
    }

    case SN_SELECTION_STRATEGY_RTT:
    {
        peer->selection_criterion = (SN_SELECTION_CRITERION_DATA_TYPE)((uint32_t)time_stamp() >> 22) - common_data; // RTT 策略
        break;
    }

    case SN_SELECTION_STRATEGY_MAC:
    {
        peer->selection_criterion = 0;
        memcpy(&peer->selection_criterion, peer->mac_addr, N2N_MAC_SIZE);                     // 根据 MAC 地址计算选择标准
        peer->selection_criterion = be64toh(peer->selection_criterion);                       // 转换为主机字节序
        peer->selection_criterion >>= (sizeof(peer->selection_criterion) - N2N_MAC_SIZE) * 8; // 右移以保持有效的选择标准
        break;
    }

    default:
    {
        // 不应该发生此情况
        traceEvent(TRACE_ERROR, "selection_criterion unknown selection strategy configuration");
        break;
    }
    }

    return 0; /* 成功 */
}

/* 将 sn_selection_criterion_common_data 字段设置为默认值。 */
int sn_selection_criterion_common_data_default(n2n_edge_t *eee)
{

    switch (eee->conf.sn_selection_strategy)
    {

    case SN_SELECTION_STRATEGY_LOAD:
    {
        SN_SELECTION_CRITERION_DATA_TYPE tmp = 0;

        tmp = HASH_COUNT(eee->pending_peers); // 获取待处理的 peer 数量
        if (eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED)
        {
            tmp *= 2; // 如果启用了头部加密，则加倍计算
        }
        eee->sn_selection_criterion_common_data = tmp / HASH_COUNT(eee->conf.supernodes); // 根据超节点数计算公共数据
        break;
    }

    case SN_SELECTION_STRATEGY_RTT:
    {
        eee->sn_selection_criterion_common_data = (SN_SELECTION_CRITERION_DATA_TYPE)((uint32_t)time_stamp() >> 22); // RTT 策略的公共数据
        break;
    }

    case SN_SELECTION_STRATEGY_MAC:
    {
        eee->sn_selection_criterion_common_data = 0; // MAC 策略的公共数据
        break;
    }

    default:
    {
        // 不应该发生此情况
        traceEvent(TRACE_ERROR, "selection_criterion unknown selection strategy configuration");
        break;
    }
    }

    return 0; /* 成功 */
}

/* 返回 sn_selection_criterion_common_data 字段的值。 */
static SN_SELECTION_CRITERION_DATA_TYPE sn_selection_criterion_common_read(n2n_edge_t *eee)
{

    return eee->sn_selection_criterion_common_data; // 返回公共数据
}

/* 比较两个 selection_criterion 字段，并按升序对它们进行排序 */
static int sn_selection_criterion_sort(peer_info_t *a, peer_info_t *b)
{

    int ret = 0;

    // 排序函数，按 selection_criterion 升序排序超节点
    if (a->selection_criterion > b->selection_criterion)
        ret = 1;
    else if (a->selection_criterion < b->selection_criterion)
        ret = -1;

    return ret;
}

/* 使用 sn_selection_criterion_sort 函数对 peer_list 进行排序 */
int sn_selection_sort(peer_info_t **peer_list)
{

    HASH_SORT(*peer_list, sn_selection_criterion_sort); // 使用哈希排序

    return 0; /* 成功 */
}

/* 收集超节点相关的数据。
 * 该函数与选择策略无关，因为它仅涉及边缘行为。
 */
SN_SELECTION_CRITERION_DATA_TYPE sn_selection_criterion_gather_data(n2n_sn_t *sss)
{

    SN_SELECTION_CRITERION_DATA_TYPE data = 0, tmp = 0;
    struct sn_community *comm, *tmp_comm;

    // 遍历超节点社区中的每个社区
    HASH_ITER(hh, sss->communities, comm, tmp_comm)
    {
        tmp = HASH_COUNT(comm->edges) + 1; // 计算社区中的节点数，包括社区本身
        if (comm->header_encryption == HEADER_ENCRYPTION_ENABLED)
        {
            tmp *= 2; // 如果启用了头部加密，则双倍计算
        }
        data += tmp; // 累加数据
    }

    return htobe64(data); // 返回处理后的数据
}

/* 将 selection_criterion 字段转换为字符串，以便管理端口输出 */
extern char *sn_selection_criterion_str(n2n_edge_t *eee, selection_criterion_str_t out, peer_info_t *peer)
{

    int chars = 0;

    if (NULL == out)
    {
        return NULL;
    }
    memset(out, 0, SN_SELECTION_CRITERION_BUF_SIZE); // 清空输出缓冲区

    // 跳过超大的值（用于“坏”、“好”或“未确定”的超节点，方便排序到列表的末尾）
    // 或者将其强制类型转换为 (int16_t) 并检查是否大于或等于零
    if (peer->selection_criterion < (UINT64_MAX >> 2))
    {

        switch (eee->conf.sn_selection_strategy)
        {

        case SN_SELECTION_STRATEGY_LOAD:
        {
            chars = snprintf(out, SN_SELECTION_CRITERION_BUF_SIZE, "load = %8ld", peer->selection_criterion); // 输出加载策略的选择标准
            break;
        }

        case SN_SELECTION_STRATEGY_RTT:
        {
            chars = snprintf(out, SN_SELECTION_CRITERION_BUF_SIZE, "rtt = %6ld ms", peer->selection_criterion); // 输出 RTT 策略的选择标准
            break;
        }

        case SN_SELECTION_STRATEGY_MAC:
        {
            chars = snprintf(out, SN_SELECTION_CRITERION_BUF_SIZE, "%s", ((int64_t)peer->selection_criterion > 0 ? ((peer == eee->curr_sn) ? "active" : "standby") : "")); // 输出 MAC 策略的选择标准
            break;
        }

        default:
        {
            // 不应该发生此情况
            traceEvent(TRACE_ERROR, "selection_criterion unknown selection strategy configuration");
            break;
        }
        }

        // 检查是否发生格式溢出
        if (chars > SN_SELECTION_CRITERION_BUF_SIZE)
        {
            traceEvent(TRACE_ERROR, "selection_criterion buffer overflow");
        }
    }

    return out; // 返回转换后的字符串
}
