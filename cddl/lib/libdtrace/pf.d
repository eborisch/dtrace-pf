#pragma D depends_on module pf

enum    { AF_UNIX = 1, AF_INET = 2, AF_INET6 = 28 };
enum    { PF_INOUT, PF_IN, PF_OUT };
enum    { PF_PASS, PF_DROP, PF_SCRUB, PF_NOSCRUB, PF_NAT, PF_NONAT,
          PF_BINAT, PF_NOBINAT, PF_RDR, PF_NORDR, PF_SYNPROXY_DROP, PF_DEFER };
enum    { PF_RULESET_SCRUB, PF_RULESET_FILTER, PF_RULESET_NAT,
          PF_RULESET_BINAT, PF_RULESET_RDR, PF_RULESET_MAX };
enum    { PF_OP_NONE, PF_OP_IRG, PF_OP_EQ, PF_OP_NE, PF_OP_LT,
          PF_OP_LE, PF_OP_GT, PF_OP_GE, PF_OP_XRG, PF_OP_RRG };
enum    { PF_DEBUG_NONE, PF_DEBUG_URGENT, PF_DEBUG_MISC, PF_DEBUG_NOISY };
enum    { PF_CHANGE_NONE, PF_CHANGE_ADD_HEAD, PF_CHANGE_ADD_TAIL,
          PF_CHANGE_ADD_BEFORE, PF_CHANGE_ADD_AFTER,
          PF_CHANGE_REMOVE, PF_CHANGE_GET_TICKET };
enum    { PF_GET_NONE, PF_GET_CLR_CNTR };
enum    { PF_SK_WIRE, PF_SK_STACK, PF_SK_BOTH };

enum { PFTM_TCP_FIRST_PACKET, PFTM_TCP_OPENING, PFTM_TCP_ESTABLISHED,
       PFTM_TCP_CLOSING, PFTM_TCP_FIN_WAIT, PFTM_TCP_CLOSED,
       PFTM_UDP_FIRST_PACKET, PFTM_UDP_SINGLE, PFTM_UDP_MULTIPLE,
       PFTM_ICMP_FIRST_PACKET, PFTM_ICMP_ERROR_REPLY,
       PFTM_OTHER_FIRST_PACKET, PFTM_OTHER_SINGLE,
       PFTM_OTHER_MULTIPLE, PFTM_FRAG, PFTM_INTERVAL,
       PFTM_ADAPTIVE_START, PFTM_ADAPTIVE_END, PFTM_SRC_NODE,
       PFTM_TS_DIFF, PFTM_MAX, PFTM_PURGE, PFTM_UNLINKED,
       PFTM_UNTIL_PACKET };

enum { src_idx = 1, dst_idx = 0 };

/* This is a simplified pf_state structure. It accounts for direction and
** translation (NAT/RDR) and it generally makes things a lot easier to figure
** out. See pfvarh.h for additional info on the sub structures.
*/
typedef struct pfstate {
    uint64_t id;                        /* connection id                     */
    uint32_t protocol;                  /* protocol                          */
    string direction;                   /* direction -- '<' (in) : '>' (out) */
    struct pf_state_peer src;           /* src pf_state_peer                 */
    struct pf_state_peer dst;           /* dst pf_state_peer                 */
    struct pf_state_key *src_key;       /* src pf_state_key                  */
    struct pf_state_key *trans_src_key; /* translated raw src pf_state_key   */
    struct pf_state_key *dst_key;       /* dst pf_state_key                  */
    struct pf_state_key *trans_dst_key; /* translated dst pf_state_key       */
    string src_ip;                      /* source ip, as a string            */
    string trans_src_ip;                /* translated source ip, as a string */
    uint16_t src_port;                  /* source port                       */
    uint16_t trans_src_port;            /* translated source port            */
    string dst_ip;                      /* dest ip, as a string              */
    string trans_dst_ip;                /* dest ip, as a string              */
    uint16_t dst_port;                  /* translated dest port              */
    uint16_t trans_dst_port;            /* source port                       */
    struct pf_state *rec;               /* raw pf_state record               */
} pfstate_t;

#pragma D binding "1.0" translator
translator pfstate_t < struct pf_state *s > {
    id            = s->id;
    protocol      = s->key[PF_SK_STACK]->proto;
    direction     = s->direction == PF_OUT ? ">" : "<";
    src           = s->direction == PF_OUT ? s->src : s->dst;
    dst           = s->direction == PF_OUT ? s->dst : s->src;
    src_key       = s->direction == PF_OUT ? s->key[PF_SK_STACK] : s->key[PF_SK_WIRE];
    trans_src_key = s->direction == PF_OUT ? s->key[PF_SK_WIRE]  : s->key[PF_SK_WIRE];
    dst_key       = s->key[PF_SK_WIRE];

    src_ip = s->direction == PF_OUT ?
             s->key[PF_SK_STACK]->af == AF_INET ?
             inet_ntoa(&(s->key[PF_SK_STACK]->addr[src_idx].pfa.v4.s_addr)) :
             inet_ntoa6(&(s->key[PF_SK_STACK]->addr[src_idx].pfa.v6))
             :
             s->key[PF_SK_WIRE]->af == AF_INET ?
             inet_ntoa(&(s->key[PF_SK_WIRE]->addr[src_idx].pfa.v4.s_addr)) :
             inet_ntoa6(&(s->key[PF_SK_WIRE]->addr[src_idx].pfa.v6));

    trans_src_ip = s->direction == PF_OUT ?
             s->key[PF_SK_WIRE]->af == AF_INET ?
             inet_ntoa(&(s->key[PF_SK_WIRE]->addr[src_idx].pfa.v4.s_addr)) :
             inet_ntoa6(&(s->key[PF_SK_WIRE]->addr[src_idx].pfa.v6))
             :
             s->key[PF_SK_STACK]->af == AF_INET ?
             inet_ntoa(&(s->key[PF_SK_STACK]->addr[src_idx].pfa.v4.s_addr)) :
             inet_ntoa6(&(s->key[PF_SK_STACK]->addr[src_idx].pfa.v6));
    
    src_port = s->direction == PF_OUT ?
             ntohs(s->key[PF_SK_STACK]->port[src_idx]) :
             ntohs(s->key[PF_SK_WIRE]->port[src_idx]);

    trans_src_port = s->direction == PF_OUT ?
             ntohs(s->key[PF_SK_WIRE]->port[src_idx]) :
             ntohs(s->key[PF_SK_STACK]->port[src_idx]);
    
    dst_ip = s->direction == PF_OUT ?
             s->key[PF_SK_WIRE]->af == AF_INET ?
             inet_ntoa(&(s->key[PF_SK_WIRE]->addr[dst_idx].pfa.v4.s_addr)) :
             inet_ntoa6(&(s->key[PF_SK_WIRE]->addr[dst_idx].pfa.v6))
             :
             s->key[PF_SK_STACK]->af == AF_INET ?
             inet_ntoa(&(s->key[PF_SK_STACK]->addr[dst_idx].pfa.v4.s_addr)) :
             inet_ntoa6(&(s->key[PF_SK_STACK]->addr[dst_idx].pfa.v6));

    trans_dst_ip = s->direction == PF_OUT ?
             s->key[PF_SK_STACK]->af == AF_INET ?
             inet_ntoa(&(s->key[PF_SK_STACK]->addr[dst_idx].pfa.v4.s_addr)) :
             inet_ntoa6(&(s->key[PF_SK_STACK]->addr[dst_idx].pfa.v6))
             :
             s->key[PF_SK_WIRE]->af == AF_INET ?
             inet_ntoa(&(s->key[PF_SK_WIRE]->addr[dst_idx].pfa.v4.s_addr)) :
             inet_ntoa6(&(s->key[PF_SK_WIRE]->addr[dst_idx].pfa.v6));
    
    dst_port = s->direction == PF_OUT ?
             ntohs(s->key[PF_SK_WIRE]->port[dst_idx]) :
             ntohs(s->key[PF_SK_STACK]->port[dst_idx]);
    
    trans_dst_port = s->direction == PF_OUT ?
             ntohs(s->key[PF_SK_STACK]->port[dst_idx]) :
             ntohs(s->key[PF_SK_WIRE]->port[dst_idx]);

    rec = s;
};
