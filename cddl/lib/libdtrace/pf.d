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

typedef struct pfstate {
    uint64_t id;              /* protocol */
    uint32_t protocol;        /* protocol */
    string direction;         /* direction  */
    struct pf_state_peer src; /* raw src pf_state_peer */
    struct pf_state_peer dst; /* raw dst pf_state_peer */
    struct pf_state_key *src_key; /* raw src pf_state_key */
    struct pf_state_key *dst_key; /* raw dst pf_state_key */
    string src_ip;            /* source address, as a string */
    string dst_ip;            /* dest address, as a string */
    struct pf_state *rec;     /* raw pf_state record */
} pfstate_t;

#pragma D binding "1.0" translator
translator pfstate_t < struct pf_state *s > {
    id        = s->id;
    protocol  = s->key[PF_SK_STACK]->proto;
    direction = s->direction == PF_IN ? "<-" : "->";
    src       = s->src;
    dst       = s->dst;
    src_key   = s->key[PF_SK_STACK];
    dst_key   = s->key[PF_SK_WIRE];
    src_ip    = s->key[PF_SK_STACK]->af == AF_INET ?
        inet_ntoa(&(s->key[PF_SK_STACK]->addr[src_idx].pfa.v4.s_addr)) :
        inet_ntoa6(&(s->key[PF_SK_STACK]->addr[src_idx].pfa.v6));
    dst_ip    = s->key[PF_SK_WIRE]->af == AF_INET ?
        inet_ntoa(&(s->key[PF_SK_WIRE]->addr[dst_idx].pfa.v4.s_addr)) :
        inet_ntoa6(&(s->key[PF_SK_WIRE]->addr[dst_idx].pfa.v6));
    rec       = s;
};
