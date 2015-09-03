# About

This is a prototype for a pf DTrace provider for FreeBSD.

The master branch is the /usr/src directory (-r274417) on FreeBSD 10. The
pftrace branch contains the pf dtrace provider.

# Usage

With this provider you can use DTrace to watch for pf state changes, general TCP
establish/close events, and raw state create/destroy events. The following
script covers illustrates basic use:

```
/* When both peers are established */
pf*:::state-change
/ args[0]->src.state == TCPS_ESTABLISHED && args[0]->dst.state == TCPS_ESTABLISHED /
{
    s = *args[0];
    printf( "pf:::state-change:established(%u) %s %s %s",
            s.id,
            s.src_ip,
            s.direction,
            s.dst_ip );
}

/* When both peers disconect */
pf*:::state-change
/ args[0]->src.state == TCPS_FIN_WAIT_2 && args[0]->dst.state == TCPS_FIN_WAIT_2 /
{
    s = *args[0];
    printf( "pf:::state-change:finwait2(%u) %s %s %s",
            s.id,
            s.src_ip,
            s.direction,
            s.dst_ip );
}

/* Generic event of peer connections established */
pf*:::tcp-established
{
    s = *args[0];
    printf( "pf:::state:tcp-established(%u) %s %s %s",
            s.id,
            s.src_ip,
            s.direction,
            s.dst_ip );
}

/* Generic event of peer connections closed */
pf*:::tcp-closed
{
    s = *args[0];
    printf( "pf:::state:tcp-closed(%u) %s %s %s",
            s.id,
            s.src_ip,
            s.direction,
            s.dst_ip );
}

/* When a new pf state is created */
pf*:::state-create
{
    state = args[0];
    src = args[0]->key[PF_SK_STACK];
    dst = args[0]->key[PF_SK_WIRE];

    proto_num  = src->proto;
    proto_name = protocols[proto_num];

    direction = state->direction == PF_IN ? "<-" : "->";
    
	saddr = src->af == AF_INET ?
	    inet_ntoa(&(src->addr[src_ip].pfa.v4.s_addr)) :
	    inet_ntoa6(&(src->addr[src_ip].pfa.v6));

    daddr = src->af == AF_INET ?
	    inet_ntoa(&(src->addr[dst_ip].pfa.v4.s_addr)) :
	    inet_ntoa6(&(src->addr[dst_ip].pfa.v6));
    
    printf( "pf:::state:create(%u) %s %i %s %s %s",
            state->id,
            proto_name,
            proto_num,
            saddr, direction, daddr );
}

/* When a pf state is destoyed */
pf*:::state-destroy
{
    state = args[0];
    printf("pf:::state-destroy(%u)", state->id);
}

```
