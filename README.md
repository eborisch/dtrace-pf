# About

The master branch is the /usr/src directory (-r274417) on FreeBSD 10. The
pftrace branch contains the pf dtrace provider.

# Usage

With the provider compiled, you can create DTrace scripts to watch for state
create and destroy events like the following:

```
enum { src_ip = 1, dst_ip = 0 };

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

pf*:::state-destroy
{
    state = args[0];
    printf("pf:::state-destroy(%u)", state->id);
}
```
