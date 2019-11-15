#include <RoundRobin.h>

RoundRobin::RoundRobin()
{
	cli_addrs = new struct addrs[20];
	cur_iter = 0;
}

struct addrs RoundRobin::select_server()
{
	return cli_addrs[cur_iter++];
}

int RoundRobin::get_cur_iter()
{
	return cur_iter;
}

void RoundRobin::set_cli_addrs(struct addrs* cli_list)
{
	cli_addrs = cli_list;
}
