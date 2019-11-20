#include <RoundRobin.h>
#include <array>

RoundRobin::RoundRobin()
{
	cli_addrs = new struct addrs[20];
	cur_iter = 0;
}

struct addrs RoundRobin::select_cli()
{
	if cur_iter == cli_addrs.size(){
		cur_iter = 0;
		return cli_addrs[0];
	}
	else
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
