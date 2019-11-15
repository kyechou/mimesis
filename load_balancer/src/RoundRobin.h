#include <LB_algo.h>

class RoundRobin : public LB_algo
{
private:
	int cur_iter;
public:
	RoundRobin();

	struct addrs select_server();
	int get_cur_iter();
	void set_cli_addrs(struct addrs* cli_list);
}
