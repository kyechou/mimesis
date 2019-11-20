#include <LB_algo.h>

class RoundRobin : public LB_algo
{
private:
	int cur_iter;
public:
	RoundRobin();

	Addrs select_cli();
	int get_cur_iter();
	void set_cli_addrs(Addrs* cli_list);
}
