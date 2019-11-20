#include <LB_algo.h>

class LeastConn : public LB_algo
{
private:
	int* cli_conn;
	int** cli_pids;
public:
	LeastConn();

	struct addrs select_cli();
	void set_cli_conn(int pid, struct addrs ad);
	void set_cli_addrs(struct addrs* cli_list);
	void reduce_conn(int pid);
}
