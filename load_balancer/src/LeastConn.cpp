#include <LeastConn.h>
#include <array>

LeastConn::LeastConn()
{
	cli_addrs = new struct addrs[20];
	cli_conn = new int[20];
	cli_pids = new int*[20];
}

struct addrs LeastConn::select_cli()
{
	int num=0;
	for(int i=0;i<cli_addrs.size();i++){
		if(cli_conn[i]<cli_conn[num]) num = i;
	}
	return cli_addrs[num];
}

void LeastConn::set_cli_conn(int pid, struct addrs ad)
{
	int num = 0;
	for(int i=0; i<cli_addrs.size();i++){
		if(cli_addrs[i] == cli_addrs[num]){
			num = i;
			break;
		}
	}
	cli_conn[num]++;
	cli_pids[num][cli_conn[num]] = pid;
}

void LeastConn::set_cli_addrs(struct addrs* cli_list)
{
	cli_addrs = cli_list;
	cli_conn = new int[cli_addrs.size()];
	cli_pids = new int*[cli_addrs.size()];
	for(int i=0;i<cli_addrs.size();i++){
		cli_conn[i] = 0;
		cli_pids[i] = new int[20];
	}
}

void LeastConn::reduce_conn(int pid)
{
	int num = 0;
	bool bb = false;
	for(int i=0;i<cli_addrs.size();i++){
		if(bb) break;
		for(int j=0;j<cli_pids[i].size();j++){
			if(bb) cli_pids[i][j-1] = cli_pids[i][j];
			if(cli_pids[i][j]==pid){
				num = i;
				bb = true;
			}
		}
	}
	
	cli_conn[num]--;
}
