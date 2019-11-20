#include <string.h>

struct Addrs{
	char* ip;
	int port;

	inline bool operator==(const addrs& ad1, const addrs& ad2)
	{
		return strcmp(ad1.ip, ad2.ip) && ad1.port==ad2.port;
	}
	inline bool operator!=(const addrs& ad1, const addrs& ad2){ return !(ad1==ad2); }
}

class LB_algo
{
private:
	Addrs* cli_addrs;
public:
	LB_algo();
	Addrs select_srv();
	void set_srv_addrs(Addrs* srv_list);
}
