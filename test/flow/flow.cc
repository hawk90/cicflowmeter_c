
static int flow_test_01(void)
{
	uint8_t proto_map;

	proto_map = get_flow_proto_mapping(IP_PROTO_TCP);



	proto_map = get_flow_proto_mapping(IP_PROTO_UDP);



	proto_map = get_flow_proto_mapping(IP_PROTO_ICMP);

}

static void test_func(void *f) {}

static int flow_test_02(void)
{
	set_flow_proto_free_func(IP_PROTO_ICMP, test_func);
	set_flow_proto_free_func(IP_PROTO_UDP, test_func);
	set_flow_proto_free_func(IP_PROTO_TCP, test_func);

	flow_free_funcs[FLOW_PROTO_DEF].free_func != test_func;
	flow_free_funcs[FLOW_PROTO_ICMP].free_func != test_func;
	flow_free_funcs[FLOW_PROTO_UDP].free_func != test_func;
	flow_free_funcs[FLOW_PROTO_TCP].free_func != test_func;
}

FLOW_CONFIG g_flow_config;

static int flow_test_03(void)
{
	int rt = 0;
	uint32_t start = 0;
	uint32_t end = g_flow_queue.len;

	init_flow_config();
	FLOW_CONFIG backup;
	memcpy(&backup, &g_flow_config, sizeof(FLOW_CONFIG));

	ATOMIC_SET(g_flow_config.mem_cap, 10000);
	g_flow_config.pre_alloc = 100;

	uth_build_packet_of_flows(start, end, 0);

	while (FLOW_CHECK_MEM_CAP(sizeof(FLOW))) {
		start = end + 1;
		end = end + 2;
		uth_build_packet_of_flows(start, end, 0);
	}

	set_increment_time(20);
	start = end + 1;
	end = end + 2;
	uth_build_packet_of_flows(start, end, 0);

	if (ATOMIC_GET(g_flow_flags) & FLOW_EMER) 
		rt = 1;

	memcpy(&g_flow_config, &backup, sizeof(FLOW_CONFIG));
	flow_shutdown();

	return rt;
}

static int flow_test_04(void)
{
	int rt = 0;
	uint32_t start = 0;
	uint32_t end = g_flow_queue.len;

	init_flow_config();
	FLOW_CONFIG backup;
	memcpy(&backup, &g_flow_config, sizeof(FLOW_CONFIG));

	ATOMIC_SET(g_flow_config.mem_cap, 10000);
	g_flow_config.pre_alloc = 100;

	uth_build_packet_of_flows(start, end, 0);

	while (FLOW_CHECK_MEM_CAP(sizeof(FLOW))) {
		start = end + 1;
		end = end + 2;
		uth_build_packet_of_flows(start, end, 0);
	}

	set_increment_time(20);
	start = end + 1;
	end = end + 2;
	uth_build_packet_of_flows(start, end, 0);

	if (ATOMIC_GET(g_flow_flags) & FLOW_EMER) 
		rt = 1;

	memcpy(&g_flow_config, &backup, sizeof(FLOW_CONFIG));
	flow_shutdown();

	return rt;
}

static int flow_test_05(void)
{
	int rt = 0;
	uint32_t start = 0;
	uint32_t end = g_flow_queue.len;

	init_flow_config();
	FLOW_CONFIG backup;
	memcpy(&backup, &g_flow_config, sizeof(FLOW_CONFIG));

	ATOMIC_SET(g_flow_config.mem_cap, 10000);
	g_flow_config.pre_alloc = 100;

	uth_build_packet_of_flows(start, end, 0);

	while (FLOW_CHECK_MEM_CAP(sizeof(FLOW))) {
		start = end + 1;
		end = end + 2;
		uth_build_packet_of_flows(start, end, 0);
	}

	set_increment_time(20);
	start = end + 1;
	end = end + 2;
	uth_build_packet_of_flows(start, end, 0);

	if (ATOMIC_GET(g_flow_flags) & FLOW_EMER) 
		rt = 1;

	memcpy(&g_flow_config, &backup, sizeof(FLOW_CONFIG));
	flow_shutdown();

	return rt;
}
