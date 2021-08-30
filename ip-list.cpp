#include <HalonMTA.h>
#include <string>
#include <cstring>
#include <shared_mutex>
#include <fstream>
#include <map>
#include <lpm.h>
#include <syslog.h>

void list_open(const std::string& id, const std::string& path);
bool list_lookup(const std::string& id, const std::string& address, std::string& tag);
void list_reload(const std::string& id);

HALON_EXPORT
int Halon_version()
{
	return HALONMTA_PLUGIN_VERSION;
}

HALON_EXPORT
bool Halon_init(HalonInitContext* hic)
{
	HalonConfig* cfg;
	HalonMTA_init_getinfo(hic, HALONMTA_INIT_CONFIG, nullptr, 0, &cfg, nullptr);

	try {
		auto lists = HalonMTA_config_object_get(cfg, "lists");
		if (lists)
		{
			size_t l = 0;
			HalonConfig* list;
			while ((list = HalonMTA_config_array_get(lists, l++)))
			{
				const char* id = HalonMTA_config_string_get(HalonMTA_config_object_get(list, "id"), nullptr);
				const char* path = HalonMTA_config_string_get(HalonMTA_config_object_get(list, "path"), nullptr);
				if (!id || !path)
					continue;
				list_open(id, path);
			}
		}
		return true;
	} catch (const std::runtime_error& e) {
		syslog(LOG_CRIT, "%s", e.what());
		return false;
	}
}

HALON_EXPORT
bool Halon_plugin_command(const char* in, size_t len, char** out, size_t* olen)
{
	if (strncmp(in, "reload:", 7) == 0)
	{
		try {
			list_reload(in + 7);
			*out = strdup("OK");
			return true;
		} catch (const std::runtime_error& e) {
			*out = strdup(e.what());
			return false;
		}
	}
	*out = strdup("Unknown command");
	return false;
}

HALON_EXPORT
void ip_list_lookup(HalonHSLContext* hhc, HalonHSLArguments* args, HalonHSLValue* ret)
{
	HalonHSLValue* x;
	char* id = nullptr;
	char* address = nullptr;

	x = HalonMTA_hsl_argument_get(args, 0);
	if (x && HalonMTA_hsl_value_type(x) == HALONMTA_HSL_TYPE_STRING)
		HalonMTA_hsl_value_get(x, HALONMTA_HSL_TYPE_STRING, &id, nullptr);
	else
		return;

	x = HalonMTA_hsl_argument_get(args, 1);
	if (x && HalonMTA_hsl_value_type(x) == HALONMTA_HSL_TYPE_STRING)
		HalonMTA_hsl_value_get(x, HALONMTA_HSL_TYPE_STRING, &address, nullptr);
	else
		return;

	try {
		std::string tag;
		bool t = list_lookup(id, address, tag);
		if (!t || tag.empty())
			HalonMTA_hsl_value_set(ret, HALONMTA_HSL_TYPE_BOOLEAN, &t, 0);
		else
			HalonMTA_hsl_value_set(ret, HALONMTA_HSL_TYPE_STRING, tag.c_str(), 0);
	} catch (const std::runtime_error& e) {
		syslog(LOG_CRIT, "%s", e.what());
	}
}

HALON_EXPORT
bool Halon_hsl_register(HalonHSLRegisterContext* ptr)
{
	HalonMTA_hsl_register_function(ptr, "ip_list_lookup", &ip_list_lookup);
	return true;
}

struct list
{
	std::string path;
	lpm_t *lpm;
	std::shared_mutex lock;
};

std::map<std::string, struct list> lists;

lpm_t* lpm_load(const std::string& id, const std::string& path)
{
	std::ifstream input(path);
	if (!input.good())
		throw std::runtime_error("Bad ip-list file: " + path);

	lpm_t *lpm = lpm_create();

	size_t len;
	unsigned preflen;
	char addr[16];
	size_t cline = 1, loaded = 0;
	for(std::string address; getline(input, address); ++cline)
	{
		if (address[0] == '#') continue;
		auto ws = address.find_first_of(" \t\r\n");

		char* tag = nullptr;
		if (ws != std::string::npos)
		{
			auto ts = address.find_first_not_of(" \t\r\n", ws);
			auto te = address.find_last_not_of(" \t\r\n");
			if (ts != std::string::npos)
				tag = strdup(address.substr(ts, te - ts + 1).c_str());
			address = address.substr(0, ws);
		}
		if (!tag)
			tag = strdup("");

		if (lpm_strtobin(address.c_str(), &addr, &len, &preflen) != 0)
		{
			syslog(LOG_INFO, "ip-list %s:%zu: bad address/network format: %s", path.c_str(), cline, address.c_str());
			continue;
		}
		if (lpm_insert(lpm, addr, len, preflen, tag) != 0)
		{
			syslog(LOG_INFO, "ip-list %s:%zu: failed to insert %s", path.c_str(), cline, address.c_str());
			continue;
		}
		++loaded;
	}
	syslog(LOG_INFO, "ip-list(%s): loaded %zu addresses/networks (%s)", id.c_str(), loaded, path.c_str());

	return lpm;
}

void list_open(const std::string& id, const std::string& path)
{
	if (lists.find(id) != lists.end())
		throw std::runtime_error("Duplicate ip-list id");

	auto lpm = lpm_load(id, path);

	auto& l = lists[id];
	l.path = path;
	l.lpm = lpm;
}

bool list_lookup(const std::string& id, const std::string& address, std::string& tag)
{
	auto l = lists.find(id);
	if (l == lists.end())
		throw std::runtime_error("No such ip-list id");

	size_t len;
	unsigned preflen;
	char addr[16];
	
	if (lpm_strtobin(address.c_str(), &addr, &len, &preflen) != 0)
		throw std::runtime_error("Bad address format: " + address);

	std::shared_lock lock(l->second.lock);

	char* t = (char*)lpm_lookup(l->second.lpm, addr, len);
	if (t)
		tag = std::string(t);
	return t != nullptr;
}

void lpm_dtor(void *arg, const void *key, size_t len, void *val)
{
	free(val);
}

void list_reload(const std::string& id)
{
	auto l = lists.find(id);
	if (l == lists.end())
		throw std::runtime_error("No such ip-list id");

	auto lpm = lpm_load(id, l->second.path);

	std::unique_lock lock(l->second.lock);
	lpm_clear(l->second.lpm, lpm_dtor, nullptr);
	lpm_destroy(l->second.lpm);
	l->second.lpm = lpm;
}