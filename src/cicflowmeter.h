#ifndef __CICFLOWMETER_H__
#define __SURICATA_H__

#include "suricata-common.h"
//#include "packet-queue.h"

/* the name of our binary */
#define PROG_NAME "cicflowmeter"
#define PROG_VER PACKAGE_VERSION

/* workaround SPlint error (don't know __gnuc_va_list) */
#ifdef S_SPLINT_S
#  include <err.h>
#  define CONFIG_DIR "/etc/cicflowmeter"
#endif

#define DEFAULT_CONF_FILE CONFIG_DIR "/cicflowmeter.yaml"

#define DEFAULT_PID_DIR LOCAL_STATE_DIR "/run/"
#define DEFAULT_PID_BASENAME "cicflowmeter.pid"
#define DEFAULT_PID_FILENAME DEFAULT_PID_DIR DEFAULT_PID_BASENAME

const char *GetDocURL(void);

/* runtime engine control flags */
#define CICFLOWMETER_STOP    (1 << 0)   /**< gracefully stop the engine: process all
                                     outstanding packets first */
#define CICFLOWMETER_DONE    (1 << 2)   /**< packets capture ended */

/* Engine stage/status*/
enum {
    CICFLOWMETER_INIT = 0,
    CICFLOWMETER_RUNTIME,
    CICFLOWMETER_DEINIT
};

/* Engine is acting as */
enum EngineMode {
    ENGINE_MODE_IDS,
    ENGINE_MODE_IPS,
};

void EngineModeSetIPS(void);
void EngineModeSetIDS(void);
int EngineModeIsIPS(void);
int EngineModeIsIDS(void);


#include "runmodes.h"

typedef struct CICInstance_ {
    enum RunModes run_mode;
    enum RunModes aux_run_mode;

    char pcap_dev[128];
    char *sig_file;
    int sig_file_exclusive;
    char *pid_filename;
    char *regex_arg;

    char *keyword_info;
    char *runmode_custom_mode;
#ifndef OS_WIN32
    const char *user_name;
    const char *group_name;
    uint8_t do_setuid;
    uint8_t do_setgid;
    uint32_t userid;
    uint32_t groupid;
#endif /* OS_WIN32 */

    bool system;
    bool set_logdir;
    bool set_datadir;

    int delayed_detect;
    int disabled_detect;
    int daemon;
    int offline;
    int verbose;
    int checksum_validation;

    struct timeval start_time;

    const char *log_dir;
    const char *progname; /**< pointer to argv[0] */
    const char *conf_filename;
    char *strict_rule_parsing_string;
} CICInstance;


/* memset to zeros, and mutex init! */
void GlobalsInitPreConfig(void);

extern volatile uint8_t cicflowmeter_ctl_flags;
extern int g_disable_randomness;
extern uint16_t g_vlan_mask;

#include <ctype.h>
#define u8_tolower(c) tolower((uint8_t)(c))
#define u8_toupper(c) toupper((uint8_t)(c))

void EngineStop(void);
void EngineDone(void);

int RunmodeIsUnittests(void);
int RunmodeGetCurrent(void);
int IsRuleReloadSet(int quiet);

int CicHasSigFile(void);

extern int run_mode;

int CicflowmeterMain(int argc, char **argv);
int InitGlobal(void);
int PostConfLoadedSetup(CICInstance *suri);
void PostConfLoadedDetectSetup(CICInstance *cic);

void PreRunInit(const int runmode);
void PreRunPostPrivsDropInit(const int runmode);
void PostRunDeinit(const int runmode, struct timeval *start_time);
void RegisterAllModules(void);

const char *GetProgramVersion(void);

#endif /* __CICFLOWMETER_H__ */
