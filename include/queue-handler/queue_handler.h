#ifndef __CICFLOWMETER_THREAD_MODULE_QUEUE_HANDLER_H__
#define __CICFLOWMETER_THREAD_MODULE_QUEUE_HANDLER_H__

#ifdef __cplusplus
extern "C" {
#endif

enum {
    TMQH_NOT_SET,
    TMQH_SIMPLE,
    TMQH_PACKETPOOL,
    TMQH_FLOW,

    TMQH_SIZE,
};

typedef struct Tmqh_ {
    const char *name;
    Packet *(*InHandler)(ThreadVars *);
    void (*InShutdownHandler)(ThreadVars *);
    void (*OutHandler)(ThreadVars *, Packet *);
    void *(*OutHandlerCtxSetup)(const char *);
    void (*OutHandlerCtxFree)(void *);
    void (*RegisterTests)(void);
} Tmqh;

extern Tmqh tmqh_table[TMQH_SIZE];

void TmqhSetup(void);
void TmqhCleanup(void);
int TmqhNameToID(const char *name);
Tmqh *TmqhGetQueueHandlerByName(const char *name);
Tmqh *TmqhGetQueueHandlerByID(const int id);

#ifdef __cplusplus
}
#endif

#endif
