#ifndef __CICFLOWMETER_THREAD_MODULE_THREADS_COMMON_H__
#define __CICFLOWMETER_THREAD_MODULE_THREADS_COMMON_H__

#ifdef __cplusplus
extern "C" {
#endif

/** \brief Thread Model Module id's.
 *
 *  \note anything added here should also be added to TmModuleTmmIdToString
 *        in tm-modules.c
 */
typedef enum {
    TMM_FLOWWORKER,
    TMM_DECODENFQ,
    TMM_VERDICTNFQ,
    TMM_RECEIVENFQ,
    TMM_RECEIVEPCAP,
    TMM_RECEIVEPCAPFILE,
    TMM_DECODEPCAP,
    TMM_DECODEPCAPFILE,
    TMM_RECEIVEPFRING,
    TMM_DECODEPFRING,
    TMM_RECEIVEPLUGIN,
    TMM_DECODEPLUGIN,
    TMM_RESPONDREJECT,
    TMM_DECODEIPFW,
    TMM_VERDICTIPFW,
    TMM_RECEIVEIPFW,
    TMM_RECEIVEERFFILE,
    TMM_DECODEERFFILE,
    TMM_RECEIVEERFDAG,
    TMM_DECODEERFDAG,
    TMM_RECEIVEAFP,
    TMM_DECODEAFP,
    TMM_RECEIVENETMAP,
    TMM_DECODENETMAP,
    TMM_ALERTPCAPINFO,
    TMM_RECEIVENAPATECH,
    TMM_DECODENAPATECH,
    TMM_STATSLOGGER,
    TMM_RECEIVENFLOG,
    TMM_DECODENFLOG,
    TMM_RECEIVEWINDIVERT,
    TMM_VERDICTWINDIVERT,
    TMM_DECODEWINDIVERT,

    TMM_FLOWMANAGER,
    TMM_FLOWRECYCLER,
    TMM_BYPASSEDFLOWMANAGER,
    TMM_DETECTLOADER,

    TMM_UNIXMANAGER,

    TMM_SIZE,
} TMM_ID_T;

/*Error codes for the thread modules*/
typedef enum {
    TM_ECODE_OK = 0, /**< Thread module exits OK*/
    TM_ECODE_FAILED, /**< Thread module exits due to failure*/
    TM_ECODE_DONE,   /**< Thread module task is finished*/
} TM_ERROR_T;

/* ThreadVars type */
enum {
    TVT_PPT,
    TVT_MGMT,
    TVT_CMD,
    TVT_MAX,
};

#ifdef __cplusplus
}
#endif

#endif
