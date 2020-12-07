#ifndef __CICFLOWMETER_FLOW_WORKER_H__
#define __CICFLOWMETER_FLOW_WORKER_H__

#ifdef __cplusplus
extern "C" {
#endif

enum ProfileFlowWorkerId {
    PROFILE_FLOWWORKER_FLOW = 0,
    PROFILE_FLOWWORKER_STREAM,
    PROFILE_FLOWWORKER_APPLAYERUDP,
    PROFILE_FLOWWORKER_DETECT,
    PROFILE_FLOWWORKER_TCPPRUNE,
    PROFILE_FLOWWORKER_FLOW_INJECTED,
    PROFILE_FLOWWORKER_FLOW_EVICTED,
    PROFILE_FLOWWORKER_SIZE
};
const char *ProfileFlowWorkerIdToString(enum ProfileFlowWorkerId fwi);

void FlowWorkerReplaceDetectCtx(void *flow_worker, void *detect_ctx);
void *FlowWorkerGetDetectCtxPtr(void *flow_worker);

void TmModuleFlowWorkerRegister(void);

#ifdef __cplusplus
}
#endif

#endif
