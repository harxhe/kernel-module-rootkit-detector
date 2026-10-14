#ifndef RISK_H
#define RISK_H

/* Phase 6 - risk scoring.
   Every anomaly rule contributes a fixed weight; a module's score is the sum
   of its weights, capped at 100, then mapped to a level.

     score  1-24  LOW        worth a glance
     score 25-49  MEDIUM     investigate
     score 50-74  HIGH       likely unauthorized / tampered
     score 75-100 CRITICAL   strong rootkit indicator                     */

typedef enum {
    RISK_NONE = 0,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_HIGH,
    RISK_CRITICAL
} risk_level_t;

/* Rule weights (single place to tune the engine); mapped to rule ids by the
   table in risk.c. */
#define W_HIDDEN_FROM_PROC   80 /* in sysfs, absent from /proc/modules      */
#define W_HIDDEN_FROM_SYSFS  60 /* in /proc/modules, absent from sysfs      */
#define W_SUSPICIOUS_NAME    50 /* name matches known rootkit naming        */
#define W_NOT_IN_BASELINE    40 /* module did not exist at baseline time    */
#define W_SRCVERSION_CHANGED 40 /* module binary differs from baseline      */
#define W_DUPLICATE_NAME     30 /* name listed twice in /proc/modules       */
#define W_NO_MODULE_FILE     25 /* not in modules.dep: loaded from nowhere  */
#define W_SIZE_CHANGED       20 /* size differs from baseline               */
#define W_UNSIGNED           10 /* taint flag E: unsigned module            */
#define W_ABNORMAL_STATE     15 /* stuck Loading/Unloading/going            */
#define W_DEPS_CHANGED       10 /* dependency list differs from baseline    */
#define W_MISSING            10 /* baseline module no longer present        */
#define W_OUT_OF_TREE         5 /* taint flag O: out-of-tree module         */
#define W_PROPRIETARY         5 /* taint flag P: proprietary license        */
#define W_NONSTANDARD_PATH    5 /* in modules.dep but outside kernel/       */

#define RISK_MAX_SCORE 100

/* Weight of one finding, looked up by the analyzer's rule id (0 if the id
   is unknown). The table is in risk.c. */
int risk_weight_for(const char *rule_id);

int risk_cap(int raw_sum);
risk_level_t risk_level_from_score(int score);
const char *risk_level_name(risk_level_t lvl);
/* Parse "low", "medium", "high", "critical" (case-insensitive). -1 if bad. */
int risk_level_parse(const char *s, risk_level_t *out);

#endif /* RISK_H */
