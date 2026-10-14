#include "risk.h"
#include <string.h>
#include <strings.h>

static const struct { const char *rule; int weight; } k_weights[] = {
    {"HIDDEN_FROM_PROC",   W_HIDDEN_FROM_PROC},
    {"HIDDEN_FROM_SYSFS",  W_HIDDEN_FROM_SYSFS},
    {"SUSPICIOUS_NAME",    W_SUSPICIOUS_NAME},
    {"NOT_IN_BASELINE",    W_NOT_IN_BASELINE},
    {"SRCVERSION_CHANGED", W_SRCVERSION_CHANGED},
    {"DUPLICATE_NAME",     W_DUPLICATE_NAME},
    {"NO_MODULE_FILE",     W_NO_MODULE_FILE},
    {"SIZE_CHANGED",       W_SIZE_CHANGED},
    {"ABNORMAL_STATE",     W_ABNORMAL_STATE},
    {"UNSIGNED",           W_UNSIGNED},
    {"DEPS_CHANGED",       W_DEPS_CHANGED},
    {"MISSING",            W_MISSING},
    {"OUT_OF_TREE",        W_OUT_OF_TREE},
    {"PROPRIETARY",        W_PROPRIETARY},
    {"NONSTANDARD_PATH",   W_NONSTANDARD_PATH},
};

int risk_weight_for(const char *rule_id)
{
    if (!rule_id)
        return 0;
    for (unsigned i = 0; i < sizeof(k_weights) / sizeof(k_weights[0]); i++)
        if (strcmp(rule_id, k_weights[i].rule) == 0)
            return k_weights[i].weight;
    return 0;
}

int risk_cap(int raw_sum)
{
    if (raw_sum < 0)
        return 0;
    return raw_sum > RISK_MAX_SCORE ? RISK_MAX_SCORE : raw_sum;
}

risk_level_t risk_level_from_score(int score)
{
    if (score <= 0)
        return RISK_NONE;
    if (score < 25)
        return RISK_LOW;
    if (score < 50)
        return RISK_MEDIUM;
    if (score < 75)
        return RISK_HIGH;
    return RISK_CRITICAL;
}

const char *risk_level_name(risk_level_t lvl)
{
    switch (lvl) {
    case RISK_NONE:     return "NONE";
    case RISK_LOW:      return "LOW";
    case RISK_MEDIUM:   return "MEDIUM";
    case RISK_HIGH:     return "HIGH";
    case RISK_CRITICAL: return "CRITICAL";
    }
    return "?";
}

int risk_level_parse(const char *s, risk_level_t *out)
{
    static const struct { const char *n; risk_level_t l; } tbl[] = {
        {"low", RISK_LOW},       {"medium", RISK_MEDIUM},
        {"high", RISK_HIGH},     {"critical", RISK_CRITICAL},
    };
    if (!s)
        return -1;
    for (unsigned i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++)
        if (strcasecmp(s, tbl[i].n) == 0) {
            *out = tbl[i].l;
            return 0;
        }
    return -1;
}
