#include "risk.h"
#include <strings.h>

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
