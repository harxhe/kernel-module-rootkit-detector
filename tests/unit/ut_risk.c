#include "risk.h"
#include "ut.h"

TEST(risk_level_boundaries)
{
    CHECK(risk_level_from_score(0) == RISK_NONE);
    CHECK(risk_level_from_score(1) == RISK_LOW);
    CHECK(risk_level_from_score(24) == RISK_LOW);
    CHECK(risk_level_from_score(25) == RISK_MEDIUM);
    CHECK(risk_level_from_score(49) == RISK_MEDIUM);
    CHECK(risk_level_from_score(50) == RISK_HIGH);
    CHECK(risk_level_from_score(74) == RISK_HIGH);
    CHECK(risk_level_from_score(75) == RISK_CRITICAL);
    CHECK(risk_level_from_score(100) == RISK_CRITICAL);
}

TEST(risk_cap_and_names)
{
    CHECK(risk_cap(250) == 100 && risk_cap(-5) == 0 && risk_cap(42) == 42);
    CHECK(strcmp(risk_level_name(RISK_NONE), "NONE") == 0);
    CHECK(strcmp(risk_level_name(RISK_HIGH), "HIGH") == 0);
    CHECK(strcmp(risk_level_name(RISK_CRITICAL), "CRITICAL") == 0);
}

TEST(risk_level_parse_cases)
{
    risk_level_t l;
    CHECK(risk_level_parse("High", &l) == 0 && l == RISK_HIGH);
    CHECK(risk_level_parse("CRITICAL", &l) == 0 && l == RISK_CRITICAL);
    CHECK(risk_level_parse("low", &l) == 0 && l == RISK_LOW);
    CHECK(risk_level_parse("medium", &l) == 0 && l == RISK_MEDIUM);
    CHECK(risk_level_parse("bogus", &l) == -1);
    CHECK(risk_level_parse("", &l) == -1);
    CHECK(risk_level_parse(NULL, &l) == -1);
}

TEST(risk_weight_design_invariants)
{
    /* the documented design: a hidden module alone is CRITICAL, a new module
       alone is only MEDIUM, a new module from nowhere is HIGH */
    CHECK(risk_level_from_score(W_HIDDEN_FROM_PROC) == RISK_CRITICAL);
    CHECK(risk_level_from_score(W_HIDDEN_FROM_SYSFS) == RISK_HIGH);
    CHECK(risk_level_from_score(W_NOT_IN_BASELINE) == RISK_MEDIUM);
    CHECK(risk_level_from_score(W_NOT_IN_BASELINE + W_NO_MODULE_FILE) == RISK_HIGH);
    CHECK(risk_level_from_score(W_UNSIGNED + W_OUT_OF_TREE + W_NONSTANDARD_PATH) == RISK_LOW);
}
