# OpenAI GPT-5.5 Migration (Project Baseline)

Generated: 2026-04-25

## Result

This repository currently has **no active OpenAI API integration** (no OpenAI SDK usage and no model-id pins in source/config code paths), so there was no direct in-repo model replacement to perform.

## Project Standard (going forward)

If/when an OpenAI integration is added, use:

- `model: "gpt-5.5"` as the default
- Responses API as the preferred surface for new implementations

## Audit scope

The migration scan covered repository source/config/docs paths (excluding heavy generated/vendor caches) and found no OpenAI model pins to update.

## Reproducible guardrail

Run:

```bash
bash ./scripts/integration_openai_model_policy_guard.sh
```

This integration guard now enforces two fail-closed policy rules:
- Disallow legacy model ids in runtime code/config paths.
- If OpenAI runtime usage appears, require the target model string (`gpt-5.5`).

## References

- OpenAI Models: https://developers.openai.com/api/docs/models
- OpenAI model-upgrade guide target (gpt-5.5): https://developers.openai.com/api/docs/guides/upgrading-to-gpt-5p5.md
