# Fine-tuning recipes — burpwn-usage

Ready-to-run [**LLaMA-Factory**](https://github.com/hiyouga/LLaMA-Factory)
recipes that fine-tune an LLM to drive burpwn (shell CLI **and** MCP tool calls)
on the `../dataset.train.jsonl` / `../dataset.validation.jsonl` split.

## Why LLaMA-Factory

* It ingests our **OpenAI `messages`** shape directly (`formatting: sharegpt` +
  an OpenAI `tags` mapping in `dataset_info.json`) — including `tool_calls` and
  `tool` turns — so no data conversion is needed.
* LoRA ↔ QLoRA is a one-line toggle (`quantization_bit`), making the 4B and 70B
  recipes structurally identical.
* It masks prompts and trains on assistant turns by default (train-on-responses-
  only), which is exactly what we want for tool-use SFT.
* Per-model chat templates (`qwen`, `llama3`, …) are built in, so the same data
  maps cleanly onto each base model's template.

(TRL `SFTTrainer` or Axolotl work too — map `messages` to the chat template and
enable completion-only masking — but the YAMLs here are LLaMA-Factory.)

## Install

```bash
git clone https://github.com/hiyouga/LLaMA-Factory && cd LLaMA-Factory
pip install -e ".[torch,metrics,bitsandbytes]"          # add ,deepspeed for 70B
```

## Data wiring

`dataset_info.json` (in this folder) registers two datasets, `burpwn_train` and
`burpwn_validation`, pointing at `../dataset.train.jsonl` and
`../dataset.validation.jsonl`. Both training YAMLs set `dataset_dir: .`, so run
them with this folder reachable, or pass an **absolute** `dataset_dir`. First
(re)generate the data:

```bash
cd ..            # training/
python generate.py
cd finetune
```

## Recipes

| Config | Base (swap freely) | Method | Context | Fits on |
|--------|--------------------|--------|---------|---------|
| `qwen3_4b_lora_sft.yaml` | Qwen3-4B-Instruct (or Llama-3.2-3B-Instruct) | LoRA, bf16 | 4096 | **single 24GB GPU** |
| `llama3_70b_qlora_sft.yaml` | Llama-3.3-70B-Instruct (or Qwen2.5-72B) | **QLoRA 4-bit (NF4)** | 8192 | **2×80GB or 4×48GB** (ZeRO-3 offload) |

Run:

```bash
# 4B LoRA, single GPU
llamafactory-cli train ../finetune/qwen3_4b_lora_sft.yaml

# 70B QLoRA, 4 GPUs
FORCE_TORCHRUN=1 NPROC_PER_NODE=4 \
  llamafactory-cli train ../finetune/llama3_70b_qlora_sft.yaml
```

> **Match the template to the base.** If you change `model_name_or_path`, set
> `template` accordingly (`qwen` for Qwen, `llama3` for Llama-3.x, `phi` for
> Phi, …). The same `messages` data is re-rendered into whatever template you
> pick — the system/user/assistant turns and the `tool_calls`/`tool` turns map
> onto that base model's native chat + tool-call format.

## Expected resources (rough)

* **4B LoRA**: ~16–22GB VRAM at `cutoff_len: 4096`, batch 2 × accum 8. ~2.6k
  examples × 3 epochs ≈ a few hundred steps; **~15–40 min** on one 4090/A100.
* **70B QLoRA**: 4-bit weights ~38–40GB; with ZeRO-3 + offload, runs on 2×80GB
  (tight) or 4×48GB. Expect **a few hours** for 3 epochs. Lower `cutoff_len` to
  4096 if you hit OOM; raise `gradient_accumulation_steps` to keep the effective
  batch.

Tune `learning_rate` (1e-4 is a sane LoRA start), `num_train_epochs` (2–3 for a
dataset this size — watch validation loss for overfit), and `lora_rank` (8–32).

## Evaluate

1. **Hold-out validation loss** — both YAMLs set `eval_dataset:
   burpwn_validation` with `eval_strategy: steps`; watch it stop improving.
2. **Smoke prompts** — after merging/loading the adapter, sanity-check a few:
   * *CLI:* "Fetch the juice-shop homepage through the proxy so it's captured."
     → expect `burpwn exec -- curl -s https://juice-shop.local/`.
   * *CLI negative:* "Export the session as a pcap." → expect it to explain pcap
     is unimplemented and steer to `burpwn export har`.
   * *MCP:* "List successful GET requests to api.shopwave.io." → expect a
     `req_list` tool call with `{"host":"api.shopwave.io","method":"GET","status":200}`.
   * *MCP multi-step:* "Enable interception, grab the next checkout request, bump
     qty to 99." → expect `intercept_enable` → `await_intercept` →
     `intercept_forward` with `set_body`.
   Check the model uses **only real** subcommands/flags/tools and the correct
   envelope shapes (CLI `{ok,data,error}` vs MCP's unwrapped results).
3. Optionally hold out by `tags` (e.g. exclude all `xxe`/`graphql` at generation
   time via a custom filter) to test generalization to unseen scenario families.

## Inference / serving

After training, merge the LoRA (`llamafactory-cli export ...`) or load the
adapter at serve time, then expose the model to your agent. For MCP-style use,
serve with an OpenAI-compatible tool-calling endpoint so the learned `tool_calls`
map onto burpwn's MCP tools (`burpwn mcp`, stdio).
