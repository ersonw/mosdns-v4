[简体中文](sequence.cn.md) | English

# sequence

**Source:** `plugin/executable/sequence/sequence.go`

## Arguments

`exec` accepts a tag, a list of tags, or logic nodes: `if` / `else_exec`, `parallel`, `load_balance`, and `primary` + `secondary`.

## Behavior

`Init` compiles the `exec` tree with `executable_seq.BuildExecutableLogicTree`. `Exec` runs the compiled chain and then the outer `next`. The preset `_return` returns without calling `next`, so it stops the chain at that point. Tags are resolved at startup; a bad tag fails the whole configuration. `sequence` can be nested.

## Presets

`_return`

## Example

```yaml
- tag: main_seq
  type: sequence
  args:
    exec:
      - _misc_optm
      - cache
      - if: "qtype_A_AAAA && !is_local"
        exec: [fast_forward]
        else_exec: [_return]
```
