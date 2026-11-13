[简体中文](sleep.cn.md) | English

# sleep

**Source:** `plugin/executable/sleep/sleep.go`

## Arguments

`duration` in milliseconds.

## Behavior

Waits for the duration using a pooled timer. A cancelled context returns early.

## Presets

`_sleep_500ms`
