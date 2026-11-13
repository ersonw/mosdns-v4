[简体中文](padding.cn.md) | English

# padding

**Source:** `plugin/executable/padding/padding.go`

## Arguments

No `type` registration. Only preset tags are available.

## Behavior

`_pad_query` pads the query to 128 bytes; on the response it removes EDNS0 if the query had none and removes padding if none was present. `_enable_conditional_response_padding` only pads the response when the client padded first. `_enable_response_padding` always pads to 468 bytes.

## Presets

`_pad_query`, `_enable_conditional_response_padding`, `_enable_response_padding`
