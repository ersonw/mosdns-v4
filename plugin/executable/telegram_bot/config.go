/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// This file gives the bot control over the mosdns configuration file: read
// and write one key, append or remove a block (log, data_providers, plugins,
// servers), and describe a plugin. Edits keep comments and ordering because
// the document is handled as a yaml.Node tree, a timestamped backup is taken
// before every write, and the generated yaml is re-parsed before it replaces
// the original.

package telegram_bot

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// configSections are the top-level blocks the bot is allowed to edit.
var configSections = map[string]struct{}{
	"log":            {},
	"data_providers": {},
	"plugins":        {},
	"servers":        {},
}

func (p *telegramBot) configPath() string {
	if p.args.ConfigPath != "" {
		return p.args.ConfigPath
	}
	argv := os.Args
	for i, a := range argv {
		switch {
		case (a == "-c" || a == "--config") && i+1 < len(argv):
			return argv[i+1]
		case strings.HasPrefix(a, "-c="):
			return strings.TrimPrefix(a, "-c=")
		case strings.HasPrefix(a, "--config="):
			return strings.TrimPrefix(a, "--config=")
		}
	}
	return "etc/mosdns/config.yaml"
}

func loadConfigDocument(path string) (*yaml.Node, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s is not a yaml mapping", path)
	}
	return &doc, nil
}

func mappingIndex(m *yaml.Node, key string) int {
	if m == nil || m.Kind != yaml.MappingNode {
		return -1
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return i
		}
	}
	return -1
}

func mappingGet(m *yaml.Node, key string) *yaml.Node {
	idx := mappingIndex(m, key)
	if idx < 0 {
		return nil
	}
	return m.Content[idx+1]
}

// parsePart splits "plugins[0]" into a key and an optional sequence index.
func parsePart(p string) (name string, index int, hasIndex bool, err error) {
	if p == "" {
		return "", 0, false, fmt.Errorf("empty key segment")
	}
	if strings.HasPrefix(p, "[") {
		end := strings.IndexByte(p, ']')
		if end < 0 || end != len(p)-1 {
			return "", 0, false, fmt.Errorf("bad index %q", p)
		}
		n, err := strconv.Atoi(p[1:end])
		if err != nil {
			return "", 0, false, fmt.Errorf("bad index %q", p)
		}
		return "", n, true, nil
	}
	lb := strings.IndexByte(p, '[')
	if lb < 0 {
		return p, 0, false, nil
	}
	rb := strings.IndexByte(p, ']')
	if rb < lb || rb != len(p)-1 {
		return "", 0, false, fmt.Errorf("bad index %q", p)
	}
	n, err := strconv.Atoi(p[lb+1 : rb])
	if err != nil {
		return "", 0, false, fmt.Errorf("bad index %q", p)
	}
	return p[:lb], n, true, nil
}

// walkPath follows a dotted path with optional [n] indexes. With create it
// builds missing mappings, and appends one element when an index equals len.
func walkPath(root *yaml.Node, parts []string, create bool) (*yaml.Node, error) {
	cur := root.Content[0]
	for _, part := range parts {
		name, idx, hasIdx, err := parsePart(part)
		if err != nil {
			return nil, err
		}

		if name != "" {
			if cur.Kind != yaml.MappingNode {
				return nil, fmt.Errorf("%s is not a mapping", part)
			}
			i := mappingIndex(cur, name)
			if i < 0 {
				if !create {
					return nil, nil
				}
				child := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
				if hasIdx {
					child = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
				}
				cur.Content = append(cur.Content,
					&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name}, child)
				cur = child
			} else {
				cur = cur.Content[i+1]
			}
		}

		if hasIdx {
			if cur.Kind != yaml.SequenceNode {
				return nil, fmt.Errorf("%s is not a sequence", part)
			}
			switch {
			case idx < len(cur.Content):
				cur = cur.Content[idx]
			case !create:
				return nil, nil
			case idx == len(cur.Content):
				child := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
				cur.Content = append(cur.Content, child)
				cur = child
			default:
				return nil, fmt.Errorf("index %d is out of range (len %d)", idx, len(cur.Content))
			}
		}
	}
	return cur, nil
}

func nodeText(n *yaml.Node) string {
	if n == nil {
		return ""
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(n); err != nil {
		return ""
	}
	_ = enc.Close()
	return strings.TrimSpace(buf.String())
}

func setConfigValue(doc *yaml.Node, path []string, raw string) error {
	if len(path) == 0 {
		return fmt.Errorf("empty key")
	}
	parent, err := walkPath(doc, path[:len(path)-1], true)
	if err != nil {
		return err
	}
	last := path[len(path)-1]
	name, idx, hasIdx, err := parsePart(last)
	if err != nil {
		return err
	}

	var value interface{}
	if err := yaml.Unmarshal([]byte(raw), &value); err != nil {
		value = raw
	}
	newNode := &yaml.Node{}
	if err := newNode.Encode(value); err != nil {
		return fmt.Errorf("encode value: %w", err)
	}

	if hasIdx {
		if parent.Kind != yaml.SequenceNode {
			return fmt.Errorf("%s is not a sequence", last)
		}
		if idx >= len(parent.Content) {
			return fmt.Errorf("index %d is out of range (len %d)", idx, len(parent.Content))
		}
		setValueNode(parent.Content[idx], newNode)
		return nil
	}

	if parent.Kind != yaml.MappingNode {
		return fmt.Errorf("%s is not a mapping", last)
	}
	if i := mappingIndex(parent, name); i >= 0 {
		setValueNode(parent.Content[i+1], newNode)
		return nil
	}
	parent.Content = append(parent.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name}, newNode)
	return nil
}

// setValueNode keeps the comments of the replaced node.
func setValueNode(old, newNode *yaml.Node) {
	newNode.HeadComment = old.HeadComment
	newNode.LineComment = old.LineComment
	newNode.FootComment = old.FootComment
	*old = *newNode
}

func writeConfigDocument(path string, doc *yaml.Node) (string, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return "", fmt.Errorf("encode config: %w", err)
	}
	_ = enc.Close()

	var check interface{}
	if err := yaml.Unmarshal(buf.Bytes(), &check); err != nil {
		return "", fmt.Errorf("generated config is invalid: %w", err)
	}

	orig, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	backup := fmt.Sprintf("%s.bak.%d", path, time.Now().Unix())
	if err := os.WriteFile(backup, orig, 0o644); err != nil {
		return "", fmt.Errorf("backup %s: %w", backup, err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o644); err != nil {
		return "", fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", fmt.Errorf("replace %s: %w", path, err)
	}
	return backup, nil
}

func sequenceLen(doc *yaml.Node, key string) int {
	n := nodePath(doc, []string{key})
	if n == nil || n.Kind != yaml.SequenceNode {
		return 0
	}
	return len(n.Content)
}

func nodePath(doc *yaml.Node, path []string) *yaml.Node {
	n, err := walkPath(doc, path, false)
	if err != nil {
		return nil
	}
	return n
}

// pluginBlock finds the plugin declaration with the given tag.
func pluginBlock(doc *yaml.Node, tag string) *yaml.Node {
	list := nodePath(doc, []string{"plugins"})
	if list == nil || list.Kind != yaml.SequenceNode {
		return nil
	}
	for _, item := range list.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		if t := mappingGet(item, "tag"); t != nil && t.Value == tag {
			return item
		}
	}
	return nil
}

var secretKeys = []string{"token", "password", "secret", "apikey", "api_key", "key"}

// maskSecrets renders a node with credentials replaced. It edits the in-memory
// tree only; a read never writes the configuration file.
func maskSecrets(n *yaml.Node) string {
	if n == nil {
		return ""
	}
	maskWalk(n)
	return nodeText(n)
}

func maskWalk(m *yaml.Node) {
	if m == nil {
		return
	}
	if m.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(m.Content); i += 2 {
			k := strings.ToLower(m.Content[i].Value)
			for _, s := range secretKeys {
				if strings.Contains(k, s) {
					v := m.Content[i+1]
					v.Kind = yaml.ScalarNode
					v.Tag = "!!str"
					v.Value = "***"
					v.Style = 0
					v.Content = nil
				}
			}
			maskWalk(m.Content[i+1])
		}
		return
	}
	for _, c := range m.Content {
		maskWalk(c)
	}
}

func (p *telegramBot) handleConfig(args []string) (string, error) {
	path := p.configPath()
	doc, err := loadConfigDocument(path)
	if err != nil {
		return "", err
	}

	if len(args) == 0 {
		return p.configSummary(path, doc), nil
	}

	switch strings.ToLower(args[0]) {
	case "show":
		if len(args) < 2 {
			return "usage: /config show <log|data_providers|plugins|servers>", nil
		}
		n := nodePath(doc, strings.Split(args[1], "."))
		if n == nil {
			return fmt.Sprintf("%s: not found", args[1]), nil
		}
		text := maskSecrets(n)
		if len(text) > 3500 {
			text = text[:3500] + "\n...(truncated)"
		}
		return text, nil

	case "get":
		if len(args) < 2 {
			return "usage: /config get <key.path>", nil
		}
		n := nodePath(doc, strings.Split(args[1], "."))
		if n == nil {
			return fmt.Sprintf("%s: not found", args[1]), nil
		}
		return fmt.Sprintf("%s: %s", args[1], maskSecrets(n)), nil

	case "set":
		if len(args) < 3 {
			return "usage: /config set <key.path> <value>", nil
		}
		if err := setConfigValue(doc, strings.Split(args[1], "."), strings.Join(args[2:], " ")); err != nil {
			return "", err
		}
		backup, err := writeConfigDocument(path, doc)
		if err != nil {
			return "", err
		}
		p.L().Info("config updated by bot", zap.String("key", args[1]), zap.String("backup", backup))
		return fmt.Sprintf("%s updated\nbackup: %s\nsend /reload confirm to apply", args[1], backup), nil

	case "add":
		if len(args) < 3 {
			return "usage: /config add <log|data_providers|plugins|servers> <yaml>", nil
		}
		backup, err := p.configAdd(doc, args[1], strings.Join(args[2:], " "))
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s appended\nbackup: %s\nsend /reload confirm to apply", args[1], backup), nil

	case "del":
		if len(args) < 3 {
			return "usage: /config del <log|data_providers|plugins|servers> <key|tag|index>", nil
		}
		backup, err := p.configDel(doc, args[1], args[2])
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s removed\nbackup: %s\nsend /reload confirm to apply", args[2], backup), nil

	case "validate":
		problems := validateConfig(doc)
		if len(problems) == 0 {
			return "config looks valid: syntax plus required fields of plugins, data_providers and servers", nil
		}
		return "problems:\n- " + strings.Join(problems, "\n- "), nil
	}

	return "usage: /config [show|get|set|add|del|validate] ...", nil
}

func (p *telegramBot) configSummary(path string, doc *yaml.Node) string {
	var b strings.Builder
	fmt.Fprintf(&b, "config: %s", path)
	for _, key := range []string{"log.level", "log.file", "api.http", "include"} {
		if n := nodePath(doc, strings.Split(key, ".")); n != nil {
			fmt.Fprintf(&b, "\n%s: %s", key, strings.Trim(n.Value, "\n"))
		}
	}
	fmt.Fprintf(&b, "\nplugins: %d", sequenceLen(doc, "plugins"))
	fmt.Fprintf(&b, "\ndata_providers: %d", sequenceLen(doc, "data_providers"))
	fmt.Fprintf(&b, "\nservers: %d", sequenceLen(doc, "servers"))
	return b.String()
}

// configAdd merges a yaml fragment into one section. log is a mapping; the
// other sections are sequences, so the fragment becomes one new element.
func (p *telegramBot) configAdd(doc *yaml.Node, section, blob string) (string, error) {
	if _, ok := configSections[section]; !ok {
		return "", fmt.Errorf("unknown section %q (use log, data_providers, plugins or servers)", section)
	}

	var frag yaml.Node
	if err := yaml.Unmarshal([]byte(blob), &frag); err != nil {
		return "", fmt.Errorf("fragment is not valid yaml: %w", err)
	}
	if len(frag.Content) == 0 || frag.Content[0].Kind != yaml.MappingNode {
		return "", fmt.Errorf("fragment must be a yaml mapping")
	}
	fragMap := frag.Content[0]

	if section == "log" {
		logNode, err := walkPath(doc, []string{"log"}, true)
		if err != nil {
			return "", err
		}
		if logNode.Kind != yaml.MappingNode {
			return "", fmt.Errorf("log is not a mapping")
		}
		for i := 0; i+1 < len(fragMap.Content); i += 2 {
			key := fragMap.Content[i].Value
			if idx := mappingIndex(logNode, key); idx >= 0 {
				setValueNode(logNode.Content[idx+1], fragMap.Content[i+1])
				continue
			}
			logNode.Content = append(logNode.Content, fragMap.Content[i], fragMap.Content[i+1])
		}
		return writeConfigDocument(p.configPath(), doc)
	}

	root := doc.Content[0]
	idx := mappingIndex(root, section)
	var seq *yaml.Node
	if idx < 0 {
		seq = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		root.Content = append(root.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: section}, seq)
	} else {
		seq = root.Content[idx+1]
		if seq.Kind != yaml.SequenceNode {
			return "", fmt.Errorf("%s is not a sequence", section)
		}
	}

	// Reject duplicate tags up front: mosdns refuses to start on them.
	if section == "plugins" || section == "data_providers" {
		if newTag := mappingGet(fragMap, "tag"); newTag != nil && newTag.Value != "" {
			if existing := findElementByTag(seq, newTag.Value); existing != nil {
				return "", fmt.Errorf("tag %q already exists", newTag.Value)
			}
		}
	}
	seq.Content = append(seq.Content, fragMap)
	return writeConfigDocument(p.configPath(), doc)
}

func (p *telegramBot) configDel(doc *yaml.Node, section, target string) (string, error) {
	if _, ok := configSections[section]; !ok {
		return "", fmt.Errorf("unknown section %q", section)
	}

	if section == "log" {
		logNode := nodePath(doc, []string{"log"})
		if logNode == nil || logNode.Kind != yaml.MappingNode {
			return "", fmt.Errorf("log is not a mapping")
		}
		idx := mappingIndex(logNode, target)
		if idx < 0 {
			return "", fmt.Errorf("log has no key %q", target)
		}
		logNode.Content = append(logNode.Content[:idx], logNode.Content[idx+2:]...)
		return writeConfigDocument(p.configPath(), doc)
	}

	seq := nodePath(doc, []string{section})
	if seq == nil || seq.Kind != yaml.SequenceNode {
		return "", fmt.Errorf("%s is not a sequence", section)
	}

	idx := -1
	if section == "servers" {
		n, err := strconv.Atoi(target)
		if err != nil || n < 0 || n >= len(seq.Content) {
			return "", fmt.Errorf("server index %q is out of range (len %d)", target, len(seq.Content))
		}
		idx = n
	} else {
		if el := findElementByTag(seq, target); el != nil {
			for i, c := range seq.Content {
				if c == el {
					idx = i
					break
				}
			}
		}
		if idx < 0 {
			return "", fmt.Errorf("%s has no element with tag %q", section, target)
		}
	}

	seq.Content = append(seq.Content[:idx], seq.Content[idx+1:]...)
	return writeConfigDocument(p.configPath(), doc)
}

func findElementByTag(seq *yaml.Node, tag string) *yaml.Node {
	for _, item := range seq.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		if t := mappingGet(item, "tag"); t != nil && t.Value == tag {
			return item
		}
	}
	return nil
}

// validateConfig checks the fields mosdns itself requires, so a write can be
// refused before it turns into a startup failure.
func validateConfig(doc *yaml.Node) []string {
	var problems []string

	plugins := nodePath(doc, []string{"plugins"})
	if plugins != nil {
		seen := make(map[string]struct{})
		for i, item := range plugins.Content {
			tag := mappingGet(item, "tag")
			typ := mappingGet(item, "type")
			if tag == nil || tag.Value == "" {
				problems = append(problems, fmt.Sprintf("plugins[%d] has no tag", i))
				continue
			}
			if typ == nil || typ.Value == "" {
				problems = append(problems, fmt.Sprintf("plugins[%d] (%s) has no type", i, tag.Value))
			}
			if _, dup := seen[tag.Value]; dup {
				problems = append(problems, fmt.Sprintf("duplicate plugin tag %q", tag.Value))
			}
			seen[tag.Value] = struct{}{}
		}
	}

	providers := nodePath(doc, []string{"data_providers"})
	if providers != nil {
		for i, item := range providers.Content {
			if tag := mappingGet(item, "tag"); tag == nil || tag.Value == "" {
				problems = append(problems, fmt.Sprintf("data_providers[%d] has no tag", i))
			}
		}
	}

	servers := nodePath(doc, []string{"servers"})
	if servers != nil {
		if len(servers.Content) == 0 {
			problems = append(problems, "servers is empty, mosdns refuses to start")
		}
		for i, item := range servers.Content {
			exec := mappingGet(item, "exec")
			if exec == nil || exec.Value == "" {
				problems = append(problems, fmt.Sprintf("servers[%d] has no exec", i))
			}
			listeners := mappingGet(item, "listeners")
			if listeners == nil || listeners.Kind != yaml.SequenceNode || len(listeners.Content) == 0 {
				problems = append(problems, fmt.Sprintf("servers[%d] has no listeners", i))
			}
		}
	}

	return problems
}

// handlePlugin describes one loaded plugin, including its configuration block
// with credentials masked.
func (p *telegramBot) handlePlugin(tag string) (string, error) {
	ex := p.M().GetExecutables()
	e, ok := ex[tag]
	if !ok {
		return fmt.Sprintf("%s: not loaded", tag), nil
	}

	var caps []string
	if _, ok := e.(mappingAdmin); ok {
		caps = append(caps, "fakeip")
	}
	if _, ok := e.(ocservAdmin); ok {
		caps = append(caps, "ocserv")
	}
	out := fmt.Sprintf("%s\n%T", tag, e)
	if len(caps) > 0 {
		out += "\ncapabilities: " + strings.Join(caps, ", ")
	}

	doc, err := loadConfigDocument(p.configPath())
	if err != nil {
		return out + "\nconfig: " + err.Error(), nil
	}
	block := pluginBlock(doc, tag)
	if block == nil {
		return out + "\nconfig: no plugin block with this tag", nil
	}
	if t := mappingGet(block, "type"); t != nil {
		out += "\ntype: " + t.Value
	}
	if argsNode := mappingGet(block, "args"); argsNode != nil {
		out += "\nargs:\n" + maskSecrets(argsNode)
	}
	return out, nil
}

// handleReload validates the config file and then stops the process, so a
// supervisor restarts it with the new configuration. mosdns builds plugins and
// listeners once at startup and has no in-process reload, so a restart is the
// only correct apply step.
func (p *telegramBot) handleReload(args []string) (string, error) {
	path := p.configPath()
	if _, err := loadConfigDocument(path); err != nil {
		return "", fmt.Errorf("config is not loadable, refusing to reload: %w", err)
	}
	if len(args) == 0 || strings.ToLower(args[0]) != "confirm" {
		return "reload stops mosdns and expects a supervisor (launchd/systemd/GoLand) to start it again.\nsend /reload confirm to proceed", nil
	}

	p.L().Info("reload requested by telegram admin", zap.String("config", path))
	go func() {
		time.Sleep(time.Second)
		// A non-nil error makes the exit code non-zero, so a supervisor that
		// restarts on failure brings mosdns back; the reason stays in its log.
		p.M().GetSafeClose().SendCloseSignal(errors.New("reload requested by telegram bot"))
	}()
	return "config is loadable, stopping mosdns so the supervisor can restart it", nil
}
