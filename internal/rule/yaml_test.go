package rule

import (
	"strings"
	"testing"
)

func TestParseYAMLDuplicateKeysPreserved(t *testing.T) {
	src := "a: 1\nb:\n  c: 2\n  c: 3\n"
	n, err := ParseYAML([]byte(src), "x.yml")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(n.GetAll("a")); got != 1 {
		t.Fatalf("a values = %d", got)
	}
	b := n.Get("b")
	if b == nil || b.Kind != MappingNode {
		t.Fatal("b missing")
	}
	all := b.GetAll("c")
	if len(all) != 2 {
		t.Fatalf("c values = %d, want 2", len(all))
	}
	if all[0].Value != "2" || all[1].Value != "3" {
		t.Fatalf("values = %q %q", all[0].Value, all[1].Value)
	}
	if b.Get("c").Value != "3" {
		t.Fatal("Get should return last value")
	}
}

func TestParseYAMLFlowAndQuotes(t *testing.T) {
	src := `
title: 'It''s a rule'
tags: [attack.execution, "attack.t1059.001"]
nested:
  list:
    - one
    - two
  flow: {a: 1, b: "two"}
block: |
  line one
  line two
folded: >
  hello
  world
`
	n, err := ParseYAML([]byte(src), "x.yml")
	if err != nil {
		t.Fatal(err)
	}
	if got := n.Get("title").Value; got != "It's a rule" {
		t.Fatalf("title = %q", got)
	}
	tags := n.Get("tags")
	if tags.Kind != SequenceNode || len(tags.Items) != 2 {
		t.Fatalf("tags = %#v", tags)
	}
	list := n.Get("nested").Get("list")
	if list.Kind != SequenceNode || len(list.Items) != 2 || list.Items[1].Value != "two" {
		t.Fatalf("list = %#v", list)
	}
	flow := n.Get("nested").Get("flow")
	if flow.Kind != MappingNode || flow.Get("b").Value != "two" {
		t.Fatalf("flow = %#v", flow)
	}
	if got := n.Get("block").Value; got != "line one\nline two\n" {
		t.Fatalf("block = %q", got)
	}
	if got := n.Get("folded").Value; got != "hello world\n" {
		t.Fatalf("folded = %q", got)
	}
}

func TestParseYAMLMultiLineFlow(t *testing.T) {
	src := "enum:\n  [1, 2,\n   3, 4]\n"
	n, err := ParseYAML([]byte(src), "x.yml")
	if err != nil {
		t.Fatal(err)
	}
	enum := n.Get("enum")
	if enum.Kind != SequenceNode || len(enum.Items) != 4 {
		t.Fatalf("enum = %#v", enum)
	}
	if enum.Items[3].Value != "4" {
		t.Fatalf("last = %q", enum.Items[3].Value)
	}
}

func TestParseYAMLCommentsAndSpans(t *testing.T) {
	src := "# header\nkey: value # trailing\nother: 'a # b'\n"
	n, err := ParseYAML([]byte(src), "x.yml")
	if err != nil {
		t.Fatal(err)
	}
	if n.Get("key").Value != "value" {
		t.Fatalf("key = %q", n.Get("key").Value)
	}
	if n.Get("other").Value != "a # b" {
		t.Fatalf("other = %q", n.Get("other").Value)
	}
	key := n.Pairs[0].Key
	if key.Span.Line != 2 || key.Span.Col != 1 {
		t.Fatalf("span = %#v", key.Span)
	}
}

func TestParseYAMLSequenceOfMappings(t *testing.T) {
	src := "items:\n  - name: one\n    value: 1\n  - name: two\n    value: 2\n"
	n, err := ParseYAML([]byte(src), "x.yml")
	if err != nil {
		t.Fatal(err)
	}
	items := n.Get("items")
	if items.Kind != SequenceNode || len(items.Items) != 2 {
		t.Fatalf("items = %#v", items)
	}
	if items.Items[0].Get("name").Value != "one" || items.Items[1].Get("value").Value != "2" {
		t.Fatalf("items = %#v", items)
	}
}

func TestParseYAMLTabIndentError(t *testing.T) {
	_, err := ParseYAML([]byte("a:\n\tb: 1\n"), "x.yml")
	if err == nil || !strings.Contains(err.Error(), "tab") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseYAMLNull(t *testing.T) {
	n, err := ParseYAML([]byte("a:\nb: null\nc: ''\n"), "x.yml")
	if err != nil {
		t.Fatal(err)
	}
	if !n.Get("a").IsNull() || !n.Get("b").IsNull() {
		t.Fatal("expected nulls")
	}
	if n.Get("c").IsNull() || n.Get("c").Value != "" {
		t.Fatal("quoted empty string is not null")
	}
}
