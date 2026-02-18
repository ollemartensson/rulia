package tree_sitter_rulia_test

import (
	"testing"

	tree_sitter "github.com/smacker/go-tree-sitter"
	"github.com/tree-sitter/tree-sitter-rulia"
)

func TestCanLoadGrammar(t *testing.T) {
	language := tree_sitter.NewLanguage(tree_sitter_rulia.Language())
	if language == nil {
		t.Errorf("Error loading Rulia grammar")
	}
}
