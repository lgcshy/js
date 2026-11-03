package main

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"jsbridge/internal/config"
)

func writeCompletion(w io.Writer, shell string) error {
	switch strings.ToLower(strings.TrimSpace(shell)) {
	case "bash":
		_, err := fmt.Fprint(w, bashCompletionScript)
		return err
	case "zsh":
		_, err := fmt.Fprint(w, zshCompletionScript)
		return err
	case "powershell", "pwsh":
		_, err := fmt.Fprint(w, powershellCompletionScript)
		return err
	default:
		return fmt.Errorf("不支持的 shell 类型 %q（支持 bash、zsh、powershell）", shell)
	}
}

func printDynamicCompletions(w io.Writer, cfgPath string, args ...string) {
	mode := "all"
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		mode = strings.ToLower(strings.TrimSpace(args[0]))
	}

	cmds := []string{
		"init", "logout", "status", "hosts", "exec", "rsh", "cp", "scp",
		"passwd", "forget", "alias", "unalias", "bind-gopass", "bind-key",
		"doctor", "store", "import", "completion", "mcp", "version",
	}

	var items []string
	if mode == "all" {
		items = append(items, cmds...)
	}

	if cfg, err := config.Load(cfgPath); err == nil {
		switch mode {
		case "aliases":
			for a := range cfg.Data.Aliases {
				items = append(items, a)
			}
		case "cp-endpoints":
			for a := range cfg.Data.Aliases {
				items = append(items, a+":")
			}
			for t := range cfg.Data.Targets {
				items = append(items, t+":")
			}
		default: // "all" or "targets"
			for a := range cfg.Data.Aliases {
				items = append(items, a)
			}
			for t := range cfg.Data.Targets {
				items = append(items, t)
			}
		}
	}
	sort.Strings(items)
	for _, it := range items {
		_, _ = fmt.Fprintln(w, it)
	}
}

const bashCompletionScript = `_js_completions() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  local cmd="${COMP_WORDS[1]}"
  if [[ ${COMP_CWORD} -eq 1 ]]; then
    local candidates
    candidates="$(js __complete 2>/dev/null)"
    COMPREPLY=( $(compgen -W "${candidates}" -- "${cur}") )
    return 0
  fi
  case "${cmd}" in
    passwd|forget|remember|connect|inspect|exec|bind-gopass|bind-key|credential)
      local targets
      targets="$(js __complete targets 2>/dev/null)"
      COMPREPLY=( $(compgen -W "${targets}" -- "${cur}") )
      ;;
    unalias)
      local aliases
      aliases="$(js __complete aliases 2>/dev/null)"
      COMPREPLY=( $(compgen -W "${aliases}" -- "${cur}") )
      ;;
    completion)
      COMPREPLY=( $(compgen -W "bash zsh powershell" -- "${cur}") )
      ;;
    cp|scp)
      local endpoints
      endpoints="$(js __complete cp-endpoints 2>/dev/null)"
      COMPREPLY=( $(compgen -W "${endpoints}" -- "${cur}") )
      ;;
  esac
}
complete -o default -F _js_completions js
`

const zshCompletionScript = `#compdef js
_js() {
  if (( CURRENT == 2 )); then
    local -a candidates
    candidates=(${(f)"$(js __complete 2>/dev/null)"})
    _describe 'js target or command' candidates
    return
  fi
  local cmd="${words[2]}"
  case "${cmd}" in
    passwd|forget|remember|connect|inspect|exec|bind-gopass|bind-key|credential)
      local -a targets
      targets=(${(f)"$(js __complete targets 2>/dev/null)"})
      _describe 'js target' targets
      ;;
    unalias)
      local -a aliases
      aliases=(${(f)"$(js __complete aliases 2>/dev/null)"})
      _describe 'js alias' aliases
      ;;
    completion)
      local -a shells
      shells=(bash zsh powershell)
      _describe 'shell' shells
      ;;
    cp|scp)
      local -a endpoints
      endpoints=(${(f)"$(js __complete cp-endpoints 2>/dev/null)"})
      _describe 'remote endpoint' endpoints
      _files
      ;;
  esac
}
compdef _js js
`

const powershellCompletionScript = `Register-ArgumentCompleter -Native -CommandName js -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $elements = $commandAst.CommandElements
    if ($elements.Count -le 2 -and ($elements.Count -eq 1 -or $wordToComplete -ne '')) {
        js __complete 2>$null | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
        return
    }
    $sub = $elements[1].Extent.Text
    switch -Regex ($sub) {
        '^(passwd|forget|remember|connect|inspect|exec|bind-gopass|bind-key|credential)$' {
            js __complete targets 2>$null | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
            }
        }
        '^unalias$' {
            js __complete aliases 2>$null | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
            }
        }
        '^completion$' {
            @('bash', 'zsh', 'powershell') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
            }
        }
        '^(cp|scp)$' {
            js __complete cp-endpoints 2>$null | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
            }
        }
    }
}
`
