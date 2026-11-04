package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lgcshy/js/internal/app"
	"github.com/lgcshy/js/internal/config"
	"github.com/lgcshy/js/internal/credentials"
	"github.com/lgcshy/js/internal/errs"
	"github.com/lgcshy/js/internal/jumpserver"
	"github.com/lgcshy/js/internal/mcpserver"
	"github.com/lgcshy/js/internal/transport"
)

var (
	Version   = "1.1.1"
	BuildDate = "2026-11-04"
)

func Run(argv []string) int {
	return runMain(argv)
}

func runMain(argv []string) int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	code, err := dispatch(ctx, argv)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			_, _ = fmt.Fprintln(os.Stderr, "操作已取消；不会自动重试。")
			return 130
		}
		if be, ok := errs.As(err); ok {
			if be.Code == "LOCAL_INPUT_ABORTED" {
				_, _ = fmt.Fprintln(os.Stderr, "操作已取消；不会自动重试。")
				return 130
			}
			_, _ = fmt.Fprintln(os.Stderr, be.JSON())
			return 125
		}
		_, _ = fmt.Fprintln(os.Stderr, `{"ok":false,"error":"LOCAL_ERROR","message":"操作失败，原始异常已隐藏；未自动重试。"}`)
		return 125
	}
	return code
}

func emitJSON(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func extractGlobalConfigFlag(args []string) (string, []string, error) {
	if len(args) == 0 {
		return "", args, nil
	}
	if args[0] == "--config" {
		if len(args) < 2 {
			return "", nil, errs.New("CONFIG", "--config 需要指定配置文件路径。")
		}
		return args[1], args[2:], nil
	}
	if strings.HasPrefix(args[0], "--config=") {
		return strings.TrimPrefix(args[0], "--config="), args[1:], nil
	}
	return "", args, nil
}

func dispatch(ctx context.Context, argv []string) (int, error) {
	cfgPath, rest, err := extractGlobalConfigFlag(argv)
	if err != nil {
		return 125, err
	}

	// 无参数：交互列出授权服务器并选择连接
	if len(rest) == 0 {
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return 125, err
		}
		return runInteractiveSelector(ctx, app.NewService(cfg, nil))
	}

	cmd := rest[0]
	cmdArgs := rest[1:]

	switch cmd {
	case "-h", "--help", "help":
		printUsage(os.Stdout)
		return 0, nil

	case "-v", "--version", "version":
		emitJSON(os.Stdout, map[string]any{
			"version":    Version,
			"build_date": BuildDate,
			"go_version": runtime.Version(),
			"os":         runtime.GOOS,
			"arch":       runtime.GOARCH,
		})
		return 0, nil

	case "__complete":
		printDynamicCompletions(os.Stdout, cfgPath, cmdArgs...)
		return 0, nil

	case "completion":
		shell := "bash"
		if len(cmdArgs) > 0 {
			shell = cmdArgs[0]
		}
		if err := writeCompletion(os.Stdout, shell); err != nil {
			return 125, errs.New("COMPLETION", err.Error())
		}
		return 0, nil

	case "init", "login":
		return cmdInit(ctx, cfgPath, cmdArgs)
	}

	// 其余命令均需要已初始化的配置
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return 125, err
	}
	svc := app.NewService(cfg, nil)

	switch cmd {
	case "logout":
		res, err := svc.Logout(ctx, credentials.IsInteractiveTTY())
		if err != nil {
			return 125, err
		}
		emitJSON(os.Stdout, res)
		return 0, nil

	case "status":
		return cmdStatus(ctx, svc, cmdArgs)

	case "doctor":
		return cmdDoctor(ctx, svc, cmdArgs)

	case "hosts":
		return cmdHosts(ctx, svc, cmdArgs)

	case "fingerprint":
		observed, err := transport.ObserveHostFingerprint(ctx, cfg.Data.KoKoHost, cfg.Data.KoKoPort)
		if err != nil {
			return 125, err
		}
		emitJSON(os.Stdout, map[string]any{
			"observed_fingerprint":     observed,
			"trusted":                  cfg.Data.KoKoHostFingerprint != "" && observed == cfg.Data.KoKoHostFingerprint,
			"authentication_attempted": false,
		})
		return 0, nil

	case "trust":
		fs := flag.NewFlagSet("trust", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		fp := fs.String("fingerprint", "", "")
		if err := fs.Parse(cmdArgs); err != nil || strings.TrimSpace(*fp) == "" {
			return 125, errs.New("USAGE", "用法：js trust --fingerprint SHA256:...")
		}
		observed, err := transport.ObserveHostFingerprint(ctx, cfg.Data.KoKoHost, cfg.Data.KoKoPort)
		if err != nil {
			return 125, err
		}
		if strings.TrimSpace(*fp) != observed {
			return 125, errs.New("HOST_KEY_CHANGED", "提供的可信指纹与当前 KoKo 服务器不一致，未保存。")
		}
		if err := cfg.Update(true, func(d *config.Data) error {
			d.KoKoHostFingerprint = observed
			return nil
		}); err != nil {
			return 125, err
		}
		emitJSON(os.Stdout, map[string]any{
			"status":      "trusted_fingerprint_saved",
			"fingerprint": observed,
		})
		return 0, nil

	case "inspect":
		if len(cmdArgs) != 1 {
			return 125, errs.New("USAGE", "用法：js inspect <用户@IP|别名>")
		}
		return cmdInspect(ctx, svc, cmdArgs[0])

	case "connect":
		if len(cmdArgs) != 1 {
			return 125, errs.New("USAGE", "用法：js connect <用户@IP|别名|IP>")
		}
		if err := svc.ConnectInteractive(ctx, cmdArgs[0]); err != nil {
			return 125, err
		}
		return 0, nil

	case "exec":
		return cmdExec(ctx, svc, cmdArgs)

	case "rsh":
		return cmdRsh(ctx, svc, cmdArgs)

	case "passwd":
		if len(cmdArgs) != 1 {
			return 125, errs.New("USAGE", "用法：js passwd <用户@IP|别名>")
		}
		canonical, err := svc.SetTargetPassword(ctx, cmdArgs[0], credentials.IsInteractiveTTY())
		if err != nil {
			return 125, err
		}
		emitJSON(os.Stdout, map[string]any{
			"status":                      "credential_mapping_saved",
			"target":                      canonical,
			"credential_type":             "store",
			"credential_store":            cfg.Data.CredentialStore,
			"remote_connection_attempted": false,
		})
		return 0, nil

	case "forget":
		if len(cmdArgs) != 1 {
			return 125, errs.New("USAGE", "用法：js forget <用户@IP|别名>")
		}
		canonical, err := svc.ForgetTarget(ctx, cmdArgs[0], credentials.IsInteractiveTTY())
		if err != nil {
			return 125, err
		}
		emitJSON(os.Stdout, map[string]any{
			"status":  "credential_forgotten",
			"target":  canonical,
			"message": "已移除本工具保存的该目标凭据引用与秘密（未删除外部私钥或 gopass 条目）。",
		})
		return 0, nil

	case "credential":
		if len(cmdArgs) == 2 && cmdArgs[0] == "forget" {
			canonical, err := svc.ForgetTarget(ctx, cmdArgs[1], credentials.IsInteractiveTTY())
			if err != nil {
				return 125, err
			}
			emitJSON(os.Stdout, map[string]any{"status": "credential_forgotten", "target": canonical})
			return 0, nil
		}
		if len(cmdArgs) == 1 {
			return cmdCredentialInteractive(ctx, svc, cmdArgs[0])
		}
		return 125, errs.New("USAGE", "用法：js credential <用户@IP> 或 js credential forget <用户@IP>")

	case "bind-gopass":
		return cmdBindGopass(svc, cmdArgs)

	case "bind-key":
		return cmdBindKey(svc, cmdArgs)

	case "alias":
		return cmdAlias(cfg, cmdArgs)

	case "unalias":
		if len(cmdArgs) != 1 {
			return 125, errs.New("USAGE", "用法：js unalias <别名>")
		}
		name := strings.TrimSpace(cmdArgs[0])
		if err := cfg.Update(false, func(d *config.Data) error {
			delete(d.Aliases, name)
			return nil
		}); err != nil {
			return 125, err
		}
		emitJSON(os.Stdout, map[string]any{"status": "alias_removed", "alias": name})
		return 0, nil

	case "store":
		return cmdStore(ctx, svc, cmdArgs)

	case "p0-check":
		fs := flag.NewFlagSet("p0-check", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		target := fs.String("target", "", "")
		if err := fs.Parse(cmdArgs); err != nil {
			return 125, errs.New("USAGE", "用法：js p0-check [--target user@IP]")
		}
		rep, err := runP0Probe(ctx, svc, *target)
		if err != nil {
			return 125, err
		}
		emitJSON(os.Stdout, rep)
		return 0, nil

	case "cp", "scp":
		return cmdCopy(ctx, svc, cmdArgs)

	case "mcp":
		if err := mcpserver.ServeStdio(ctx, svc, Version); err != nil {
			return 125, err
		}
		return 0, nil
	}

	if strings.HasPrefix(cmd, "-") {
		return 125, errs.New("UNKNOWN_FLAG", "未知选项 "+cmd+"；运行 js --help 查看用法。")
	}

	// 简写形式：
	//   js 用户@IP             → 交互 Shell
	//   js 用户@IP 命令...      → 远程执行单条命令
	if len(cmdArgs) == 0 {
		if err := svc.ConnectInteractive(ctx, cmd); err != nil {
			return 125, err
		}
		return 0, nil
	}

	remoteCmd := strings.Join(cmdArgs, " ")
	res, _, err := svc.ExecuteCommand(ctx, cmd, remoteCmd, 30*time.Second, "", credentials.IsInteractiveTTY())
	if err != nil {
		return 125, err
	}
	_, _ = os.Stdout.WriteString(res.Stdout)
	_, _ = os.Stderr.WriteString(res.Stderr)
	if res.Status != "ssh_completed" {
		_, _ = fmt.Fprintf(os.Stderr, "\n连接状态：%s；不自动重试。\n", res.Status)
		return 125, nil
	}
	if res.ExitCode == nil {
		return 125, nil
	}
	return *res.ExitCode, nil
}

func cmdInit(ctx context.Context, cfgPath string, args []string) (int, error) {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	coreURL := fs.String("core-url", "", "")
	kokoHost := fs.String("koko-host", "", "")
	kokoPort := fs.Int("koko-port", 0, "")
	fingerprint := fs.String("fingerprint", "", "")
	caFile := fs.String("ca-file", "", "")
	proxyURL := fs.String("proxy-url", "", "")
	orgID := fs.String("org-id", "", "")
	storeMode := fs.String("store", "", "")
	user := fs.String("user", "", "")
	useAK := fs.Bool("access-key", false, "")
	akFile := fs.String("access-key-file", "", "")
	jsonOut := fs.Bool("json", false, "")

	if err := fs.Parse(args); err != nil {
		return 125, errs.New("USAGE", "用法：js init [--store keyring|file] [--access-key] [--core-url https://...]")
	}

	res, err := app.Initialize(ctx, app.InitOptions{
		ConfigPath:    cfgPath,
		CoreURL:       *coreURL,
		KoKoHost:      *kokoHost,
		KoKoPort:      *kokoPort,
		Fingerprint:   *fingerprint,
		CAFile:        *caFile,
		ProxyURL:      *proxyURL,
		OrgID:         *orgID,
		StoreMode:     *storeMode,
		Username:      *user,
		UseAccessKey:  *useAK,
		AccessKeyFile: *akFile,
	})
	if err != nil {
		return 125, err
	}
	if *jsonOut {
		emitJSON(os.Stdout, res)
	}
	return 0, nil
}

func cmdStatus(ctx context.Context, svc *app.Service, args []string) (int, error) {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	verifyOnline := fs.Bool("online", false, "")
	_ = fs.Parse(args)

	storeAvailErr := svc.Store.Available(ctx, false)
	isNetFS, netFSType := config.IsNetworkFilesystem(svc.Config.Dir())

	_, _, akErr := svc.LoadAccessKey(ctx, false)
	out := map[string]any{
		"config_path":          svc.Config.Path,
		"core_url":             svc.Config.Origin,
		"koko":                 fmt.Sprintf("%s:%d", svc.Config.Data.KoKoHost, svc.Config.Data.KoKoPort),
		"jumpserver_user":      svc.Config.Data.JumpServerUser,
		"credential_store":     svc.Config.Data.CredentialStore,
		"store_ready":          storeAvailErr == nil,
		"logged_in_locally":    akErr == nil,
		"save_password_policy": svc.Config.Data.SavePasswordPolicy,
		"configured_targets":   len(svc.Config.Data.Targets),
		"configured_aliases":   len(svc.Config.Data.Aliases),
		"generation":           svc.Config.Data.Generation,
	}
	if isNetFS {
		out["network_filesystem_warning"] = netFSType
	}
	if *verifyOnline && akErr == nil {
		api, err := svc.NewCoreClient(ctx, false)
		if err != nil {
			return 125, err
		}
		defer api.Close()
		prof, err := api.VerifyIdentity(ctx)
		if err != nil {
			return 125, err
		}
		out["online_verified"] = true
		out["is_active"] = prof.IsActive
	}
	emitJSON(os.Stdout, out)
	return 0, nil
}

func cmdDoctor(ctx context.Context, svc *app.Service, args []string) (int, error) {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	netCheck := fs.Bool("net", false, "")
	if err := fs.Parse(args); err != nil {
		return 125, errs.New("USAGE", "用法：js doctor [--net]")
	}

	storeErr := svc.Store.Available(ctx, false)
	isNetFS, netFSType := config.IsNetworkFilesystem(svc.Config.Dir())

	var pathConflict string
	if found, err := exec.LookPath("js"); err == nil {
		if selfExe, sErr := os.Executable(); sErr == nil {
			absFound, _ := filepath.Abs(found)
			absSelf, _ := filepath.Abs(selfExe)
			if absFound != "" && absSelf != "" && absFound != absSelf {
				pathConflict = absFound
			}
		}
	}

	report := map[string]any{
		"platform":                  runtime.GOOS + "/" + runtime.GOARCH,
		"config_path":               svc.Config.Path,
		"credential_store":          svc.Config.Data.CredentialStore,
		"store_available":           storeErr == nil,
		"gopass_available":          credentials.GopassAvailable(),
		"pinned_koko_key":           svc.Config.Data.KoKoHostFingerprint != "",
		"configured_targets":        len(svc.Config.Data.Targets),
		"network_or_auth_attempted": *netCheck,
	}
	if storeErr != nil {
		report["store_issue"] = storeErr.Error()
	}
	if isNetFS {
		report["network_filesystem_warning"] = "配置目录位于 " + netFSType + " 网络文件系统"
	}
	if pathConflict != "" {
		report["path_shadow_warning"] = "PATH 中存在另一个同名程序：" + pathConflict
	}

	if *netCheck {
		observed, hErr := transport.ObserveHostFingerprint(ctx, svc.Config.Data.KoKoHost, svc.Config.Data.KoKoPort)
		if hErr != nil {
			report["koko_reachable"] = false
			report["koko_error"] = hErr.Error()
		} else {
			report["koko_reachable"] = true
			report["koko_fingerprint_matches"] = (observed == svc.Config.Data.KoKoHostFingerprint)
		}
		if api, cErr := svc.NewCoreClient(ctx, false); cErr == nil {
			if prof, pErr := api.VerifyIdentity(ctx); pErr == nil {
				report["core_identity_ok"] = true
				report["jumpserver_user"] = prof.Username
			} else {
				report["core_identity_ok"] = false
				report["core_error"] = pErr.Error()
			}
			api.Close()
		} else {
			report["core_identity_ok"] = false
			report["core_error"] = cErr.Error()
		}
	}

	emitJSON(os.Stdout, report)
	return 0, nil
}

func cmdHosts(ctx context.Context, svc *app.Service, args []string) (int, error) {
	fs := flag.NewFlagSet("hosts", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	localOnly := fs.Bool("local", false, "")
	authorized := fs.Bool("authorized", false, "")
	jsonOut := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return 125, errs.New("USAGE", "用法：js hosts [--local] [--json]")
	}

	// 构建反向别名表
	reverseAliases := map[string][]string{}
	for a, dest := range svc.Config.Data.Aliases {
		reverseAliases[dest] = append(reverseAliases[dest], a)
	}
	for k := range reverseAliases {
		sort.Strings(reverseAliases[k])
	}

	if *localOnly && !*authorized {
		var keys []string
		for k := range svc.Config.Data.Targets {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var rows []map[string]any
		for _, k := range keys {
			tc := svc.Config.Data.Targets[k]
			rows = append(rows, map[string]any{
				"target":          k,
				"asset_id":        tc.AssetID,
				"asset_name":      tc.AssetName,
				"credential_type": tc.Credential.Type,
				"aliases":         reverseAliases[k],
			})
		}
		emitJSON(os.Stdout, rows)
		return 0, nil
	}

	api, err := svc.NewCoreClient(ctx, credentials.IsInteractiveTTY())
	if err != nil {
		return 125, err
	}
	defer api.Close()

	prof, err := api.VerifyIdentity(ctx)
	if err != nil {
		return 125, err
	}
	assets, err := api.ListAssets(ctx)
	if err != nil {
		return 125, err
	}

	// 按 IP 汇总本地已绑定账号
	byIP := map[string][]string{}
	for t, tc := range svc.Config.Data.Targets {
		if idx := strings.LastIndex(t, "@"); idx > 0 {
			ip := t[idx+1:]
			label := t[:idx] + "(" + tc.Credential.Type + ")"
			if als := reverseAliases[t]; len(als) > 0 {
				label += " 别名:" + strings.Join(als, ",")
			}
			byIP[ip] = append(byIP[ip], label)
		}
	}
	for ip := range byIP {
		sort.Strings(byIP[ip])
	}

	if *jsonOut || *authorized || !credentials.IsInteractiveTTY() {
		var list []map[string]any
		for _, a := range assets {
			list = append(list, map[string]any{
				"id":             a.ID,
				"address":        a.Address,
				"name":           a.Name,
				"is_active":      a.IsActive,
				"saved_accounts": byIP[a.Address],
			})
		}
		emitJSON(os.Stdout, map[string]any{
			"identity": map[string]any{
				"username":  prof.Username,
				"is_active": prof.IsActive,
			},
			"assets": list,
		})
		return 0, nil
	}

	_, _ = fmt.Fprintf(os.Stdout, "本人账号：%s  授权服务器：%d 台（存储：%s）\n", prof.Username, len(assets), svc.Config.Data.CredentialStore)
	_, _ = fmt.Fprintln(os.Stdout, "----------------------------------------------------------------------")
	for _, a := range assets {
		saved := "首次连接输入一次密码"
		if accs := byIP[a.Address]; len(accs) > 0 {
			saved = "本地配置: " + strings.Join(accs, "; ")
		}
		_, _ = fmt.Fprintf(os.Stdout, "%-16s  %-26s  %s\n", a.Address, a.Name, saved)
	}
	return 0, nil
}

func cmdInspect(ctx context.Context, svc *app.Service, targetInput string) (int, error) {
	rt, _, err := svc.Config.ResolveTarget(targetInput)
	if err != nil {
		return 125, err
	}
	api, err := svc.NewCoreClient(ctx, credentials.IsInteractiveTTY())
	if err != nil {
		return 125, err
	}
	defer api.Close()

	resolved, err := api.ResolveAsset(ctx, jumpserver.ResolveAssetRequest{
		Address:        rt.Address,
		CachedAssetID:  rt.Entry.AssetID,
		Protocol:       "ssh",
		Username:       rt.Username,
		ManagedAccount: rt.Entry.Credential.ManagedAccount,
		AllowManaged:   rt.Entry.Credential.Type == "" || rt.Entry.Credential.Type == "prompt" || rt.Entry.Credential.Type == "managed",
	})
	if err != nil {
		return 125, err
	}
	var protos []string
	for _, p := range resolved.Asset.PermedProtocols {
		protos = append(protos, p.Name)
	}
	emitJSON(os.Stdout, map[string]any{
		"target":                      rt.Canonical,
		"asset_id":                    resolved.Asset.ID,
		"asset_name":                  resolved.Asset.Name,
		"cache_hit":                   resolved.CacheHit,
		"protocols":                   protos,
		"account":                     resolved.AccountAlias,
		"is_managed_account":          resolved.IsManaged,
		"credential_type":             rt.Entry.Credential.Type,
		"key_bound":                   rt.Entry.Credential.Path != "",
		"token_created":               false,
		"target_connection_attempted": false,
	})
	return 0, nil
}

func cmdExec(ctx context.Context, svc *app.Service, args []string) (int, error) {
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOut := fs.Bool("json", false, "")
	showTimings := fs.Bool("timings", false, "")
	timeoutSec := fs.Float64("timeout", 30, "")
	cwd := fs.String("cwd", "", "")
	if err := fs.Parse(args); err != nil {
		return 125, errs.New("USAGE", "用法：js exec [--json] [--timeout 30] [--cwd /dir] <用户@IP|别名> [--] <命令...>")
	}
	rem := fs.Args()
	if len(rem) < 2 {
		return 125, errs.New("COMMAND", "用法：js exec [选项] <用户@IP|别名> [--] <命令...>")
	}
	target := rem[0]
	words := rem[1:]
	if len(words) > 0 && words[0] == "--" {
		words = words[1:]
	}
	if len(words) == 0 {
		return 125, errs.New("COMMAND", "请提供要执行的远程命令。")
	}

	timeout := time.Duration(*timeoutSec * float64(time.Second))
	interactive := !*jsonOut && credentials.IsInteractiveTTY()
	res, timings, err := svc.ExecuteCommand(ctx, target, strings.Join(words, " "), timeout, *cwd, interactive)
	if err != nil {
		return 125, err
	}

	if *jsonOut {
		if *showTimings && timings != nil {
			emitJSON(os.Stdout, map[string]any{
				"result":  res,
				"timings": timings,
			})
		} else {
			emitJSON(os.Stdout, res)
		}
	} else {
		_, _ = os.Stdout.WriteString(res.Stdout)
		_, _ = os.Stderr.WriteString(res.Stderr)
		if res.Status != "ssh_completed" {
			_, _ = fmt.Fprintf(os.Stderr, "\n连接状态：%s；不自动重试。\n", res.Status)
		}
	}

	if res.Status == "ssh_completed" && res.ExitCode != nil {
		return *res.ExitCode, nil
	}
	return 125, nil
}

func cmdCredentialInteractive(ctx context.Context, svc *app.Service, targetInput string) (int, error) {
	rt, _, err := svc.Config.ResolveTarget(targetInput)
	if err != nil {
		return 125, err
	}
	_, _ = fmt.Fprintf(os.Stderr, "为 %s 配置凭据来源：\n  [1] 输入密码并保存到当前凭据库 (%s)\n  [2] 绑定已有 gopass 条目\n  [3] 绑定本机 SSH 私钥路径\n", rt.Canonical, svc.Config.Data.CredentialStore)
	choice, err := credentials.PromptLine("选择 [1-3]：")
	if err != nil {
		return 125, err
	}
	switch strings.TrimSpace(choice) {
	case "1", "":
		canonical, sErr := svc.SetTargetPassword(ctx, rt.Canonical, true)
		if sErr != nil {
			return 125, sErr
		}
		emitJSON(os.Stdout, map[string]any{"status": "credential_mapping_saved", "target": canonical, "credential_type": "store"})
		return 0, nil
	case "2":
		ref, rErr := credentials.PromptLine("gopass 条目名：")
		if rErr != nil {
			return 125, rErr
		}
		canonical, bErr := svc.BindGopass(rt.Canonical, ref)
		if bErr != nil {
			return 125, bErr
		}
		emitJSON(os.Stdout, map[string]any{"status": "credential_mapping_saved", "target": canonical, "credential_type": "gopass"})
		return 0, nil
	case "3":
		p, pErr := credentials.PromptLine("SSH 私钥绝对路径：")
		if pErr != nil {
			return 125, pErr
		}
		ans, aErr := credentials.PromptLine("是否明确允许连接该目标时将此私钥经 HTTPS 提交给 JumpServer？[y/N]：")
		if aErr != nil {
			return 125, aErr
		}
		allow := strings.EqualFold(strings.TrimSpace(ans), "y") || strings.EqualFold(strings.TrimSpace(ans), "yes")
		canonical, bErr := svc.BindSSHKey(rt.Canonical, p, allow, "")
		if bErr != nil {
			return 125, bErr
		}
		emitJSON(os.Stdout, map[string]any{"status": "credential_mapping_saved", "target": canonical, "credential_type": "ssh_key", "submit_to_jumpserver": allow})
		return 0, nil
	default:
		return 125, errs.New("USAGE", "无效选择。")
	}
}

func cmdBindGopass(svc *app.Service, args []string) (int, error) {
	if len(args) == 0 {
		return 125, errs.New("USAGE", "用法：js bind-gopass <用户@IP> <条目名>")
	}
	target := args[0]
	var ref string
	fs := flag.NewFlagSet("bind-gopass", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	refFlag := fs.String("ref", "", "")
	if err := fs.Parse(args[1:]); err != nil {
		return 125, errs.New("USAGE", "用法：js bind-gopass <用户@IP> [--ref] <条目名>")
	}
	if *refFlag != "" {
		ref = *refFlag
	} else if fs.NArg() == 1 {
		ref = fs.Arg(0)
	}
	if strings.TrimSpace(ref) == "" {
		return 125, errs.New("USAGE", "用法：js bind-gopass <用户@IP> <条目名>")
	}
	canonical, err := svc.BindGopass(target, ref)
	if err != nil {
		return 125, err
	}
	emitJSON(os.Stdout, map[string]any{
		"status":                      "credential_mapping_saved",
		"target":                      canonical,
		"credential_type":             "gopass",
		"remote_connection_attempted": false,
	})
	return 0, nil
}

func cmdBindKey(svc *app.Service, args []string) (int, error) {
	if len(args) == 0 {
		return 125, errs.New("USAGE", "用法：js bind-key <用户@IP> <私钥路径> [--allow-key-submission]")
	}
	target := args[0]
	var identity string
	var allow bool
	var passRef string

	// 支持位置路径和选项任意顺序
	rest := args[1:]
	var flagPart []string
	for i := 0; i < len(rest); i++ {
		tok := rest[i]
		switch {
		case tok == "--allow-key-submission":
			allow = true
		case tok == "--identity" && i+1 < len(rest):
			identity = rest[i+1]
			i++
		case strings.HasPrefix(tok, "--identity="):
			identity = strings.TrimPrefix(tok, "--identity=")
		case tok == "--passphrase-gopass-ref" && i+1 < len(rest):
			passRef = rest[i+1]
			i++
		case strings.HasPrefix(tok, "--passphrase-gopass-ref="):
			passRef = strings.TrimPrefix(tok, "--passphrase-gopass-ref=")
		case !strings.HasPrefix(tok, "-") && identity == "":
			identity = tok
		default:
			flagPart = append(flagPart, tok)
		}
	}
	if len(flagPart) > 0 || strings.TrimSpace(identity) == "" {
		return 125, errs.New("USAGE", "用法：js bind-key <用户@IP> [--identity] <私钥路径> [--allow-key-submission] [--passphrase-gopass-ref 条目]")
	}
	canonical, err := svc.BindSSHKey(target, identity, allow, passRef)
	if err != nil {
		return 125, err
	}
	emitJSON(os.Stdout, map[string]any{
		"status":                      "credential_mapping_saved",
		"target":                      canonical,
		"credential_type":             "ssh_key",
		"submit_to_jumpserver":        allow,
		"remote_connection_attempted": false,
	})
	return 0, nil
}

func cmdAlias(cfg *config.Config, args []string) (int, error) {
	if len(args) == 0 {
		emitJSON(os.Stdout, cfg.Data.Aliases)
		return 0, nil
	}
	if len(args) != 2 {
		return 125, errs.New("USAGE", "用法：js alias [别名 用户@IP]")
	}
	var canonical string
	err := cfg.Update(false, func(_ *config.Data) error {
		var sErr error
		canonical, sErr = cfg.SetAlias(args[0], args[1])
		return sErr
	})
	if err != nil {
		return 125, err
	}
	emitJSON(os.Stdout, map[string]any{
		"status": "alias_saved",
		"alias":  strings.TrimSpace(args[0]),
		"target": canonical,
	})
	return 0, nil
}

func cmdStore(ctx context.Context, svc *app.Service, args []string) (int, error) {
	if len(args) == 0 || args[0] != "migrate" {
		return 125, errs.New("USAGE", "用法：js store migrate --to keyring|file")
	}
	fs := flag.NewFlagSet("store migrate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	to := fs.String("to", "", "")
	if err := fs.Parse(args[1:]); err != nil || strings.TrimSpace(*to) == "" {
		return 125, errs.New("USAGE", "用法：js store migrate --to keyring|file")
	}
	migrated, err := svc.MigrateStore(ctx, *to, credentials.IsInteractiveTTY())
	if err != nil {
		return 125, err
	}
	emitJSON(os.Stdout, map[string]any{
		"status":           "store_migrated",
		"credential_store": svc.Config.Data.CredentialStore,
		"migrated_entries": migrated,
	})
	return 0, nil
}

type selectorItem struct {
	Display  string
	Target   string // 若已知 user@IP 则直接填充
	Address  string
	Name     string
	Saved    bool
}

func runInteractiveSelector(ctx context.Context, svc *app.Service) (int, error) {
	if !credentials.IsInteractiveTTY() {
		printUsage(os.Stdout)
		return 0, nil
	}

	api, err := svc.NewCoreClient(ctx, true)
	if err != nil {
		return 125, err
	}
	assets, err := api.ListAssets(ctx)
	api.Close()
	if err != nil {
		return 125, err
	}

	reverseAliases := map[string][]string{}
	for a, dest := range svc.Config.Data.Aliases {
		reverseAliases[dest] = append(reverseAliases[dest], a)
	}

	byIP := map[string][]string{}
	for t := range svc.Config.Data.Targets {
		if idx := strings.LastIndex(t, "@"); idx > 0 {
			byIP[t[idx+1:]] = append(byIP[t[idx+1:]], t)
		}
	}
	for ip := range byIP {
		sort.Strings(byIP[ip])
	}

	var items []selectorItem
	for _, a := range assets {
		if !a.IsActive {
			continue
		}
		targets := byIP[a.Address]
		if len(targets) > 0 {
			for _, t := range targets {
				tc := svc.Config.Data.Targets[t]
				tag := tc.Credential.Type
				if als := reverseAliases[t]; len(als) > 0 {
					tag += ", 别名:" + strings.Join(als, "/")
				}
				items = append(items, selectorItem{
					Display: fmt.Sprintf("%-22s  %-24s  [%s]", t, a.Name, tag),
					Target:  t,
					Address: a.Address,
					Name:    a.Name,
					Saved:   tc.Credential.Type != "" && tc.Credential.Type != "prompt",
				})
			}
		} else {
			items = append(items, selectorItem{
				Display: fmt.Sprintf("%-22s  %-24s  [首次输入用户名与密码]", a.Address, a.Name),
				Address: a.Address,
				Name:    a.Name,
			})
		}
	}

	if len(items) == 0 {
		return 125, errs.New("NO_ASSETS", "当前 JumpServer 账号下没有已授权的活跃服务器。")
	}

	printItems := func(list []selectorItem) {
		_, _ = fmt.Fprintln(os.Stderr, "授权服务器列表：")
		for i, it := range list {
			_, _ = fmt.Fprintf(os.Stderr, "  [%2d] %s\n", i+1, it.Display)
		}
	}

	printItems(items)
	input, err := credentials.PromptLine(fmt.Sprintf("输入序号 [1-%d]、关键字过滤，或直接输入 user@IP：", len(items)))
	if err != nil {
		return 125, err
	}
	input = strings.TrimSpace(input)
	if input == "" {
		return 0, nil
	}

	chooseFrom := items
	if idx, convErr := strconv.Atoi(input); convErr == nil && idx >= 1 && idx <= len(chooseFrom) {
		return connectSelectedItem(ctx, svc, chooseFrom[idx-1])
	}

	if strings.Contains(input, "@") {
		if err := svc.ConnectInteractive(ctx, input); err != nil {
			return 125, err
		}
		return 0, nil
	}

	// 按关键字过滤
	kw := strings.ToLower(input)
	var filtered []selectorItem
	for _, it := range items {
		if strings.Contains(strings.ToLower(it.Display), kw) {
			filtered = append(filtered, it)
		}
	}
	if len(filtered) == 0 {
		return 125, errs.New("TARGET_NOT_FOUND", "没有匹配关键字的授权服务器。")
	}
	if len(filtered) == 1 {
		return connectSelectedItem(ctx, svc, filtered[0])
	}
	printItems(filtered)
	input2, err := credentials.PromptLine(fmt.Sprintf("输入序号 [1-%d]：", len(filtered)))
	if err != nil {
		return 125, err
	}
	idx, convErr := strconv.Atoi(strings.TrimSpace(input2))
	if convErr != nil || idx < 1 || idx > len(filtered) {
		return 125, errs.New("USAGE", "未选择有效序号。")
	}
	return connectSelectedItem(ctx, svc, filtered[idx-1])
}

func connectSelectedItem(ctx context.Context, svc *app.Service, it selectorItem) (int, error) {
	target := it.Target
	if target == "" {
		user, err := credentials.PromptLine(fmt.Sprintf("目标服务器 %s (%s) 的登录用户名：", it.Address, it.Name))
		if err != nil {
			return 125, err
		}
		if strings.TrimSpace(user) == "" {
			return 125, errs.New("TARGET_USER", "目标登录用户名不能为空。")
		}
		target = strings.TrimSpace(user) + "@" + it.Address
	}
	if err := svc.ConnectInteractive(ctx, target); err != nil {
		return 125, err
	}
	return 0, nil
}

func cmdCopy(ctx context.Context, svc *app.Service, args []string) (int, error) {
	var recursive, force, quiet, jsonOut bool
	var operands []string
	endOfFlags := false

	for _, tok := range args {
		if endOfFlags {
			operands = append(operands, tok)
			continue
		}
		if tok == "--" {
			endOfFlags = true
			continue
		}
		if strings.HasPrefix(tok, "--") {
			switch tok {
			case "--recursive":
				recursive = true
			case "--force", "--overwrite":
				force = true
			case "--quiet":
				quiet = true
			case "--json":
				jsonOut = true
			default:
				return 125, errs.New("USAGE", "未知选项 "+tok+"；用法：js cp [-r] [-f] [-q] [--json] <源...> <目标>")
			}
			continue
		}
		if strings.HasPrefix(tok, "-") && len(tok) > 1 {
			validBundle := true
			for _, ch := range tok[1:] {
				switch ch {
				case 'r', 'R':
					recursive = true
				case 'f':
					force = true
				case 'q':
					quiet = true
				default:
					validBundle = false
				}
			}
			if !validBundle {
				return 125, errs.New("USAGE", "未知选项 "+tok+"；用法：js cp [-r] [-f] [-q] [--json] <源...> <目标>")
			}
			continue
		}
		operands = append(operands, tok)
	}

	if len(operands) < 2 {
		return 125, errs.New("USAGE", "用法：js cp [-r] [-f] <源...> <目标>")
	}

	interactive := !jsonOut && credentials.IsInteractiveTTY()
	res, err := svc.Copy(ctx, operands, app.CopyOptions{
		Recursive:   recursive,
		Overwrite:   force,
		Interactive: interactive,
		Quiet:       quiet || jsonOut || !interactive,
	})
	if err != nil {
		return 125, err
	}

	if jsonOut {
		emitJSON(os.Stdout, res)
	} else {
		verb := "已上传"
		if res.Direction == "download" {
			verb = "已下载"
		}
		_, _ = fmt.Fprintf(
			os.Stderr,
			"✓ %s %d 个文件（%s，耗时 %.2fs）\n",
			verb,
			res.FilesCount,
			transport.FormatBytes(res.TotalBytes),
			res.DurationSeconds,
		)
	}
	return 0, nil
}

func printUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `js — 通过 JumpServer 便捷连接授权服务器

用法：
  js                              列出本人授权服务器，输入序号或关键字连接
  js <用户@IP|别名|IP>             打开目标交互终端（首次输入密码后自动保存）
  js <用户@IP|别名|IP> <命令...>   执行单条远程命令并返回退出码
  js cp [-r] [-f] <源...> <目标>   上传或下载文件与目录（别名：js scp）
  js init [--store keyring|file]  首次初始化本机 JumpServer 身份
  js hosts [--local] [--json]     查看授权服务器及本地已保存状态
  js alias [别名 用户@IP]          查看或设置便捷别名
  js unalias <别名>                删除别名
  js passwd <用户@IP|别名>         更新并保存服务器密码
  js forget <用户@IP|别名>         删除本工具保存的该服务器密码
  js bind-gopass <用户@IP> <条目>  绑定已有 gopass 密码条目（可选）
  js bind-key <用户@IP> <私钥路径> 绑定 SSH 私钥路径
  js exec [选项] <目标> -- <命令>  脚本/Agent 远程命令执行（支持 --json --cwd --timeout）
  js rsh [-l 用户] <目标> <命令...>  rsync 的远程 shell：rsync -avz -e "js rsh" 源 用户@IP:目标
  js mcp                          启动供 Agent 调用的 stdio MCP 服务
  js store migrate --to file      在系统凭据库与 0600 文件存储之间迁移
  js status / js doctor [--net]   查看状态与环境诊断
  js logout                       注销本机并吊销本工具创建的 Access Key
  js completion bash|zsh|pwsh     输出 Shell Tab 补全脚本
`)
}

// parseRshArgs 解析 ssh 风格参数，返回目标（-l 用户已并入）与远端命令。
func parseRshArgs(args []string) (string, string, error) {
	// 带参数的 ssh 选项；-l user 会并入目标
	withArg := "bBcDEeFIiJLmOopQRSWw"
	user := ""
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") && args[i] != "-" {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if a == "-l" && i+1 < len(args) {
			user = args[i+1]
			i += 2
			continue
		}
		if strings.HasPrefix(a, "-l") && len(a) > 2 {
			user = a[2:]
			i++
			continue
		}
		if len(a) == 2 && strings.Contains(withArg, a[1:]) {
			i += 2
			continue
		}
		i++
	}
	rem := args[i:]
	if len(rem) < 2 {
		return "", "", errs.New("USAGE", "用法：rsync -e \"js rsh\" 源 用户@IP:目标（也可直接 js rsh [-l 用户] <目标> <命令...>）")
	}
	target := rem[0]
	if user != "" && !strings.Contains(target, "@") {
		target = user + "@" + target
	}
	return target, strings.Join(rem[1:], " "), nil
}

// cmdRsh 作为 rsync -e 的“远程 shell”：js rsh [ssh 风格选项] <用户@IP|别名> <命令...>
// stdin/stdout 原样透传到远端 exec 通道（无 PTY），诊断只写 stderr，退出码为远端真实退出码。
func cmdRsh(ctx context.Context, svc *app.Service, args []string) (int, error) {
	target, command, err := parseRshArgs(args)
	if err != nil {
		return 125, err
	}
	return svc.StreamCommand(ctx, target, command, os.Stdin, os.Stdout, os.Stderr)
}
