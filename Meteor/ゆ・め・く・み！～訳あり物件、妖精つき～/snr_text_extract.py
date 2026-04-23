# -*- coding: utf-8 -*-
"""
UMakeMe! SNR 脚本 文本提取
用法:
    python snr_text_extract.py <unpacked_dir> <json_dir>

为 <unpacked_dir> 下每个 *.txt 生成 <json_dir>/<name>.json
GalTransl 格式:
  [ {"name": "...", "message": "..."}, ... ]

可翻译内容:
  1. 命令行 (\t 开头) 中白名单命令的 "..." 参数:
       SetInfo      标题
       SetSelBtn    选择按钮文字
       switch       (第 3+ 个参数是路由选项文字)
  2. 对话行:  角色名(voiceID)：「台词」 / 角色名：「台词」
             括号可为 () 或 （）, 引号可为 「」 或 『』
  3. 旁白行:  非命令非对话非 label 的剩余行

不翻译:
  - 注释 (# 开头)
  - label ([NAME])
  - GrpLoad/BG/Cutin/GrayScaleFade/SetMesWnd/SptLoad 等资源 ID 参数
  - 语音 ID (括号内)
"""
import sys, os, re, json

# --- 行分类正则 ---
# 对话: 角色名[(voice_id)]：「台词」或『台词』
# 允许括号: ASCII () 与 全角 （）;  引号: 「」『』
_RE_DIALOG = re.compile(
    r'^(?P<prefix>\s*)'
    r'(?P<name>[^\t（(：]+?)'
    r'(?:[（(](?P<voice>[A-Za-z0-9_]+)[)）])?'
    r'：'
    r'(?P<lq>[「『])(?P<text>.*)(?P<rq>[」』])'
    r'(?P<suffix>\s*)$'
)

# 白名单命令, key = 命令名, value = 要提取的参数索引列表 (0-based, 不含命令名)
# 如果是 "从某索引起全部", 用 (start, None)
# 'all_from:N' 表示从第 N 个参数开始全部提取
_CMD_EXTRACT = {
    'SetInfo'  : [0],          # SetInfo "标题"
    'SetSelBtn': [2],          # SetSelBtn id, x, y, "文字"   -> 第 2 号 0-based? 实际是第3个
    # 实际 SetSelBtn 格式: \tSetSelBtn\t0,0,136,"外に出す"
    # 命令名后只有 ONE tab, 后面是逗号分隔的参数. 这里不是 tab 分隔!
    'switch'   : 'switch',     # 特殊: switch @var, "", "A", "B", ... 从第 2 号起(0-based)全部字符串参数
}


def _parse_csv_args(s):
    """把 csv 风格的参数串拆成 token 列表, 保留引号内容原样.
    支持: 0,0,136,"中に出す" -> ['0', '0', '136', '"中に出す"']
    """
    tokens = []
    i = 0
    n = len(s)
    while i < n:
        # skip leading spaces
        while i < n and s[i] in ' \t':
            i += 1
        if i >= n: break
        if s[i] == '"':
            # 引号 token, 寻找匹配的 "
            j = i + 1
            while j < n and s[j] != '"':
                j += 1
            if j >= n:
                tokens.append(s[i:])
                break
            tokens.append(s[i:j+1])
            i = j + 1
            # 跳到下个 , 或 EOL
            while i < n and s[i] != ',':
                i += 1
            if i < n and s[i] == ',':
                i += 1
        else:
            j = i
            while j < n and s[j] != ',':
                j += 1
            tokens.append(s[i:j].rstrip())
            i = j + 1
    return tokens


def _cmd_translatable_ranges(line):
    """输入原始行 (\\t 开头), 返回 [(start, end, text_inside_quotes), ...]
    其中 start/end 是该行 str 的 char 索引, text 是引号内的文本 (不含引号).
    """
    # \tCMD\targs
    m = re.match(r'^(\t)([A-Za-z_]\w*)(\t)(.*)$', line)
    if not m:
        return []
    cmd = m.group(2)
    args_start = m.end(3)
    args = m.group(4)

    results = []
    if cmd == 'SetInfo':
        # 单一参数就是 "标题"
        qm = re.search(r'"([^"]*)"', args)
        if qm:
            s = args_start + qm.start(1)
            e = args_start + qm.end(1)
            results.append((s, e, qm.group(1)))
    elif cmd == 'SetSelBtn':
        # 最后一个字符串参数是显示文字
        # 参数形如: 0,0,136,"外に出す"
        # 取最后一个 "..."
        matches = list(re.finditer(r'"([^"]*)"', args))
        if matches:
            qm = matches[-1]
            s = args_start + qm.start(1)
            e = args_start + qm.end(1)
            results.append((s, e, qm.group(1)))
    elif cmd == 'switch':
        # \tswitch\t@51,"","光ルートへ","凛ルートへ",...
        # 第 2 个参数(0-based 是 0=@51, 1="", 2..N 是选项文字). 全部提取 "..." 字符串且过滤空串?
        # 为了可翻, 保留所有非空字符串.
        for qm in re.finditer(r'"([^"]*)"', args):
            s = args_start + qm.start(1)
            e = args_start + qm.end(1)
            if qm.group(1):   # 非空才提
                results.append((s, e, qm.group(1)))
    return results


def extract_lines(script_text):
    """script_text 是 CP932 解码后的完整脚本字符串.
    返回 list of dict, 每条:
      {'kind': 'dialog'|'narration'|'cmd', 'name': str, 'message': str,
       'line_no': int, 'col_range': (s,e) (仅 cmd/dialog 用),
       'voice': str or None}
    """
    out = []
    lines = script_text.split('\r\n')
    for ln_no, line in enumerate(lines):
        if line == '' or line.startswith('#'):
            continue
        # label: [xxx] 整行
        if re.match(r'^\[[^\]]+\]\s*$', line):
            continue

        if line.startswith('\t'):
            # 命令行: 只对白名单命令抽取
            for (s, e, text) in _cmd_translatable_ranges(line):
                out.append({
                    'kind'     : 'cmd',
                    'line_no'  : ln_no,
                    'col_range': (s, e),
                    'name'     : '',
                    'message'  : text,
                })
            continue

        # 对话
        m = _RE_DIALOG.match(line)
        if m:
            name = m.group('name')
            voice = m.group('voice')
            text  = m.group('text')
            if not text:   # 空对话不提取
                continue
            out.append({
                'kind'     : 'dialog',
                'line_no'  : ln_no,
                'name'     : name,
                'voice'    : voice,
                'lq'       : m.group('lq'),
                'rq'       : m.group('rq'),
                'message'  : text,
            })
            continue

        # 其他 "非 tab 非 # 非 label" 行 — 判定是否有日文字符, 有则当旁白
        if re.search(r'[\u3040-\u30ff\u3400-\u9fff]', line):
            out.append({
                'kind'   : 'narration',
                'line_no': ln_no,
                'name'   : '',
                'message': line,
            })
        # 其他无日文行 (如 SetMode\t1,0 这种没前导 tab 的命令) 跳过

    return out


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    in_dir, out_dir = sys.argv[1], sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)

    files = sorted(f for f in os.listdir(in_dir) if f.endswith('.txt'))
    total_entries = 0

    for fn in files:
        raw = open(os.path.join(in_dir, fn), 'rb').read()
        try:
            text = raw.decode('cp932')
        except UnicodeDecodeError as e:
            print(f"[!] {fn}: cp932 decode error: {e}")
            continue
        items = extract_lines(text)
        # 输出 GalTransl 简洁格式: [{name, message}, ...]
        # name 为空串时 GalTransl 视为旁白
        out_items = [{'name': it['name'], 'message': it['message']} for it in items]
        out_path = os.path.join(out_dir, fn.replace('.txt', '.json'))
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(out_items, f, ensure_ascii=False, indent=2)
        total_entries += len(out_items)
        print(f"  [{fn}] {len(out_items)} entries")

    print(f"\n[+] total: {len(files)} files, {total_entries} entries -> {out_dir}")


if __name__ == '__main__':
    main()
