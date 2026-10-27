<?php
/*
 * Consulta CGNAT / BPA
 * Executar com (index.php também atua como roteador):
 *   php -S 0.0.0.0:8080 -t /var/opt/hexa-cgnat-logger /var/opt/hexa-cgnat-logger/index.php
 */

// Bloqueia acesso direto a qualquer outro arquivo da pasta (ex.: o .py)
if (PHP_SAPI === 'cli-server') {
    $rota = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    if ($rota !== '/' && $rota !== '/index.php') {
        http_response_code(404);
        exit('404 Not Found');
    }
}

// ===== Configuração =====
const PYTHON         = '/usr/bin/python3';
const SCRIPT         = __DIR__ . '/cgnat_bpa_lookup.py';   // /var/opt/hexa-cgnat-logger/cgnat_bpa_lookup.py
const NFDUMP_DIR     = '/var/cache/nfdump';
const OUTDIR         = '/var/cache/cgnat_reports';
const LOOKBACK_DAYS  = 60;
const LOOKAHEAD_DAYS = 60;
const NFDUMP_SERVICE = 'nfdump';    // nome da unit no systemd (nfdump.service)
const NFCAPD_PROC    = 'nfcapd';    // processo coletor que escuta a porta
const LOGO_URL       = 'https://static.wixstatic.com/media/fa9c68_30f57c9a7b5b44a186f4bb6c940031ce~mv2.png/v1/fill/w_314,h_110,al_c,q_85,usm_0.66_1.00_0.01,enc_avif,quality_auto/Logotipo%20Hexa%20Networks%20Neg.png';
// =========================

$erros = [];
$data  = $_POST['data']  ?? '';
$hora  = $_POST['hora']  ?? '';
$ip    = trim($_POST['ip']    ?? '');
$porta = trim($_POST['porta'] ?? '');
$fusos = ['UTC' => 'UTC', 'America/Sao_Paulo' => 'Horário de Brasília'];
$tz    = $_POST['tz'] ?? '';
$enviado = $_SERVER['REQUEST_METHOD'] === 'POST';

if ($enviado) {
    // Data YYYY-MM-DD
    $d = DateTime::createFromFormat('Y-m-d', $data);
    if (!$d || $d->format('Y-m-d') !== $data) {
        $erros[] = 'Data inválida.';
    }
    // Hora HH:MM ou HH:MM:SS
    if (preg_match('/^\d{2}:\d{2}$/', $hora)) {
        $hora .= ':00';
    }
    if (!preg_match('/^([01]\d|2[0-3]):[0-5]\d:[0-5]\d$/', $hora)) {
        $erros[] = 'Hora inválida.';
    }
    // IP público (IPv4 ou IPv6)
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        $erros[] = 'IP público inválido.';
    }
    // Porta 1-65535
    if (!ctype_digit($porta) || (int)$porta < 1 || (int)$porta > 65535) {
        $erros[] = 'Porta inválida (1 a 65535).';
    }
    // Fuso do horário informado no ofício (sem padrão: escolha obrigatória)
    if (!isset($fusos[$tz])) {
        $erros[] = 'Selecione o fuso horário informado no ofício.';
    }
}

function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

function sh($cmd) { return trim((string)shell_exec($cmd . ' 2>/dev/null')); }

/** Coleta status do serviço nfdump e as portas em que o nfcapd está escutando */
function status_nfdump() {
    $svc = escapeshellarg(NFDUMP_SERVICE);

    $st = [
        'ativo'      => sh("systemctl is-active $svc")  ?: 'desconhecido',
        'habilitado' => sh("systemctl is-enabled $svc") ?: 'desconhecido',
        'desde'      => sh("systemctl show -p ActiveEnterTimestamp --value $svc"),
        'pid'        => sh("systemctl show -p MainPID --value $svc"),
        'processos'  => (int)sh('pgrep -c -x ' . escapeshellarg(NFCAPD_PROC)),
        'portas'     => [],
    ];

    // Portas via ss (UDP e TCP em escuta, filtrando pelo processo nfcapd)
    foreach (explode("\n", sh('ss -H -lnup; ss -H -lntp')) as $linha) {
        if (strpos($linha, '"' . NFCAPD_PROC . '"') === false) continue;
        $c = preg_split('/\s+/', trim($linha));
        $local = $c[3] ?? '';
        if (preg_match('/:(\d+)$/', $local, $m)) {
            $proto = (stripos($c[0], 'UNCONN') === 0) ? 'udp' : 'tcp';
            $st['portas'][$local . $proto] = ['porta' => $m[1], 'end' => $local, 'proto' => $proto];
        }
    }

    // Fallback: lê o parâmetro -p da linha de comando do nfcapd
    if (!$st['portas']) {
        foreach (explode("\n", sh('ps -C ' . escapeshellarg(NFCAPD_PROC) . ' -o args=')) as $linha) {
            if (preg_match('/(?:^|\s)-p\s*(\d+)/', $linha, $m)) {
                $st['portas'][$m[1]] = ['porta' => $m[1], 'end' => '(linha de comando)', 'proto' => 'udp'];
            }
        }
    }
    return $st;
}

$nf = status_nfdump();
?>
<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Consulta CGNAT</title>
<style>
    body { font-family: system-ui, sans-serif; background:#f3f4f6; margin:0; padding:0 0 24px; color:#111; }
    .topo { background:#333333; border-bottom:4px solid #33CC33; padding:14px 24px; margin-bottom:24px; }
    .topo div { max-width:900px; margin:0 auto; display:flex; align-items:center; justify-content:space-between; gap:16px; }
    .topo img { height:44px; display:block; }
    .topo span { color:#d9d9d9; font-size:14px; }
    main { padding:0 24px; }
    .conv { background:#EFF9EF; border-left:4px solid #33CC33; padding:10px 14px; border-radius:5px; margin:0 0 12px; font-size:14px; }
    .conv small { color:#555; }
    .card { background:#fff; max-width:900px; margin:0 auto 20px; padding:20px 24px; border-radius:8px; box-shadow:0 1px 3px rgba(0,0,0,.1); }
    h1 { font-size:20px; margin:0 0 16px; }
    form { display:grid; grid-template-columns:repeat(auto-fit, minmax(180px,1fr)); gap:14px; align-items:end; }
    label { display:flex; flex-direction:column; font-size:13px; font-weight:600; gap:4px; }
    input, select { padding:8px; font-size:14px; border:1px solid #ccc; border-radius:5px; background:#fff; }
    button { padding:10px; font-size:14px; background:#197D19; color:#fff; border:0; border-radius:5px; cursor:pointer; }
    button:hover { background:#145F14; }
    .erro { background:#fee2e2; color:#991b1b; padding:10px 14px; border-radius:5px; margin-bottom:14px; }
    pre { background:#0f172a; color:#e2e8f0; padding:16px; border-radius:6px; overflow-x:auto; white-space:pre-wrap; word-break:break-word; font-size:13px; max-height:70vh; overflow-y:auto; }
    .cmd { font-family:monospace; font-size:12px; color:#555; word-break:break-all; margin-bottom:8px; }
    .status-ok { color:#15803d; font-weight:600; }
    .status-err { color:#b91c1c; font-weight:600; }
    .veredito { padding:14px 18px; border-radius:6px; margin:0 0 12px; font-size:16px; font-weight:700; border-left:6px solid; }
    .veredito small { display:block; font-weight:400; font-size:13px; margin-top:4px; }
    .v-ok   { background:#dcfce7; color:#14532d; border-color:#15803d; }
    .v-nao  { background:#fee2e2; color:#7f1d1d; border-color:#b91c1c; }
    .v-warn { background:#fef3c7; color:#78350f; border-color:#d97706; }
    .badge { display:inline-block; padding:3px 10px; border-radius:12px; font-size:13px; font-weight:600; }
    .b-ok   { background:#dcfce7; color:#166534; }
    .b-err  { background:#fee2e2; color:#991b1b; }
    .b-warn { background:#fef3c7; color:#92400e; }
    table.info { border-collapse:collapse; width:100%; font-size:14px; }
    table.info td { padding:6px 8px; border-bottom:1px solid #eee; vertical-align:top; }
    table.info td:first-child { font-weight:600; width:200px; color:#444; }
</style>
</head>
<body>

<header class="topo">
    <div>
        <img src="<?= h(LOGO_URL) ?>" alt="Hexa Networks">
        <span>Consulta CGNAT</span>
    </div>
</header>

<main>

<div class="card">
    <h1>Serviço nfdump</h1>
    <?php
        $cls = $nf['ativo'] === 'active' ? 'b-ok' : ($nf['ativo'] === 'activating' ? 'b-warn' : 'b-err');
    ?>
    <table class="info">
        <tr><td>Status (<?= h(NFDUMP_SERVICE) ?>)</td>
            <td><span class="badge <?= $cls ?>"><?= h($nf['ativo']) ?></span></td></tr>
        <tr><td>Inicia no boot</td><td><?= h($nf['habilitado']) ?></td></tr>
        <?php if ($nf['desde']): ?>
        <tr><td>Ativo desde</td><td><?= h($nf['desde']) ?></td></tr>
        <?php endif; ?>
        <?php if ($nf['pid'] && $nf['pid'] !== '0'): ?>
        <tr><td>PID principal</td><td><?= h($nf['pid']) ?></td></tr>
        <?php endif; ?>
        <tr><td>Processos <?= h(NFCAPD_PROC) ?></td><td><?= (int)$nf['processos'] ?></td></tr>
        <tr><td>Porta(s) em escuta</td><td>
            <?php if ($nf['portas']): ?>
                <?php foreach ($nf['portas'] as $p): ?>
                    <span class="badge b-ok"><?= h($p['porta']) ?>/<?= h($p['proto']) ?></span>
                    <span style="color:#666;font-size:12px"><?= h($p['end']) ?></span><br>
                <?php endforeach; ?>
            <?php else: ?>
                <span class="badge b-err">nenhuma porta encontrada</span>
            <?php endif; ?>
        </td></tr>
    </table>
</div>

<div class="card">
    <h1>Consulta CGNAT / BPA</h1>

    <?php if ($erros): ?>
        <div class="erro"><?= implode('<br>', array_map('h', $erros)) ?></div>
    <?php endif; ?>

    <form method="post">
        <label>Data
            <input type="date" name="data" value="<?= h($data) ?>" required>
        </label>
        <label>Hora
            <input type="time" name="hora" step="1" value="<?= h($hora) ?>" required>
        </label>
        <label>Fuso do horário informado
            <select name="tz" required>
                <option value="" disabled <?= $tz === '' ? 'selected' : '' ?>>Selecione…</option>
                <?php foreach ($fusos as $v => $nome): ?>
                    <option value="<?= h($v) ?>" <?= $tz === $v ? 'selected' : '' ?>><?= h($nome) ?></option>
                <?php endforeach; ?>
            </select>
        </label>
        <label>IP público
            <input type="text" name="ip" placeholder="170.150.223.228" value="<?= h($ip) ?>" required>
        </label>
        <label>Porta de origem
            <input type="number" name="porta" min="1" max="65535" placeholder="10800" value="<?= h($porta) ?>" required>
        </label>
        <button type="submit">Consultar</button>
    </form>
</div>

<?php if ($enviado && !$erros):
    $timestamp = "$data $hora";

    $cmd = escapeshellarg(PYTHON) . ' ' . escapeshellarg(SCRIPT)
         . ' --dir '            . escapeshellarg(NFDUMP_DIR)
         . ' --pub '            . escapeshellarg($ip)
         . ' --port '           . escapeshellarg($porta)
         . ' --time '           . escapeshellarg($timestamp)
         . ' --tz '             . escapeshellarg($tz)
         . ' --lookback-days '  . (int)LOOKBACK_DAYS
         . ' --lookahead-days ' . (int)LOOKAHEAD_DAYS
         . ' --outdir '         . escapeshellarg(OUTDIR)
         . ' 2>&1';
?>
<div class="card">
    <h1>Resultado</h1>
    <?php
        $origem = new DateTime($timestamp, new DateTimeZone($tz));
        $utc    = (clone $origem)->setTimezone(new DateTimeZone('UTC'));
        $brt    = (clone $origem)->setTimezone(new DateTimeZone('America/Sao_Paulo'));
    ?>
    <p class="conv"><strong>Horário consultado:</strong>
        <?= h($utc->format('d/m/Y H:i:s')) ?> UTC
        = <?= h($brt->format('d/m/Y H:i:s')) ?> (Brasília)
        <br><small>Informado no ofício como <?= h($fusos[$tz]) ?></small></p>
    <div class="cmd">$ <?= h($cmd) ?></div>
<pre id="saida"><?php
    // Execução sem limite de tempo e com saída em tempo real
    set_time_limit(0);
    ignore_user_abort(false);
    while (ob_get_level() > 0) { ob_end_flush(); }
    ob_implicit_flush(true);

    $status = '';
    $futuro = false;
    $privado = '';
    $proc = proc_open($cmd, [1 => ['pipe', 'w']], $pipes);
    if (!is_resource($proc)) {
        echo h("Falha ao iniciar o script.\n");
        $codigo = -1;
    } else {
        while (!feof($pipes[1])) {
            $linha = fgets($pipes[1]);
            if ($linha === false) break;
            // linha de máquina do script: não exibe, só guarda o veredito
            if (preg_match('/^STATUS=(\w+)/', $linha, $m)) { $status = $m[1]; continue; }
            if (strpos($linha, 'posterior aos logs disponíveis') !== false) $futuro = true;
            if ($status === '' && $privado === '' && preg_match('/^\s*IP privado:\s*(\S+)/', $linha, $m)) $privado = $m[1];
            echo h($linha);
            flush();
        }
        fclose($pipes[1]);
        $codigo = proc_close($proc);
    }
?></pre>
    <?php
        $vered = [
            'IDENTIFICADO'  => ['v-ok',   "Assinante identificado: $privado",
                                'O vínculo do bloco estava ativo no horário consultado.'],
            'SEM_ASSINANTE' => ['v-nao',  'Nenhum assinante com esse bloco no horário consultado',
                                'O IP privado que aparece no relatório é apenas o último titular, cujo vínculo já tinha sido encerrado. NÃO informar no ofício.'],
            'SEM_REGISTRO'  => ['v-warn', 'Nenhum registro encontrado',
                                'Não há alocação desse IP/porta no período pesquisado. Confira os dados do ofício.'],
        ][$status] ?? ['v-warn', 'Resultado indeterminado', 'O script não retornou um veredito. Verifique a saída abaixo.'];
        if ($futuro) {
            $vered[2] .= ' Atenção: o horário consultado é posterior aos logs disponíveis; confira data, hora e fuso.';
        }
    ?>
    <div id="veredito" class="veredito <?= $vered[0] ?>">
        <?= h($vered[1]) ?><small><?= h($vered[2]) ?></small>
    </div>
    <script>
        // o veredito só é conhecido no fim da execução; move-o para cima da saída
        (function () {
            var v = document.getElementById('veredito'), c = document.querySelector('.conv');
            if (v && c) c.parentNode.insertBefore(v, c.nextSibling);
        })();
    </script>
    <p class="<?= $codigo === 0 ? 'status-ok' : 'status-err' ?>">
        Código de saída: <?= (int)$codigo ?>
    </p>
</div>
<?php endif; ?>

</main>
</body>
</html>

