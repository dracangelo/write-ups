<?php
if ($argc != 2) {
    echo "Usage: php enum-authors.php <url>\n";
    echo "Example: php enum-authors.php http://192.168.57.5\n";
    exit;
}

$url = rtrim($argv[1], '/');
echo "[*] Enumerating users via ?author=1,2,3...\n";

for ($id = 1; $id <= 20; $id++) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "$url/?author=$id");
    curl_setopt($ch, CURLOPT_NOBODY, true);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_exec($ch);
    $final_url = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($code == 200 && strpos($final_url, '/author/') !== false) {
        preg_match('#/author/([^/]+)/#', $final_url, $match);
        $username = $match[1] ?? 'unknown';
        echo "[+] ID $id → User: $username\n";
    }
    usleep(200000); // Be gentle
}
echo "[*] Done.\n";
?>
