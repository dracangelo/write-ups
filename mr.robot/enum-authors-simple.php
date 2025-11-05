<?php
if ($argc != 2) {
    die("Usage: php enum-authors-simple.php <url>\n");
}

$url = rtrim($argv[1], '/');
echo "[*] Enumerating users via ?author=1,2,3...\n";

for ($id = 1; $id <= 20; $id++) {
    $author_url = "$url/?author=$id";
    $response = @file_get_contents($author_url);
    
    if ($response === false) {
        echo "[-] Error fetching ID $id\n";
        continue;
    }

    // Look for redirect in HTML or Location header
    if (preg_match('#Location: .*?/author/([^/]+)/#i', $response, $match) ||
        strpos($response, '/author/') !== false) {
        
        $username = $match[1] ?? 'unknown';
        echo "[+] ID $id → User: $username\n";
    }
    
    usleep(200000); // 0.2 sec delay
}
echo "[*] Done.\n";
?>
