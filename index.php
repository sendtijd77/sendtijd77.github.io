<?php
session_start();
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Debug: Log volledige serverinformatie
error_log("SERVER DATA: " . print_r($_SERVER, true));

// Functie: Detecteer bots op basis van uitgebreide methoden
function isBot() {
    $botKeywords = [
        'bot', 'crawl', 'spider', 'mediapartners', 'slurp', 'httpclient', 'wget', 'curl',
        'python', 'java', 'fetch', 'libwww', 'http', 'urllib', 'go-http-client', 'node-fetch',
        'headless', 'phantomjs', 'selenium', 'awesomium', 'chrome-lighthouse', 'httpclient'
    ];

    // Controleer User-Agent
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    if (!$userAgent || strlen($userAgent) < 10) {
        error_log("Suspicious User-Agent: Empty or too short.");
        return true;
    }

    foreach ($botKeywords as $keyword) {
        if (stripos($userAgent, $keyword) !== false) {
            error_log("Suspicious User-Agent detected: $userAgent");
            return true;
        }
    }

    // Controleer verdachte headers
    if (detectSuspiciousHeaders()) {
        error_log("Suspicious headers detected.");
        return true;
    }

    // Controleer verdachte IP-adressen
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    if (isSuspiciousIP($ip)) {
        error_log("Suspicious IP detected: $ip");
        return true;
    }

    // Controleer snelheid van verzoeken (rate limiting)
    if (rateLimitSlidingWindow($ip)) {
        error_log("Rate limit exceeded for IP: $ip");
        return true;
    }

    return false;
}

// Functie: Detecteer verdachte headers
function detectSuspiciousHeaders() {
    $headers = [
        'HTTP_ACCEPT' => $_SERVER['HTTP_ACCEPT'] ?? null,
        'HTTP_REFERER' => $_SERVER['HTTP_REFERER'] ?? null,
        'HTTP_ACCEPT_LANGUAGE' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? null
    ];

    // Alleen headers met duidelijke fouten blokkeren
    if (!empty($headers['HTTP_REFERER']) && stripos($headers['HTTP_REFERER'], 'spam') !== false) {
        return true;
    }

    return false;
}

// Functie: Controleer verdachte IP-adressen (bijvoorbeeld datacenters of bekende crawlers)
function isSuspiciousIP($ip) {
    $datacenterIPs = [
        '66.249.', '72.14.', '203.208.', '157.55.', '199.30.', '144.76.', '46.165.', '151.101.',
        '35.', '34.', '104.', '45.79.'
    ];

    foreach ($datacenterIPs as $prefix) {
        if (strpos($ip, $prefix) === 0) {
            return true;
        }
    }
    return false;
}

// Functie: Controleer op rate limiting met sliding window-algoritme
function rateLimitSlidingWindow($ip) {
    $redis = new Redis();
    $redis->connect('127.0.0.1', 6379);

    $windowSize = 60; // Sliding window van 60 seconden
    $requestLimit = 15; // Maximaal 15 verzoeken per minuut

    $currentTimestamp = time();
    $key = "rate_limit_$ip";

    // Voeg huidige timestamp toe aan de lijst
    $redis->rPush($key, $currentTimestamp);

    // Behoud alleen recente verzoeken
    $redis->lTrim($key, -$requestLimit, -1);

    // Controleer of er teveel verzoeken zijn
    $requestCount = $redis->lLen($key);
    if ($requestCount > $requestLimit) {
        return true;
    }

    // Stel een timeout in voor de sleutel
    $redis->expire($key, $windowSize);
    return false;
}

// Haal de huidige `SERVER_NAME` op
$serverName = $_SERVER['SERVER_NAME'] ?? null;

// Debugging: Log de servernaam
error_log("Server Name: " . ($serverName ?? 'No server name'));

// Antibot-actie
if (isBot()) {
    header("HTTP/1.1 403 Forbidden");
    echo "Access Denied: Bot or Crawler detected.";
    exit();
}

// Redirect-logica gebaseerd op `SERVER_NAME`
switch ($serverName) {
    case 'sendtijd77.github.io':
        header("Location: https://youtube.com");
        exit();
    case 'com.example2.com':
        header("Location: https://google.com");
        exit();
    case 'com.example.com':
        header("Location: /012/");
        exit();
    default:
        // Geen match, log het probleem en toon debugginginformatie
        error_log("No valid SERVER_NAME found for redirect.");
        echo "Invalid server name detected. Debug Info:";
        echo "<pre>";
        print_r($_SERVER);
        echo "</pre>";
        exit();
}
?>
