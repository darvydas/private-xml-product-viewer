<?php
// Basic security check: Only allow GET requests
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    header('HTTP/1.1 405 Method Not Allowed');
    header('Allow: GET');
    // Set CORS header even for errors, so the browser can read the message
    header('Access-Control-Allow-Origin: https://darvydas.github.io'); // Or specify your domain: https://darvydas.github.io
    echo 'Error: Only GET requests are allowed.';
    exit;
}

// Get the target URL from the query parameter (e.g., proxy.php?url=http://example.com/file.xml)
$targetUrl = isset($_GET['url']) ? trim($_GET['url']) : '';

// --- Initial Basic URL Validation ---
if (empty($targetUrl) || !filter_var($targetUrl, FILTER_VALIDATE_URL) || !preg_match('/^https?:\/\//i', $targetUrl)) {
    header('HTTP/1.1 400 Bad Request');
    header('Access-Control-Allow-Origin: https://darvydas.github.io');
    echo 'Error: Invalid or missing target URL parameter (Initial Check).';
    exit;
}


// --- Enhanced SSRF Protection ---

$parsedUrl = parse_url($targetUrl);

// Check if parsing failed or host is missing
if ($parsedUrl === false || empty($parsedUrl['host'])) {
    header('HTTP/1.1 400 Bad Request');
    header('Access-Control-Allow-Origin: https://darvydas.github.io');
    echo 'Error: Could not parse the target URL.';
    exit;
}

// Double-check scheme (defense in depth)
$scheme = strtolower($parsedUrl['scheme'] ?? '');
if ($scheme !== 'http' && $scheme !== 'https') {
    header('HTTP/1.1 400 Bad Request');
    header('Access-Control-Allow-Origin: https://darvydas.github.io');
    echo 'Error: Target URL scheme must be HTTP or HTTPS.';
    exit;
}

$host = $parsedUrl['host'];

// Check if the host is an IP address or a domain name
$isDirectIp = filter_var($host, FILTER_VALIDATE_IP);
$resolvedIps = [];

if ($isDirectIp) {
    // If the host is already an IP, use it directly
    $resolvedIps[] = $host;
} else {
    // If it's a domain name, resolve it to IP(s)
    // Use DNS_A for IPv4 and DNS_AAAA for IPv6
    // Suppress errors in case of resolution failure, check result instead
    $dnsRecords = @dns_get_record($host, DNS_A + DNS_AAAA);

    if ($dnsRecords === false || empty($dnsRecords)) {
        // Allow connection attempt if DNS fails? Or block? Let's block for safety.
        // Some internal hostnames might intentionally not resolve publicly.
        header('HTTP/1.1 400 Bad Request');
        header('Access-Control-Allow-Origin: https://darvydas.github.io');
        echo 'Error: Could not resolve the hostname (' . htmlspecialchars($host) . ') to an IP address.';
        exit;
    }

    foreach ($dnsRecords as $record) {
        if (isset($record['ipv6'])) {
            $resolvedIps[] = $record['ipv6'];
        } elseif (isset($record['ip'])) {
            $resolvedIps[] = $record['ip'];
        }
    }

    if (empty($resolvedIps)) {
        header('HTTP/1.1 400 Bad Request');
        header('Access-Control-Allow-Origin: https://darvydas.github.io');
        echo 'Error: No valid IPv4 or IPv6 addresses found for hostname (' . htmlspecialchars($host) . ').';
        exit;
    }
}

// Validate ALL resolved IPs against private and reserved ranges
foreach ($resolvedIps as $ip) {
    // FILTER_FLAG_NO_PRIV_RANGE: Blocks private ranges (e.g., 10/8, 172.16/12, 192.168/16, fc00::/7)
    // FILTER_FLAG_NO_RES_RANGE: Blocks reserved ranges (e.g., loopback 127/8, ::1, link-local 169.254/16, fe80::/10, documentation ranges)
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        header('HTTP/1.1 400 Bad Request'); // Or 403 Forbidden might be semantically better
        header('Access-Control-Allow-Origin: https://darvydas.github.io');
        echo 'Error: Access to the resolved IP address (' . htmlspecialchars($ip) . ') for hostname (' . htmlspecialchars($host) . ') is not allowed.';
        exit;
    }
}

// --- Fetch the content using cURL (Recommended) ---
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $targetUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); // Return the transfer as a string
curl_setopt($ch, CURLOPT_HEADER, false);        // Don't include headers in the output
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true); // Follow redirects
curl_setopt($ch, CURLOPT_MAXREDIRS, 5);         // Limit redirects
curl_setopt($ch, CURLOPT_TIMEOUT, 15);          // Timeout in seconds
curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);   // Connection timeout
curl_setopt($ch, CURLOPT_USERAGENT, 'PrivateXmlViewerProxy/1.0'); // Set a user agent
// If target is HTTPS, you might need these depending on server config, but usually not:
// curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
// curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

$xmlContent = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$curlError = curl_error($ch);
curl_close($ch);

// --- Handle potential errors ---
if ($curlError) {
    header('HTTP/1.1 502 Bad Gateway'); // Indicate proxy error
    // Set CORS header even for errors
    header('Access-Control-Allow-Origin: https://darvydas.github.io');
    echo 'Error fetching remote URL: cURL Error: ' . htmlspecialchars($curlError);
    exit;
}

if ($httpCode >= 400) {
    // Forward the error status code from the target server
    header('HTTP/1.1 ' . $httpCode);
     // Set CORS header even for errors
    header('Access-Control-Allow-Origin: https://darvydas.github.io');
    // Try to forward the body too, but sanitize it
    echo 'Error fetching remote URL: Target server responded with status ' . $httpCode . "\n";
    echo htmlspecialchars(substr($xmlContent, 0, 500)); // Show beginning of error body if any
    exit;
}

// --- Success: Send the response back to the client ---

// Set the CORS header - This is the crucial part!
// '*' allows any origin. For better security, replace '*' with your specific domain
// where index.html is hosted, e.g., 'https://darvydas.github.io'
header('Access-Control-Allow-Origin: https://darvydas.github.io');

// Set the appropriate Content-Type header (try to guess, default to XML)
// You could try getting the Content-Type from the cURL response headers if needed
header('Content-Type: application/xml; charset=utf-8'); // Assume XML

// Output the fetched XML content
echo $xmlContent;
exit;

?>
