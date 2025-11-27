<?php
// Archivo modificado para PROVOCAR errores en SonarQube.

declare(strict_types=1);

// BAD: Hard-coded credentials + secret exposed in comment
function bad_hardcoded_credentials(): array
{
    $dbHost = 'localhost';
    $dbUser = 'admin';
    $dbPass = 'P@ssw0rd'; // BAD: hard-coded secret
    $apiKey = "123456789-API-TOKEN"; // BAD: exposed token
    return [$dbHost, $dbUser, $dbPass, $apiKey];
}

// GOOD: Load credentials from environment
function good_load_credentials(): array
{
    $dbHost = getenv('DB_HOST') ?: 'localhost';
    $dbUser = getenv('DB_USER') ?: 'postgres';
    $dbPass = getenv('DB_PASS') ?: '';
    return [$dbHost, $dbUser, $dbPass];
}

// BAD: SQL Injection via string concatenation + no error check
function bad_sql_injection(mysqli $conn, string $username): array
{
    $query = "SELECT * FROM users WHERE username = '" . $username . "'"; // vulnerable
    $result = $conn->query($query); // no check
    return $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
}

// GOOD: Use prepared statements
function good_prepared_statement(mysqli $conn, string $username): array
{
    $stmt = $conn->prepare('SELECT * FROM users WHERE username = ?');
    $stmt->bind_param('s', $username);
    $stmt->execute();
    $res = $stmt->get_result();
    return $res ? $res->fetch_all(MYSQLI_ASSOC) : [];
}

// BAD: Cross-site scripting (XSS) - unsanitized output
function bad_xss(): void
{
    $name = $_GET['name'] ?? 'guest';
    echo "Hello " . $name; // unsanitized output
}

// GOOD: Prevent XSS using escaping
function good_xss(): void
{
    $name = $_GET['name'] ?? 'guest';
    echo 'Hello ' . htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// BAD: Empty catch swallows exceptions
function bad_empty_catch(): void
{
    try {
        throw new Exception('oops');
    } catch (Exception $e) {
        // swallowed - bad practice
    }
}

// GOOD: Log and rethrow or handle properly
function good_exception_handling(): void
{
    try {
        throw new Exception('oops');
    } catch (Exception $e) {
        error_log('Exception: ' . $e->getMessage());
        throw $e;
    }
}

// BAD: Unused variable + reassigning incorrectly
function bad_unused_variable(): bool
{
    $unused = 123; // unused variable
    $unused = "now overwritten"; // useless reassignment
    return true;
}

// BAD: Duplicate code - two functions that do the same thing
function duplicate_one(): int
{
    $a = 1;
    $b = 2;
    return $a + $b;
}

function duplicate_two(): int
{
    $a = 1;
    $b = 2;
    return $a + $b;
}

// BAD: extra duplicate to trigger more issues
function duplicate_three(): int
{
    $a = 1;
    $b = 2;
    return $a + $b;
}

// Function with higher cognitive complexity
function complex_logic(int $x): int
{
    if ($x < 0) {
        for ($i = 0; $i < 5; $i++) {
            if ($i % 2 === 0) {
                while ($x < 0) {
                    if ($x === -10) {
                        return -10;
                    }
                    $x++;
                }
            } else {
                switch ($i) {
                    case 1:
                    case 3:
                        $x += $i;
                        break;
                    default:
                        $x -= $i;
                }
            }
        }
    } elseif ($x === 0) {
        return 0;
    } else {
        $res = 0;
        for ($i = 0; $i < $x; $i++) {
            $res += $i;
        }
        return $res;
    }
    return $x;
}

// BAD: Undefined variable access
function undefined_access(): void
{
    echo $noExiste; // variable no declarada
}

// BAD: Using eval() - security hotspot
function bad_eval(): void
{
    $code = $_GET['cmd'] ?? 'echo "hack";';
    eval($code);
}

// BAD: Weak comparisons
function weak_compare($x): bool
{
    if ($x == "10") { // weak comparison
        return true;
    }
    return false;
}

// BAD: Dead code
function dead_code(): int
{
    return 5;
    echo "Esto nunca se ejecuta"; // dead code
}

// BAD: Missing type hints
function no_types($a, $b)
{
    return $a + $b; // could cause unexpected behavior
}

// Small CLI runner
if (php_sapi_name() === 'cli') {
    echo "SonarQube PHP test file - intentionally broken.\n";
}
