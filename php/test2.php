<?php
// This file contains examples of good and bad practices for SonarQube.
// Use this file when scanning with the SonarPHP analyzer to exercise common rules.
// SonarQube PHP test cases - examples of GOOD and BAD code to trigger rules.
// Use this file when scanning with the SonarPHP analyzer to exercise common rules
// such as SQL injection, XSS, hard-coded secrets, unused variables, complexity, etc.

declare(strict_types=1);

// BAD: Hard-coded credentials (should be flagged as a secret)
function bad_hardcoded_credentials(): array
{
	$dbHost = 'localhost';
	$dbUser = 'admin';
	$dbPass = 'P@ssw0rd'; // BAD: hard-coded secret
	return [$dbHost, $dbUser, $dbPass];
}

// GOOD: Load credentials from environment
function good_load_credentials(): array
{
	$dbHost = getenv('DB_HOST') ?: 'localhost';
	$dbUser = getenv('DB_USER') ?: 'postgres';
	$dbPass = getenv('DB_PASS') ?: '';
	return [$dbHost, $dbUser, $dbPass];
}

// BAD: SQL Injection via string concatenation
function bad_sql_injection(mysqli $conn, string $username): array
{
	$query = "SELECT * FROM users WHERE username = '" . $username . "'"; // vulnerable
	$result = $conn->query($query);
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

// BAD: Unused variable should be flagged
function bad_unused_variable(): bool
{
	$unused = 123; // unused variable
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

// Small CLI runner to avoid accidental execution on web servers
if (php_sapi_name() === 'cli' && basename(__FILE__) === basename($_SERVER['argv'][0])) {
	echo "SonarQube PHP test file\n";
	echo "- Demonstrating good/bad examples for scanning.\n";
}
