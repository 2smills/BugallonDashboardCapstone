<?php
$db = mysqli_connect('localhost', 'root', '', 'bugallondashboard');
if (!$db) {
    echo json_encode(array("status" => "Error", "message" => "Database Connection Failed"));
    exit; // Terminate the script
}

$username = $_POST["username"];
$email = $_POST["email"];
$password = $_POST["password"];

// Validate email format
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(array("status" => "Error", "message" => "Invalid email format"));
    exit;
}

// Hash the password
$hashedPassword = password_hash($password, PASSWORD_BCRYPT);

// Use prepared statements to prevent SQL injection
$stmt = $db->prepare("SELECT * FROM user WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows == 1) {
    echo json_encode(array("status" => "Error", "message" => "User Already Exists"));
} else {
    // Use prepared statement for INSERT
    $stmt = $db->prepare("INSERT INTO user (username, email, password) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $username, $email, $hashedPassword);
    
    if ($stmt->execute()) {
        echo json_encode(array("status" => "Success", "message" => "Registration Success"));
        header('Location: index.html');
    } else {
        echo json_encode(array("status" => "Error", "message" => "Registration Failed"));
    }
}

// Close the database connection
mysqli_close($db);
?>