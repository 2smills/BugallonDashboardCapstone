<?php
session_start();

$db = mysqli_connect('localhost', 'root', '', 'bugallondashboard');
if (!$db) {
    echo json_encode(array("status" => "Error", "message" => "Database Connection Failed"));
    exit;
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST["email"];
    $password = $_POST["password"];

    // Use prepared statement to retrieve user data
    $stmt = $db->prepare("SELECT * FROM user WHERE email = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows == 1) {
        $row = $result->fetch_assoc();
        if (password_verify($password, $row["password"])) {
            // Password is correct, create a session and redirect to the dashboard or another page
            $_SESSION["email"] = $username;
            header('Location: home.html'); // Change the URL to the dashboard page
            exit;
        } else {
            echo json_encode(array("status" => "Error", "message" => "Incorrect Password"));
        }
    } else {
        echo json_encode(array("status" => "Error", "message" => "User not found"));
    }
}

mysqli_close($db);
?>