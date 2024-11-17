<?php 

    //This connects our current page to the php file that connects to the database.
    include("connection.php");


    // Assuming form data is sent via POST
    $email = $_POST['email'] ?? '';
    $comment = $_POST['comment'] ?? '';

    // Use prepared statements for security
    $sql = "INSERT INTO contactus (email, comment) VALUES (?, ?)";
    $stmt = mysqli_stmt_init($mysqlconnect);

    if (mysqli_stmt_prepare($stmt, $sql)) {
        mysqli_stmt_bind_param($stmt, "ss", $email, $comment); // "ss" for two strings
        mysqli_stmt_execute($stmt);
        echo "Record saved";
    } else {
        echo "Error: " . mysqli_error($mysqlconnect);
    }

?>