<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
//Include Ipconfig file
require_once "Config.php";

//Define varible
$UserName = $Password = $Confirm_password = "";
$UserName_err = $Password_err = $Confirm_password_err = "";


if($_SERVER["REQUEST_METHOD"]=="POST"){

    //USERNAME VALIDATION
    if(empty(trim($_POST["username"]))){
        $UserName_err = "Please enter a username";
    }else{
        //prepare a select sql satatement
        $sql = "select id from users where username = ?";

        if($stmt = mysqli_prepare($link,$sql)){
            //binding variable to preapre a statement
            mysql_stmt_bind_param($stmt,"s",$param_username);
        
            //set para
            $param_username = trim($_POST["username"]);

            //attempt to excute the prepared statement
            if(mysql_stmt_execute($stmt)){
                //store result
                mysql_stmt_store_result($stmt);

                if(mysql_stmt_num_rows($stmt)==1){
                    $UserName_err = "this username is already taken.";
                }else{
                    $UserName = trim($_POST["username"]);
                }

            }else {
                    echo "oops! something's wrong";
                }

                //close statement
                mysql_stmt_close($stmt);

                // Validate password
            if(empty(trim($_POST["password"]))){
                 $password_err = "Please enter a password.";     
                 } elseif(strlen(trim($_POST["password"])) < 6){
                $password_err = "Password must have atleast 6 characters.";
            } else{
            $password = trim($_POST["password"]);
            }
    
         // Validate confirm password
            if(empty(trim($_POST["confirm_password"]))){
            $confirm_password_err = "Please confirm password.";     
             } else{
                $confirm_password = trim($_POST["confirm_password"]);
                if(empty($password_err) && ($password != $confirm_password)){
                 $confirm_password_err = "Password did not match.";
                 }
             }
    
    // Check input errors before inserting in database
    if(empty($username_err) && empty($password_err) && empty($confirm_password_err)){
        
        // Prepare an insert statement
        $sql = "INSERT INTO users (username, password) VALUES (?, ?)";
         
        if($stmt = mysqli_prepare($link, $sql)){
            // Bind variables to the prepared statement as parameters
            mysqli_stmt_bind_param($stmt, "ss", $param_username, $param_password);
            
            // Set parameters
            $param_username = $username;
            $param_password = password_hash($password, PASSWORD_DEFAULT); // Creates a password hash
            
            // Attempt to execute the prepared statement
            if(mysqli_stmt_execute($stmt)){
                // Redirect to login page
                header("location: login.php");
            } else{
                echo "Oops! Something went wrong. Please try again later.";
            }

            // Close statement
            mysqli_stmt_close($stmt);
        }
    }
    
    // Close connection
    mysqli_close($link);

            }
        }
    }
    ?>


<html lang = "en">
<head>
<meta charset="UTF-8">
    <title>Sign Up</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body{ font: 14px sans-serif; }
        .wrapper{ width: 350px; padding: 20px; }
    </style>
</head>
    <body>
        <div class="wrapper">
            <h2>Sign up</h2>
            <p>Please fill this form to create an account.</p>
            <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?> " method="post">
            <div class="form-group">
                <label>User Name</label>
                <input type="text" name ="username" class="form-control <?php echo (!empty($username_err)) ? 'is-invalid' : ''; ?>" value="<?php echo $username; ?>"> 
                <span class="invalid-feedback"><?php echo $username_err; ?></span>
            </div>
            <div class= "form-group">
                <label>Password</label>
                <input type="text" name="password" class="form-control<?php echo (!empty($password_err)) ? 'is-invalid' : ''; ?>" value="<?php echo $password; ?>">
                <span class="invalid-feedback"><?php echo $password_err; ?></span>
            </div>
            <div class="form-group">
                <label>Confirm Password</label>
                <input type="text" name="confirm_password" class="form-control <?php echo (!empty($confirm_password_err)) ? 'is-invalid' : ''; ?>" value="<?php echo $confirm_password; ?>">
                <span class="invalid-feedback"><?php echo $confirm_password_err; ?></span>
            </div>
            <div class="form-group">
                <input type="submit" value="submit" class="btn btn-primary" >
                <input type="reset" value="reset" class="btn btn-secondary">
            </div>
            <p>Already have an account?<a href="Login.php">Login Here</a></p>
            </form>
        </div>
    </body>
</html>