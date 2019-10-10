<?php

require_once '../src/Security.php';
use marcocesarato\security\Security;

ob_start();

Security::putInSafety();
Security::cleanGlobals();

?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>Form</title>
    </head>

    <body>


    <h1>Form</h1>
    <form action="#" method="POST">
        <div>
            <label>Author:</label>
            <input type = "text" name="author" placeholder="Author's Name" />
        </div>

        <input type="submit" name="submit" value="Submit">
    </form>

    <h2>Response</h2>
    <?php
    if (isset($_POST['submit'])) {
        echo $_POST['author'];
    }
    ?>

    </body>
    </html>

<?php

die(Security::output(ob_get_clean()));
