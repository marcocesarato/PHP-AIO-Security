<?php

require_once '../src/Security.php';
use marcocesarato\security\Security;

ob_start();

Security::putInSafety();
Security::cleanGlobals();

?>
<!DOCTYPE html>
<html lang="en">

<head>

	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
	<meta name="description" content="">
	<meta name="author" content="">

	<title>Scrolling Nav - Start Bootstrap Template</title>

	<!-- Bootstrap core CSS -->
	<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous">

</head>

<body id="page-top">

<!-- Navigation -->
<nav class="navbar navbar-expand-lg navbar-dark bg-dark" id="mainNav">
	<div class="container">
		<a class="navbar-brand js-scroll-trigger" href="#page-top">Start Bootstrap</a>
		<button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarResponsive" aria-controls="navbarResponsive" aria-expanded="false" aria-label="Toggle navigation">
			<span class="navbar-toggler-icon"></span>
		</button>
		<div class="collapse navbar-collapse" id="navbarResponsive">
			<ul class="navbar-nav ml-auto">
				<li class="nav-item">
					<a class="nav-link js-scroll-trigger" href="#about">About</a>
				</li>
				<li class="nav-item">
					<a class="nav-link js-scroll-trigger" href="#services">Services</a>
				</li>
				<li class="nav-item">
					<a class="nav-link js-scroll-trigger" href="#contact">Contact</a>
				</li>
			</ul>
		</div>
	</div>
</nav>

<header class="bg-primary text-white">
	<div class="container text-center">
		<h1>Welcome to Scrolling Nav</h1>
		<p class="lead">A landing page template freshly redesigned for Bootstrap 4</p>
	</div>
</header>

<section id="about">
	<div class="container">
		<div class="row">
			<div class="col-lg-8 mx-auto">
				<h2>About this page</h2>
				<p class="lead">This is a great place to talk about your webpage. This template is purposefully unstyled so you can use it as a boilerplate or starting point for you own landing page designs! This template features:</p>
				<ul>
					<li>Clickable nav links that smooth scroll to page sections</li>
					<li>Responsive behavior when clicking nav links perfect for a one page website</li>
					<li>Bootstrap's scrollspy feature which highlights which section of the page you're on in the navbar</li>
					<li>Minimal custom CSS so you are free to explore your own unique design options</li>
				</ul>
			</div>
		</div>
	</div>
</section>

<section id="services" class="bg-light">
	<div class="container">
		<div class="row">
			<div class="col-lg-8 mx-auto">
				<h2>Services we offer</h2>
				<p class="lead">Lorem ipsum dolor sit amet, consectetur adipisicing elit. Aut optio velit inventore, expedita quo laboriosam possimus ea consequatur vitae, doloribus consequuntur ex. Nemo assumenda laborum vel, labore ut velit dignissimos.</p>
				 <h1>Form</h1>
				 <form action="#" method="POST">
				        <label>Author:</label>
				        <input type="text" class="form-control" name="author" placeholder="Author's Name" />
				        <input type="submit" class="form-control" name="submit" value="Submit">
				 </form>
				 <br>
			</div>
		</div>
	</div>
</section>

<section id="contact">
	<div class="container">
		<div class="row">
			<div class="col-lg-8 mx-auto">
				<h2>Contact us</h2>
				<p class="lead">Lorem ipsum dolor sit amet, consectetur adipisicing elit. Vero odio fugiat voluptatem dolor, provident officiis, id iusto! Obcaecati incidunt, qui nihil beatae magnam et repudiandae ipsa exercitationem, in, quo totam.</p>
			</div>
		</div>
	</div>
</section>

<!-- Footer -->
<footer class="py-5 bg-dark">
	<div class="container">
		<p class="m-0 text-center text-white">Copyright &copy; Your Website 2019</p>
	</div>
	<!-- /.container -->
</footer>

<!-- Bootstrap core JavaScript -->
<script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js" integrity="sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1" crossorigin="anonymous"></script>
<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js" integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM" crossorigin="anonymous"></script>

</body>

</html>


<?php

die(Security::output(ob_get_clean()));
