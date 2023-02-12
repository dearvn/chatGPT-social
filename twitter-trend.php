<?php

include_once './twitter.php';


$tokenGPT = '';

$consumerKey = '';
$consumerSecret = '';
$accessToken = '';
$accessTokenSecret = '';

$twitter = new Twitter($consumerKey, $consumerSecret, $accessToken, $accessTokenSecret);

try {
	$trends = $twitter->getTrends(2459115);

	foreach($trends[0]->trends as $item) {
		$text = "write funny content maximum 200 characters about {$item->url}";

		$content = post_chatGPT($text, $tokenGPT);

		if (empty($content)) {
			continue;
		}

		if (strlen($content) > 280) {
			$content = substr_words($content, 260);
		}
		echo $content.PHP_EOL;
		
		$twitter->send($content);

	}
            
} catch (\Exception $e) {
	echo 'Error: ' . $e->getMessage();
}
