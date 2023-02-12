<?php

include_once './twitter.php';

$tokenGPT = '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';

$tokenGPT = '';

$consumerKey = '';
$consumerSecret = '';
$accessToken = '';
$accessTokenSecret = '';


$twitter = new Twitter($consumerKey, $consumerSecret, $accessToken, $accessTokenSecret);

try {
	$lists = $twitter->search('$XRP #Crypto #Ripple binance');

	foreach($lists as $list) {
		$text = 'write content hashtag maximum 200 characters about "'.$list->text.'"';

		$content = post_chatGPT($text, $tokenGPT);

		if (empty($content)) {
			continue;
		}

		if (strlen($content) > 280) {
			$content = substr_words($content, 260);
		}
		
		echo "==========".strlen($content); 
		echo $content.PHP_EOL;

		$twitter->send($content);
	}
            
} catch (\Exception $e) {
	echo 'Error: ' . $e->getMessage();
}
