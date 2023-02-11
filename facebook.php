<?



function substr_words($text, $maxchar) {
	if (strlen($text) > $maxchar || $text == '') {
		$words = preg_split('/\s/', $text);
		$output = '';
		$i      = 0;
		while (1) {
			$length = strlen($output)+strlen($words[$i]);
			if ($length > $maxchar) {
				break;
			}
			else {
				$output .= " " . $words[$i];
				++$i;
			}
		}
	}
	else {
		$output = $text;
	}
	return $output;
}


function post_image_chatGPT($text, $token) {
	try {
		$ch = curl_init();

		$payload = [
            "size" => "1024x1024",
			"n" => 1,
			"prompt" => $text
		];
		
		curl_setopt($ch, CURLOPT_HTTPHEADER, [
			"Content-Type: application/json; charset=utf-8",
			"Authorization: Bearer $token",
			"Accept-Charset: application/json; charset=utf-8"
		]);

		curl_setopt($ch, CURLOPT_URL,"https://api.openai.com/v1/images/generations");
		curl_setopt($ch, CURLOPT_POST, 1);
		curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));

		// Receive server response ...
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

		$output = curl_exec($ch);

		curl_close($ch);

		if (empty($output)) {
			return '';
		}

		$resp = json_decode($output);
		if (empty($resp) || empty($resp->data)) {
			return '';
		}
		$items = (array)$resp->data;
		return $items[0]->url;
	} catch (\Exception $e) {
		echo $e->getMessage();
	}
}

function post_text_chatGPT($text, $token) {
	try {
		$ch = curl_init();

		$payload = [
			"model" => "text-davinci-003",
			"prompt" => $text,
			"temperature" => 0.7,
			"max_tokens" => 2049, // max-limit = 2049
			"top_p" => 1,
			"best_of" => 1,
		];
		
		curl_setopt($ch, CURLOPT_HTTPHEADER, [
			"Content-Type: application/json; charset=utf-8",
			"Authorization: Bearer $token",
			"Accept-Charset: application/json; charset=utf-8"
		]);

		curl_setopt($ch, CURLOPT_URL,"https://api.openai.com/v1/completions");
		curl_setopt($ch, CURLOPT_POST, 1);
		curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));

		// Receive server response ...
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

		$output = curl_exec($ch);

		curl_close($ch);

		if (empty($output)) {
			return '';
		}

		$resp = json_decode($output);
		if (empty($resp) || empty($resp->choices)) {
			return '';
		}
		$items = (array)$resp->choices;
		return $items[0]->text;
	} catch (\Exception $e) {
		echo $e->getMessage();
	}
}

function publishFacebook($page_id, $page_access_token, $data) {
    try {
            
        if (empty($page_access_token) || empty($page_id) || empty($data)) {
            return;
        }
        
        $payload = [];
        $payload['message'] = $data['description'];
        $payload['description'] = $data['description'];
        $payload['access_token'] = $page_access_token;

        $uri = '/feed';
        if (!empty($data['image_url'])) {
            $uri = '/photos';
            $payload['url'] = $data['image_url'];
        }

        $post_url = 'https://graph.facebook.com/'.$page_id.$uri;

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $post_url);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        $reps = curl_exec($ch);
        curl_close($ch);

        if (empty($reps)) {
            return '';
        }
        $item = json_decode($reps);

        $id = !empty($item->id) ? $item->id : '';
        
        if (!empty($data['image_url'])) {
            $id = !empty($item->post_id) ? $item->post_id : '';
        }
        
        return $id;
    } catch ( \Exception $e ) {
        echo $e->getMessage();
    }
}


$tokenGPT = '';
$page_id = '';
$page_access_token = '';

$feed = file_get_contents('https://search.cnbc.com/rs/search/combinedcms/view.xml?partnerId=wrss01&id=15837362');

$rss = simplexml_load_string($feed);

foreach ($rss->channel->item as $item) {

    $title = (string)$item->title;

    $text = 'write content maximum 500 characters about "'.$title.'"';

    $content = post_text_chatGPT($text, $tokenGPT);

    if (empty($content)) {
        continue;
    }

    $image_url = post_image_chatGPT($title, $tokenGPT);

    if (strlen($content) > 280) {
        $content = substr_words($content, 260);
    }

    $data = [
        'description' => $content,
        'image_url' => $image_url
    ];

    $id = publishFacebook($page_id, $page_access_token, $data);
    echo $id;
}
