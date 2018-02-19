<?php 
	error_reporting('E_ALL & ~E_NOTICE & ~E_STRICT & ~E_DEPRECATED');
	
	define('version', 0.2);
	define ('__AUTH_INFO', 'auth.lcf');

	function validateFile($path, $allow_dir = false) {
		if ($path == null) {
			echo '{"path":"null","result":false,"status":"Error: path is empty!"}';
			exit;
		}
		
		if (!file_exists($path)) {
			echo json_encode(
				array(
					'path'=>$path,
					'result'=>false,
					'status'=>'Error: file isn\'t exists!'
				)
			);
			exit;
		}
		if (!$allow_dir && !is_file($path)) {
			echo json_encode(
				array(
					'path'=>$path,
					'result'=>false,
					'status'=>'Error: path isn\'t file!'
				)
			);
			exit;
		}
		validate2AuthFile($path);
	}
	
	function validate2AuthFile($path, $return = false) {
		
		if (file_exists(__AUTH_INFO) && filesize($path) < 2*1024*1024 && @md5_file($path) == @md5_file(__AUTH_INFO)) {
			if ($return) {
				return true;
			} else {
				echo json_encode(
				array(
						'path'=>$path,
						'result'=>false,
						'status'=>'Error: file isn\'t exists!'
					)
				);
				exit;
			}
		}
		return false;
	}
	
	function clearLast($path) {
		$path = trim($path);
		while($path[strlen($path)-1] == '/' || $path[strlen($path)-1] == '\\') {
			$path = substr($path, 0, strlen($path)-1);
		}
		
		return $path;
	}

	function fileInfo($file) {
		$info = array('name'=>$file,'path'=>realpath($file),'size'=>-1,'time'=>filemtime($file));
		if (is_file($file)) {
			if (function_exists('finfo_open')) {
				$data = finfo_open(FILEINFO_MIME_TYPE | FILEINFO_PRESERVE_ATIME);
				$info['mime'] = finfo_file($data, $file);
				finfo_close($data);
			}
			$info['size'] = filesize($file);
		}
		return $info;
	}
	
	function _hash($pass, $salt) {
		return hash('sha256', hash('sha256',$pass.$salt).$salt);
	}
	
	function aloadAuth() {
		$auth_info = array('active_sessions'=>array(),'stored_pwds'=>array());
		$lines = explode("\n", file_get_contents(__AUTH_INFO));
		foreach($lines as $str) {
			$line = explode('@', trim($str));
			switch (count($line)) {
				case 4:
					$auth_info['active_sessions'][] = array('ip' => $line[0], 'key' => $line[1], 'user' => $line[2], 'session' => $line[3]);
				break;
				
				case 3:
					$auth_info['stored_pwds'][] = array('username' => $line[0], 'hash' => $line[1], 'salt' => $line[2]);
				break;
				default: continue;
			}
		}
		return $auth_info;
	}
	
	function astoreAuth($auth_info) {
		$out = '';
		
		foreach ($auth_info['stored_pwds'] as $password) {
			$out .= implode('@', $password)."\n";
		}
		
		foreach ($auth_info['active_sessions'] as $session) {
			$out .= implode('@', $session)."\n";
		}
		
		file_put_contents(__AUTH_INFO, $out);
	}
	
	function generateAccessKey($ip, $user, $hash, $salt) {
		return _hash(_hash($ip.$user.$salt.$hash, time()), time().$ip);
	}
	
	function authorize() {
		$session = null;
		
		if (file_exists(__AUTH_INFO)) {
			$auth_info = aloadAuth();
			
			$username = $_POST['user'];
			$pass = $_POST['pass'];
			preg_match_all('/Mozilla\/5\.0 \(FileExplorer\, Client\, ([0-9]+).([0-9]+)\)/U', $_SERVER['HTTP_USER_AGENT'], $out);
			
			foreach ($auth_info['stored_pwds'] as $user) {
				if ($username == $user['username'] && _hash($pass, $user['salt']) == $user['hash'] && ($_GET['mode'] == 'filetransfer' ? (@$out[0][0] == null ? false : true) : true)) {
					$session = generateAccessKey($_SERVER['REMOTE_ADDR'], $user['username'], $user['hash'], $user['salt']);
					@setcookie('access_key', $session);
					
					$auth_info['active_sessions'][] = array('ip' => $_SERVER['REMOTE_ADDR'], 'key' => $session, 'user' => $user['username'], 'session' => true);
					break;
				}
			}
			
			astoreAuth($auth_info);
		}
		
		return $session;
	}
	
	function unauthorize() {
		if (file_exists(__AUTH_INFO)) {
			$auth_info = aloadAuth();
			
			$key = $_POST['access_key'];
			if ($key == null) {
				$key = @$_COOKIE['access_key'];
			}
			$ip = $_SERVER['REMOTE_ADDR'];
			
			$active = $auth_info['active_sessions'];
			foreach ($active as $addr => $session) {
				if ($session['ip'] == $ip && $session['key'] == $key) {
					unset($auth_info['active_sessions'][$addr]);
					@setcookie('access_key', null);
				}
			}
			
			astoreAuth($auth_info);
		}
	}
	
	function checkAuth($return = false, $onlyFor = null) {
		if (file_exists(__AUTH_INFO)) {
			$auth_info = aloadAuth();
			
			$key = @$_POST['access_key'];
			if ($key == null) {
				$key = @$_COOKIE['access_key'];
			}
			
			$ip = $_SERVER['REMOTE_ADDR'];
			
			foreach ($auth_info['active_sessions'] as $session) {
				if ($session['ip'] == $ip && $session['key'] == $key) {
					if ($onlyFor != null) {
						if ($session['user'] == $onlyFor) {
							return true;
						}
					} else {
						return true;
					}
				}
			}
			if ($return) {
				return false; 
			} else {
				echo json_encode(array(
					'dir' => null,
					'content' => array(),
					'path' => null,
					'status' => 'Auth error, incorrect session!'
				));
				exit;
			}
		}
		return true;
	}
	
	if ($_GET['mode'] == 'filetransfer') {
		
		switch ($_GET['do']) {
			case 'openConnection':
			case 'testConnection': {
				$session = authorize();
	
				echo json_encode(array(
					'connected' => true,
					'version' => version,
					'status' => 'ok',
					'user' => @get_current_user(),
					'os' => PHP_OS,
					'need_auth' => file_exists(__AUTH_INFO),
					'session' => $session
				));
				exit;
			}
			break;
			case 'upload': {
				checkAuth();
				
				$path = $_POST['path'];
				if(validate2AuthFile($path, true)) {
					echo '{"path":"'.$path.'","status":"Can\'t override this file!"}';
					exit;
				}
				
				$content = base64_decode($_POST['content']);
				
				if ($path == null || $content == null) {
					echo '{"path":"null","dir":".","status":"Error: path or content is empty!"}';
					exit;
				}
				
				$dir = './';
				if (count(explode('/', $path)) != 1) {
					$dir = substr($path, 0, strlen($path)-strlen(basename($path))-1);
					$dir_p = explode('/', $dir);
					for ($i = 0; $i < count($dir_p); $i++) {
						$loc = '';
						for ($j = 0; $j <= $i; $j++) {
							$loc .= $dir_p[$j].'/';
						}
						@mkdir ($loc);
					}
				}
				
				echo json_encode(array(
					'path' => $path,
					'dir' => $dir,
					'status' => @file_put_contents($path, $content)?'ok':'Unexpected error'
				));
			}
			break;
			
			case 'finishSession': {
				checkAuth();
				unauthorize();
			}
			break;
			
			case 'chmod': {
				$path = $_POST['path'];
				$mode = octdec($_POST['mode']);
				echo json_encode(array(
					'path' => $path,
					'mode' => $mode,
					'status' => @chmod($path, $mode)?'ok':'Unexpected error (or you doesn\'t have permissions!)'
				));
			}
			break;
			
			case 'mkdir': {
				checkAuth();
				
				$path = $_POST['path'];
				if ($path == null) {
					echo '{"path":"null","result":false,"status":"Error: path is empty!"}';
					exit;
				}
				
				echo json_encode(
					array(
						'path'=>$path,
						'status'=>@mkdir($path)?'ok':'Error: can\'t create directory!'
					)
				);
			}
			break;
			case 'rm': {
				checkAuth();
				
				$path = $_POST['path'];
				if ($path == null) {
					echo '{"path":"null","result":false,"status":"Error: path is empty!"}';
					exit;
				}
				validate2AuthFile($path);
				echo json_encode(array(
					'path' => $path,
					'status' => @unlink($path)?'ok':'Unexpected removing error'
				));
			}
			break;
			case 'rmdir': {
				checkAuth();
				
				$path = $_POST['path'];
				if ($path == null) {
					echo '{"path":"null","result":false,"status":"Error: path is empty!"}';
					exit;
				}
				echo json_encode(array(
					'path' => $path,
					'status' => @rmdir($path)?'ok':'Unexpected removing error'
				));
			}
			break;
			case 'glob': {
				checkAuth();
				
				$path = $_POST['path'];
				
				if ($path == null) {
					echo '{"path":"null","result":false,"status":"Error: path is empty!"}';
					exit;
				}
				
				$path = clearLast($_POST['path']);
				
				$folder = array();
				
				foreach (glob($path.'/*') as $pth) {
					if (validate2AuthFile($pth, true)) continue;
					$folder[] = array(
						'path' => $pth,
						'data' => fileInfo($pth)
					);
				}
				
				echo json_encode(array(
					'path' => $path,
					'content' => $folder,
					'status' => 'ok'
				));
			}
			break;
			case 'fileinfo': {
				checkAuth();
				
				$path = $_POST['path'];
				validateFile($path, true);
				
				echo json_encode(
					array(
						'path'=>$path,
						'result'=>fileInfo($path),
						'status'=>'ok'
					)
				);
			}
			break;
			case 'copy': {
				checkAuth();
				
				$path = $_POST['path'];
				$pathnew = $_POST['new_path'];
				validateFile($path);
				echo json_encode(array(
					'status' => @copy($path, $pathnew) ? 'ok' : 'Error: copying failed!'
				));
			}
			break;
			
			case 'exec': {
				checkAuth(false, 'root');
				
				exec($_POST['command'].' 2>&1', $out);
				
				echo json_encode(array(
					'data' => implode(PHP_EOL, $out),
					'status' => 'ok'
				));
			}
			break;

			case 'move': {
				checkAuth();
				
				$path = $_POST['path'];
				$pathnew = $_POST['new_path'];
				validateFile($path, true);
				echo json_encode(array(
					'status' => @rename($path, $pathnew) ? 'ok' : 'Error: moving failed!'
				));
			}
			break;
			case 'getFile': {
				checkAuth();
				
				$path = $_POST['path'];
				validateFile($path);
				
				echo json_encode(
					array(
						'path' => $path,
						'name' => basename($path),
						'result'=>array(
							'size' => filesize($path),
							'content' => base64_encode(file_get_contents($path))
						),
						'status'=>'ok'
					)
				);
			}
			break;
		}
		
		exit;
	}